/*
 * ptdump.c - standalone decoder for kAFL/Nyx PT dumps
 *
 * Copyright (c) 2020 Sergej Schumilo, Cornelius Aschermann
 * Copyright (c) 2021 Steffen Schulz, Intel Corporation
 *
 * SPDX-License: BSD-2
 */

#include <stdio.h>
#include <libxdc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "page_cache.h"
#include "helper.h"
#include <errno.h>

/*
 * Edge callback. The decoder invokes this once per taken branch — for a dense
 * VM-interpreter trace that is tens of millions of times. The output stream is
 * therefore the whole cost: the previous implementation used dprintf() on a raw
 * fd, i.e. one UNBUFFERED write() syscall per edge, which on a 43M-edge trace is
 * ~53s single-process and >600s under parallel load (kernel/disk syscall
 * contention). Writing through a FILE* with a large fully-buffered stream
 * (see setvbuf in trace_file) collapses those millions of syscalls into a few
 * hundred and produces byte-identical output. */
void trace_log(void* ctx, disassembler_mode_t mode, uint64_t src, uint64_t dst)
{
	assert(mode == mode_16 || mode == mode_32 || mode == mode_64);
	fprintf((FILE*)ctx, "%lx,%lx\n", src, dst);
}

/* 4 MB fully-buffered output buffer: turns ~N write() syscalls per edge into
 * one per 4 MB of CSV. Static so it outlives trace_file's stack frame. */
static char g_out_buf[1 << 22];

/*
 * Walk log (`-w <path>`): header "XDC-WALK" + u32 version, then one 68-byte
 * little-endian record per libxdc walk, Python struct `<QQQIIIQQQB7x>`:
 * (anchor packet offset, first edge index, end edge index, tnt_before,
 *  tnt_used, tnt_after, stop address, walk entry IP, limit IP (0 when not
 *  limited), flags). Edge indices count CSV rows. Only when -w is given is
 * the counting edge callback installed, so the default path is exactly the
 * old one.
 *
 * Exit codes: 0 decode ok, 1 decode failed / bad arguments (as before),
 * 2 the walk log could not be opened or written (fopen/fwrite/fclose); the
 * edge CSV may still be complete, but the run must not be used as a walk-log
 * decode. 2 takes precedence over 1.
 */
#define WALK_LOG_VERSION 2
#define WALK_LOG_IO_ERROR 2

typedef struct __attribute__((packed)) walk_record_s {
	uint64_t anchor_offset;
	uint64_t edge_start;
	uint64_t edge_end;
	uint32_t tnt_before;
	uint32_t tnt_used;
	uint32_t tnt_after;
	uint64_t stop_addr;
	uint64_t entry;
	uint64_t limit;
	uint8_t flags;
	uint8_t pad[7];
} walk_record_t;
_Static_assert(sizeof(walk_record_t) == 68, "walk record is <QQQIIIQQQB7x>");

static char g_walk_buf[1 << 20];
static FILE* g_walk_out = NULL;
static uint64_t g_edge_count = 0;
static uint64_t g_walk_edge_start = 0;

void trace_log_counted(void* ctx, disassembler_mode_t mode, uint64_t src, uint64_t dst)
{
	trace_log(ctx, mode, src, dst);
	g_edge_count++;
}

static void walk_begin(void* opaque)
{
	(void)opaque;
	g_walk_edge_start = g_edge_count;
}

static void walk_end(void* opaque, const libxdc_walk_t* walk)
{
	walk_record_t rec = {
		.anchor_offset = walk->anchor_offset,
		.edge_start = g_walk_edge_start,
		.edge_end = g_edge_count,
		.tnt_before = walk->tnt_before,
		.tnt_used = walk->tnt_before - walk->tnt_after,
		.tnt_after = walk->tnt_after,
		.stop_addr = walk->stop_addr,
		.entry = walk->start,
		.limit = walk->limit,
		.flags = walk->flags,
	};
	fwrite(&rec, sizeof(rec), 1, (FILE*)opaque);
}

static FILE* walk_log_open(const char* path)
{
	static const char magic[8] = {'X', 'D', 'C', '-', 'W', 'A', 'L', 'K'};
	uint32_t version = WALK_LOG_VERSION;
	FILE* f = fopen(path, "wb");
	if (!f)
		return NULL;
	setvbuf(f, g_walk_buf, _IOFBF, sizeof(g_walk_buf));
	/* a short header write sets the stream error flag, checked at close */
	fwrite(magic, sizeof(magic), 1, f);
	fwrite(&version, sizeof(version), 1, f);
	return f;
}

int trace_file(uint64_t filter[4][2], uint8_t* trace, uint64_t trace_size, const char* page_cache_file, const char* outfile, const char* walk_file)
{
	int ret_val = 0;
	bool walk_log_failed = false;
	decoder_result_t ret;
	FILE* out;

	if (0 == strcmp(outfile, "-")) {
		out = stdout;
	} else {
		out = fopen(outfile, "w");
		if (!out) {
			fprintf(stderr, "Error: %s\n", strerror(errno));
			return 1;
		}
	}
	setvbuf(out, g_out_buf, _IOFBF, sizeof(g_out_buf));

	if (walk_file) {
		g_walk_out = walk_log_open(walk_file);
		if (!g_walk_out) {
			fprintf(stderr, "Error: walk log open failed: %s\n", strerror(errno));
			if (out != stdout)
				fclose(out);
			return WALK_LOG_IO_ERROR;
		}
	}

	page_cache_t* page_cache =  page_cache_new(page_cache_file);
	void* bitmap = malloc(0x10000);
	libxdc_t* decoder = libxdc_init(filter, &page_cache_fetch, page_cache, bitmap, 0x10000);
	libxdc_enable_tracing(decoder);
	if (g_walk_out) {
		libxdc_register_edge_callback(decoder, &trace_log_counted, out);
		libxdc_register_walk_callbacks(decoder, &walk_begin, &walk_end, g_walk_out);
	} else {
		libxdc_register_edge_callback(decoder, &trace_log, out);
	}
	ret = libxdc_decode(decoder, trace, trace_size);
	libxdc_disable_tracing(decoder);
	fflush(out);
	if (out != stdout)
		fclose(out);
	if (g_walk_out) {
		int walk_err = ferror(g_walk_out);
		walk_err |= fclose(g_walk_out);
		g_walk_out = NULL;
		if (walk_err)
			fprintf(stderr, "Error: walk log write failed\n");
		walk_log_failed = walk_err != 0;
	}

	print_result_code(ret);
	if (ret != decoder_success && ret != decoder_success_pt_overflow) {
		printf("[*] page fault addr:   \t0x%lx\n", libxdc_get_page_fault_addr(decoder));
		ret_val = 1;
	}
	if (walk_log_failed)
		ret_val = WALK_LOG_IO_ERROR;
	// libxdc bitmap remains zero in trace mode
	//printf("[*] bitmap hash:   \t0x%lx\n", libxdc_bitmap_get_hash(decoder));

	page_cache_destroy(page_cache);
	libxdc_free(decoder);
	free(bitmap);
	return ret_val;
}

int main(int argc, char** argv)
{
	uint64_t filter[4][2] = {0};
	uint64_t start, end;
	uint8_t* trace;
	uint64_t trace_size;
	uint64_t final_hash;
	const char* page_cache_file;
	const char* outfile;
	const char* walk_file = NULL;

	int ret_val;

	/* optional leading `-w <walk_log>`; the positional arguments are unchanged */
	if (argc >= 3 && 0 == strcmp(argv[1], "-w")) {
		walk_file = argv[2];
		argv[2] = argv[0];
		argv += 2;
		argc -= 2;
	}

	if (argc < 6 || argc%2 == 1){
		printf("Usage: %s [-w <walk_log>] <page_cache> <trace_data> <outfile>"
				" <ip_start> <ip_end> [<ip_start> <ip_end>]\n", argv[0]);
		printf("[ ] Aborting...\n");
		return 1;
	}

	//printf("[*] Loading files...\n");

	page_cache_file = argv[1];
	trace = mapfile_read(argv[2], &trace_size);
	outfile = argv[3];

	int arg_n = 4;
	for (int region=0; region<4; region++) {
		if (argc-arg_n < 2)
			break;
		filter[region][0] = strtoul(argv[arg_n], NULL, 16);
		filter[region][1] = strtoul(argv[arg_n+1], NULL, 16);
		//printf("[*] Trace region %d: 0x%lx-0x%lx (size=0x%lx)\n",
		//		region,
		//		filter[region][0], filter[region][1],
		//		filter[region][1]-filter[region][0]);
		arg_n += 2;
	}

	if(!trace){
		printf("[ ] Trace file not found...\n");
		exit(1);
	}
	//printf("[*] Trace size:  \t0x%lx\n", trace_size);

	ret_val = trace_file(filter, trace, trace_size, page_cache_file, outfile, walk_file);

	free(trace);

	return ret_val;
}
