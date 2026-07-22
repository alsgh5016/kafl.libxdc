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

int trace_file(uint64_t filter[4][2], uint8_t* trace, uint64_t trace_size, const char* page_cache_file, const char* outfile)
{
	int ret_val = 0;
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

	page_cache_t* page_cache =  page_cache_new(page_cache_file);
	void* bitmap = malloc(0x10000);
	libxdc_t* decoder = libxdc_init(filter, &page_cache_fetch, page_cache, bitmap, 0x10000);
	libxdc_enable_tracing(decoder);
	libxdc_register_edge_callback(decoder, &trace_log, out);
	ret = libxdc_decode(decoder, trace, trace_size);
	libxdc_disable_tracing(decoder);
	fflush(out);
	if (out != stdout)
		fclose(out);

	print_result_code(ret);
	if (ret != decoder_success && ret != decoder_success_pt_overflow) {
		printf("[*] page fault addr:   \t0x%lx\n", libxdc_get_page_fault_addr(decoder));
		ret_val = 1;
	}
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

	int ret_val;

	if (argc < 6 || argc%2 == 1){
		printf("Usage: %s <page_cache> <trace_data> <outfile>"
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

	ret_val = trace_file(filter, trace, trace_size, page_cache_file, outfile);

	free(trace);

	return ret_val;
}
