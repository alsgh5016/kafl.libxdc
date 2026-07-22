/*
 * ptdump_bench.c - benchmark variant of ptdump to isolate the per-edge output
 * cost from libxdc decode cost.
 *
 * Build one binary per MODE:
 *   -DMODE_RAW  : current behaviour (unbuffered dprintf per edge -> fd)
 *   -DMODE_NOOP : count edges only, no output  (isolates decode + callback)
 *   -DMODE_BUF  : buffered stdio (setvbuf big buffer) fprintf per edge
 *
 * Prints: edges decoded + wall time of libxdc_decode() only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <libxdc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "page_cache.h"
#include "helper.h"
#include <errno.h>

static unsigned long long g_edges = 0;

#if defined(MODE_NOOP)
void trace_log(void* ctx, disassembler_mode_t mode, uint64_t src, uint64_t dst) {
	(void)ctx; (void)mode; (void)src; (void)dst;
	g_edges++;
}
#elif defined(MODE_BUF)
void trace_log(void* ctx, disassembler_mode_t mode, uint64_t src, uint64_t dst) {
	(void)mode;
	g_edges++;
	fprintf((FILE*)ctx, "%lx,%lx\n", src, dst);   /* buffered via setvbuf */
}
#else /* MODE_RAW: exactly the shipping ptdump.c behaviour */
void trace_log(void* ctx, disassembler_mode_t mode, uint64_t src, uint64_t dst) {
	(void)mode;
	g_edges++;
	dprintf(*(int*)ctx, "%lx,%lx\n", src, dst);   /* unbuffered write() per edge */
}
#endif

static double now_s(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char** argv) {
	uint64_t filter[4][2] = {0};
	uint8_t* trace;
	uint64_t trace_size;

	if (argc < 6 || argc % 2 == 1) {
		printf("Usage: %s <page_cache> <trace_data> <outfile> <ip_start> <ip_end> [...]\n", argv[0]);
		return 1;
	}
	const char* page_cache_file = argv[1];
	trace = mapfile_read(argv[2], &trace_size);
	const char* outfile = argv[3];
	int arg_n = 4;
	for (int region = 0; region < 4; region++) {
		if (argc - arg_n < 2) break;
		filter[region][0] = strtoul(argv[arg_n], NULL, 16);
		filter[region][1] = strtoul(argv[arg_n + 1], NULL, 16);
		arg_n += 2;
	}
	if (!trace) { printf("[ ] Trace file not found...\n"); exit(1); }

	page_cache_t* page_cache = page_cache_new(page_cache_file);
	void* bitmap = malloc(0x10000);
	libxdc_t* decoder = libxdc_init(filter, &page_cache_fetch, page_cache, bitmap, 0x10000);
	libxdc_enable_tracing(decoder);

	/* set up output context per mode */
#if defined(MODE_NOOP)
	libxdc_register_edge_callback(decoder, &trace_log, NULL);
#elif defined(MODE_BUF)
	FILE* fp = fopen(outfile, "w");
	static char buf[1 << 22];               /* 4 MB stdio buffer */
	setvbuf(fp, buf, _IOFBF, sizeof(buf));
	libxdc_register_edge_callback(decoder, &trace_log, fp);
#else
	int fd = open(outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	libxdc_register_edge_callback(decoder, &trace_log, &fd);
#endif

	double t0 = now_s();
	decoder_result_t ret = libxdc_decode(decoder, trace, trace_size);
	double t1 = now_s();
	libxdc_disable_tracing(decoder);

#if defined(MODE_BUF)
	fflush(fp); fclose(fp);
#elif !defined(MODE_NOOP)
	close(fd);
#endif

	const char* mode =
#if defined(MODE_NOOP)
		"NOOP";
#elif defined(MODE_BUF)
		"BUF";
#else
		"RAW";
#endif
	fprintf(stderr, "[bench] mode=%s ret=%d edges=%llu decode_wall=%.3fs\n",
	        mode, (int)ret, g_edges, t1 - t0);

	page_cache_destroy(page_cache);
	libxdc_free(decoder);
	free(bitmap);
	return 0;
}
