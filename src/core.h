/*
Copyright (c) 2020 Sergej Schumilo, Cornelius Aschermann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "khash.h"
#include <unistd.h>
#include <sys/time.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include "tnt_cache.h"
#include "cfg.h"

#define INIT_TRACE_IP 0xFFFFFFFFFFFFFFFFULL

/*
 * Opt-in walk log (see libxdc_register_walk_callbacks). A walk is one
 * trace_disassembler run from an IP anchor to the next one; it only happens
 * when TNT bits are pending. Mirrored in the public libxdc.h.
 */
#define LIBXDC_WALK_PAGE_FAULT   0x01 /* hit a missing page; the decoder resyncs at the next PGE/FUP */
#define LIBXDC_WALK_INDIRECT     0x02 /* stopped at an indirect / far transfer (waits for a TIP) */
#define LIBXDC_WALK_LIMITED      0x04 /* bounded by a FUP or TIP.PGD IP */
#define LIBXDC_WALK_OOB_OR_LOOP  0x08 /* libxdc OUT_OF_BOUNDS or loop-limit stop; see LOOP and LEFT_RANGE */
#define LIBXDC_WALK_LOOP         0x10 /* loop limit (MAX_LOOP_COUNT) reached; implies OOB_OR_LOOP */
#define LIBXDC_WALK_LEFT_RANGE   0x20 /* left the filter range (branch target outside it, or block ran past its end); implies OOB_OR_LOOP */
/* A walk that genuinely reached its FUP/PGD limit block is exactly:
 * LIMITED && OOB_OR_LOOP && !LOOP && !LEFT_RANGE. */

typedef struct libxdc_walk_s {
	uint64_t anchor_offset; /* byte offset in the decoded buffer of the TIP/PGE/PGD packet that ran the walk, or of the FUP packet for a FUP-bound walk; UINT64_MAX when that FUP was in an earlier libxdc_decode() call */
	uint64_t start;         /* walk entry IP */
	uint64_t limit;         /* FUP/PGD IP bounding the walk (0 when not LIMITED) */
	uint64_t stop_addr;     /* branch instruction the walk stopped at; faulting address on a page fault;
	                           LEFT_RANGE: 0 when a branch target was outside the range (the target is the dst
	                           of the walk's last edge), else the first instruction past the range end */
	uint32_t tnt_before;    /* TNT bits pending when the walk started */
	uint32_t tnt_after;     /* TNT bits left when it stopped */
	uint8_t flags;          /* LIBXDC_WALK_* */
} libxdc_walk_t;

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

typedef struct tracelet_cache_s{
	uint64_t next_entry_address;
	uint8_t tnt_bits;

	uint8_t result_bits; 
	uint8_t result_bits_max;
	uint32_t* bitmap_results;
	bool cont_exec;
} tracelet_cache_t;


typedef struct tracelet_cache_tmp_s{
	tracelet_cache_t cache;
	uint8_t* lookup_bitmap;
} tracelet_cache_tmp_t;

typedef struct trace_cache_key_s{
	uint64_t tnt_hash;
	uint64_t entry;
	uint64_t limit;
} trace_cache_key_t;


#define kh_trace_cache_key_t_hash_func(key)  (khint32_t)(((key.entry)>>33^(key.entry)^(key.entry)<<11) ^ ((key.limit)>>33^(key.limit)^(key.limit)<<11) ^ ((key.tnt_hash)>>33^(key.tnt_hash)^(key.tnt_hash)<<11))

//static inline int kh_trace_cache_key_t_equal(trace_cache_key_t k1, trace_cache_key_t k2) { return !memcmp(&k1, &k2, sizeof(k1)); }
static inline int kh_trace_cache_key_t_equal(trace_cache_key_t k1, trace_cache_key_t k2) { return k1.tnt_hash == k2.tnt_hash && k1.entry == k2.entry && k1.limit == k2.limit ; }

KHASH_INIT(TRACE_CACHE, trace_cache_key_t, tracelet_cache_t*, 1, kh_trace_cache_key_t_hash_func, kh_trace_cache_key_t_equal)

typedef struct trace_cache_s{
	khash_t(TRACE_CACHE) *lookup;
	tracelet_cache_tmp_t* trace_cache;
} trace_cache_t;

typedef struct fuzz_bitmap_s {
	uint8_t* bitmap;
	uint32_t bitmap_size;
} fuzz_bitmap_t;

typedef struct{
	uint16_t opcode;
	uint8_t modrm;
	uint8_t opcode_prefix;
} cofi_ins;


typedef enum disas_result_s { 
	disas_success, 
	disas_tnt_empty, 
	disas_tip_pending,
	disas_out_of_bounds,
	disas_infinite_loop,
	disas_page_fault,
} disas_result_t;


typedef enum disassembler_mode_s { 
	mode_16, 
	mode_32, 
	mode_64,
} disassembler_mode_t;

typedef struct disassembler_s{
	bool infinite_loop_found;

	uint8_t* code;
	uint64_t min_addr_0;
	uint64_t max_addr_0;
	uint64_t min_addr_1;
	uint64_t max_addr_1;
	uint64_t min_addr_2;
	uint64_t max_addr_2;
	uint64_t min_addr_3;
	uint64_t max_addr_3;

	bool debug;
	bool has_pending_indirect_branch;
	uint64_t pending_indirect_branch_src;
	fuzz_bitmap_t* fuzz_bitmap;
	trace_cache_t* trace_cache;

	uint8_t disassemble_cache[32];

	csh handle_16;
	csh handle_32;
	csh handle_64;

	bool trace_mode;

	void* (*page_cache_fetch_fptr)(void*, uint64_t, bool*);
	void* page_cache_fetch_opaque;

	void (*trace_edge_callback)(void*, disassembler_mode_t, uint64_t, uint64_t);
	void* trace_edge_callback_opaque;

	void (*basic_block_callback)(void*, disassembler_mode_t, uint64_t, uint64_t);
	void* basic_block_callback_opaque;

	disassembler_cfg_t cfg;

	/* walk log: branch address where the last trace-mode walk stopped */
	uint64_t walk_stop_addr;
	/* walk log: the last trace-mode walk stopped on an OUT_OF_BOUNDS node (left the filter range) */
	bool walk_left_range;

} disassembler_t;



typedef enum decoder_state { 
	TraceDisabled=1, 
	TraceEnabledWithLastIP, 
	TraceEnabledWOLastIP} 
decoder_state_e;

typedef struct DecoderStateMachine{
  decoder_state_e state;
  uint64_t last_ip;
} decoder_state_machine_t;

/*
Used as return type for statemachine updates, start and end are undefined unless valid is true
*/
typedef struct ShouldDisasm{
  uint64_t start;
  uint64_t end;
  bool valid;
} should_disasm_t;


typedef struct decoder_s{
	bool page_fault_found;
	uint64_t page_fault_addr;
	bool ovp_state; 
	uint64_t last_tip;
	uint64_t last_tip_tmp;
	uint64_t last_fup_src;
	bool fup_bind_pending;
	disassembler_t* disassembler_state;
	tnt_cache_t* tnt_cache_state;
	decoder_state_machine_t* decoder_state;
	should_disasm_t* decoder_state_result;
	disassembler_mode_t mode;
	int error_counter;

	void (*ip_callback)(void*, disassembler_mode_t, uint64_t);
	void* ip_callback_opaque;

	/* walk log (NULL walk_end_callback = disabled, the default) */
	void (*walk_begin_callback)(void*);
	void (*walk_end_callback)(void*, const libxdc_walk_t*);
	void* walk_callback_opaque;
	const uint8_t* walk_map_base;
	const uint8_t* last_fup_pkt;

#ifdef DECODER_LOG
	struct decoder_log_s{
		uint64_t tnt64;
		uint64_t tnt8;
		uint64_t pip;
		uint64_t cbr;
		uint64_t ts;
		uint64_t ovf;
		uint64_t psbc;
		uint64_t psbend;
		uint64_t mnt;
		uint64_t tma;
		uint64_t vmcs;
		uint64_t pad;
		uint64_t tip;
		uint64_t tip_pge;
		uint64_t tip_pgd;
		uint64_t tip_fup;
		uint64_t mode;
	} log;
#endif
} decoder_t;

typedef enum decoder_result_s { 
	decoder_success, 
	decoder_success_pt_overflow,
	decoder_page_fault, 
	decoder_error,
	decoder_unkown_packet,
} decoder_result_t;


typedef struct libxdc_s {
	fuzz_bitmap_t* fuzz_bitmap;
  decoder_t* decoder;
  disassembler_t* disassembler;

  uint64_t trace_regions[4][2];
} libxdc_t;

#ifdef DEBUG_TRACES
#define LOGGER(format, ...) (printf(format, ##__VA_ARGS__))
#else
#define LOGGER(format, ...)  (void)0 
#endif