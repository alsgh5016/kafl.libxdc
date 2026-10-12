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

/* user header */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define LIBXDC_RELEASE_VERSION 2

#define PT_TRACE_END			__extension__ 0b01010101

typedef void libxdc_t;

typedef enum decoder_result_s { 
	decoder_success, 
	decoder_success_pt_overflow,
	decoder_page_fault, 
	decoder_error,
	decoder_unkown_packet,
} decoder_result_t;

typedef enum disassembler_mode_s { 
	mode_16, 
	mode_32, 
	mode_64,
} disassembler_mode_t;

/* Walk log record, mirrors src/core.h (see libxdc_register_walk_callbacks). */
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

uint16_t libxdc_get_release_version(void);

void libxdc_reset_trace_cache(libxdc_t* self);

libxdc_t* libxdc_init(uint64_t filter[4][2], void* (*page_cache_fetch_fptr)(void*, uint64_t, bool*), void* page_cache_fetch_opaque, void* bitmap_ptr, size_t bitmap_size);
decoder_result_t libxdc_decode(libxdc_t* self, uint8_t* data, size_t len);

uint64_t libxdc_bitmap_get_hash(libxdc_t* self);
uint64_t libxdc_get_page_fault_addr(libxdc_t* self);

void libxdc_free(libxdc_t* self);
void libxdc_bitmap_reset(libxdc_t* self);

void libxdc_register_bb_callback(libxdc_t* self,  void (*basic_block_callback)(void*, disassembler_mode_t, uint64_t, uint64_t), void* basic_block_callback_opaque);
void libxdc_register_edge_callback(libxdc_t* self,  void (*edge_callback)(void*, disassembler_mode_t, uint64_t, uint64_t), void* edge_callback_opaque);
void libxdc_register_ip_callback(libxdc_t* self,  void (*ip_callback)(void*, disassembler_mode_t, uint64_t), void* ip_callback_opaque);
/*
 * Opt-in walk log. A walk is one disassembler run from an IP anchor to the next
 * one (only when TNT bits are pending). walk_begin (may be NULL) runs right
 * before the walk emits its first edge, walk_end right after its last one, so a
 * caller that counts edge callbacks gets each walk's edge range. Passing a NULL
 * walk_end disables the log (the default); the decode itself is unchanged.
 * Walks are reported in trace mode (libxdc_enable_tracing) only.
 */
void libxdc_register_walk_callbacks(libxdc_t* self, void (*walk_begin)(void*), void (*walk_end)(void*, const libxdc_walk_t*), void* opaque);

void libxdc_enable_tracing(libxdc_t* self);
void libxdc_disable_tracing(libxdc_t* self);
