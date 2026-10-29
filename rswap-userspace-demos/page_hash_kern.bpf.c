// SPDX-License-Identifier: GPL-2.0-only
/*
 * page_hash_kern.bpf.c -- BPF program: on-demand SHA-256 via probe-read
 *
 * == Overview ==
 *
 * This BPF program implements the function:
 *
 *   bool get_hash_for_addr(void *__user ptr, char out_hash[32]);
 *
 * Given a userspace pointer, it page-aligns the address, reads the page
 * data from userspace via bpf_probe_read_user(), computes the SHA-256
 * hash entirely inside the BPF program, writes the digest to @out_hash,
 * and returns 1 (true).  Returns 0 (false) if the page is inaccessible.
 *
 * Because this kernel lacks CONFIG_DEBUG_INFO_BTF, we inline all code
 * into the SEC("syscall") entry point — no noinline subprograms that
 * would trigger verifier argument-type rejection.
 *
 * == SHA-256 implementation notes ==
 *
 *   - All loops use compile-time constant bounds so the BPF verifier can
 *     prove termination.
 *   - The 64-round compression and 48-round message-schedule extension
 *     are both bounded by constant literals.
 *   - State (8×u32), W array (64×u32), and block buffer (64 bytes) all
 *     fit within the 512-byte BPF stack.
 *   - SHA-256 is a 32-bit algorithm; we use u32 arithmetic.
 *   - Big-endian conversion is done explicitly with byte-manipulation.
 */

#define __section(NAME)   __attribute__((section(NAME), used))
#define __always_inline   inline __attribute__((always_inline))

/* Basic integer types. */
typedef unsigned char       u8;
typedef unsigned int        u32;
typedef unsigned long long  u64;

/* Pull in the struct get_hash_args definition (ptr, page_size, hash[32]). */
#include "page_hash.h"

/* ------------------------------------------------------------------ */
/*  BPF helper declarations                                           */
/* ------------------------------------------------------------------ */

/* bpf_probe_read_user(void *dst, u32 size, const void *unsafe_ptr) — ID 112 */
static long (*bpf_probe_read_user)(void *dst, u32 size, const void *unsafe_ptr) =
	(void *) 112;

/* ------------------------------------------------------------------ */
/*  SHA-256 constants                                                 */
/* ------------------------------------------------------------------ */

#define SHA256_DIGEST_LEN  32

static const u32 K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* ------------------------------------------------------------------ */
/*  SHA-256 primitives (all __always_inline → no call frames)          */
/* ------------------------------------------------------------------ */

#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))

static __always_inline u32 load_be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
	       ((u32)p[2] <<  8) |  (u32)p[3];
}

static __always_inline void store_be32(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >>  8);
	p[3] = (u8)(v >>  0);
}

static __always_inline u32 Ch(u32 e, u32 f, u32 g) { return (e & f) ^ ((~e) & g); }
static __always_inline u32 Maj(u32 a, u32 b, u32 c) { return (a & b) ^ (a & c) ^ (b & c); }
static __always_inline u32 Sum0(u32 x) { return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22); }
static __always_inline u32 Sum1(u32 x) { return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25); }
static __always_inline u32 Sig0(u32 x) { return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3); }
static __always_inline u32 Sig1(u32 x) { return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10); }

/* ------------------------------------------------------------------ */
/*  SEC("syscall") entry point — does everything inline                */
/* ------------------------------------------------------------------ */

/*
 * Context (from page_hash.h):
 *   struct get_hash_args {
 *       unsigned long long  ptr;       // input:  userspace page address
 *       unsigned char       hash[32];  // output: SHA-256 digest
 *   };
 *
 * Return: 0 on success, 1 if the page could not be read.
 */
__section("syscall")
int lookup_hash_entry(struct get_hash_args *ctx)
{
	u8   block[64];           /* one 64-byte message block      */
	u32  state[8];            /* SHA-256 working state          */
	u64  page_base;           /* page-aligned userspace address      */
	/* We hash a fixed 4096-byte window (64 × 64-byte blocks).
	 * This keeps verifier loop-unrolling well under 1M insns.
	 * Adjust HASH_WINDOW if you need a different size.
	 */
#define HASH_WINDOW  4096u
#define NUM_BLOCKS   (HASH_WINDOW / 64u)   /* = 64 */

	u64  bit_len;             /* message length in bits (HASH_WINDOW * 8) */
	long ret;                 /* bpf_probe_read_user return               */
	int  i;                   /* loop counter                              */
	u32  a, b, c, d, e, f, g, h, t1, t2;
	u32  W[64];

	/* Page-align the userspace address. */
	page_base = ctx->ptr & ~0xfffULL;
	bit_len    = HASH_WINDOW * 8u;

	/* ---- Initialise SHA-256 state ---- */
	state[0] = 0x6a09e667;  state[1] = 0xbb67ae85;
	state[2] = 0x3c6ef372;  state[3] = 0xa54ff53a;
	state[4] = 0x510e527f;  state[5] = 0x9b05688c;
	state[6] = 0x1f83d9ab;  state[7] = 0x5be0cd19;

	bit_len = HASH_WINDOW * 8u;

	/* ---- Process all full blocks ---- */
	for (i = 0; i < NUM_BLOCKS; i++) {
		/* Read 64 bytes from userspace at the current block offset. */
		ret = bpf_probe_read_user(block, 64,
			(const void *)(page_base + (u64)i * 64));
		if (ret < 0)
			return 1;            /* false: page inaccessible */

		/* ---- Message schedule: rounds 0 … 15 ---- */
		for (int w = 0; w < 16; w++)
			W[w] = load_be32(block + 4 * w);

		/* ---- Message schedule: rounds 16 … 63 ---- */
		for (int w = 16; w < 64; w++)
			W[w] = Sig1(W[w - 2]) + W[w - 7] +
			       Sig0(W[w - 15]) + W[w - 16];

		/* ---- Initialise working variables ---- */
		a = state[0];  b = state[1];  c = state[2];  d = state[3];
		e = state[4];  f = state[5];  g = state[6];  h = state[7];

		/* ---- 64 compression rounds ---- */
		for (int r = 0; r < 64; r++) {
			t1 = h + Sum1(e) + Ch(e, f, g) + K[r] + W[r];
			t2 = Sum0(a) + Maj(a, b, c);
			h = g;  g = f;  f = e;  e = d + t1;
			d = c;  c = b;  b = a;  a = t1 + t2;
		}

		/* ---- Update state ---- */
		state[0] += a;  state[1] += b;
		state[2] += c;  state[3] += d;
		state[4] += e;  state[5] += f;
		state[6] += g;  state[7] += h;
	}

	/* ---- SHA-256 padding ---- */
	/*
	 * SHA-256 always appends:
	 *   1. 0x80 byte  (a '1' bit followed by zeros)
	 *   2. 0x00 bytes until (msg_len + 1 + pad + 8) ≡ 0 (mod 64)
	 *   3. 64-bit big-endian bit-length
	 *
	 * Since HASH_WINDOW is a multiple of 64, the padding always fills
	 * exactly one extra block:  0x80 || (55 zeros) || 8-byte length.
	 */
	for (i = 0; i < 64; i++)
		block[i] = 0;
	block[0]   = 0x80;          /* start of padding */

	/* Store bit_len in big-endian in the last 8 bytes of the block. */
	block[56]  = (u8)(bit_len >> 56);
	block[57]  = (u8)(bit_len >> 48);
	block[58]  = (u8)(bit_len >> 40);
	block[59]  = (u8)(bit_len >> 32);
	block[60]  = (u8)(bit_len >> 24);
	block[61]  = (u8)(bit_len >> 16);
	block[62]  = (u8)(bit_len >>  8);
	block[63]  = (u8)(bit_len >>  0);

	/* Message schedule + compression for the padding block. */
	for (int w = 0; w < 16; w++)
		W[w] = load_be32(block + 4 * w);
	for (int w = 16; w < 64; w++)
		W[w] = Sig1(W[w - 2]) + W[w - 7] +
		       Sig0(W[w - 15]) + W[w - 16];
	a = state[0];  b = state[1];  c = state[2];  d = state[3];
	e = state[4];  f = state[5];  g = state[6];  h = state[7];
	for (int r = 0; r < 64; r++) {
		t1 = h + Sum1(e) + Ch(e, f, g) + K[r] + W[r];
		t2 = Sum0(a) + Maj(a, b, c);
		h = g;  g = f;  f = e;  e = d + t1;
		d = c;  c = b;  b = a;  a = t1 + t2;
	}
	state[0] += a;  state[1] += b;
	state[2] += c;  state[3] += d;
	state[4] += e;  state[5] += f;
	state[6] += g;  state[7] += h;

	/* ---- Output final digest (big-endian) ---- */
	store_be32(ctx->hash +  0, state[0]);
	store_be32(ctx->hash +  4, state[1]);
	store_be32(ctx->hash +  8, state[2]);
	store_be32(ctx->hash + 12, state[3]);
	store_be32(ctx->hash + 16, state[4]);
	store_be32(ctx->hash + 20, state[5]);
	store_be32(ctx->hash + 24, state[6]);
	store_be32(ctx->hash + 28, state[7]);

	return 0;                            /* true: hash computed */
}

/* ------------------------------------------------------------------ */
/*  License                                                           */
/* ------------------------------------------------------------------ */

char _license[] __section("license") = "GPL";
