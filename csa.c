/*
 * CSA functions
 * Copyright (C) 2011-2012 Unix Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License (COPYING file) for more details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>

#include "libfuncs/libfuncs.h"

#include "csa.h"

#ifndef DLIB
#define DLIB
#endif

csakey_t *csa_key_alloc(void) {
	struct csakey *key = calloc(1, sizeof(struct csakey));
	key->libaeskey = aes_get_key_struct();
	return (csakey_t *) key;
}

void csa_key_free(csakey_t **pcsakey) {
	struct csakey *key = *((struct csakey **) pcsakey);
	if (key) {
		FREE(*pcsakey);
	}
}

inline unsigned int csa_get_batch_size(void) {
	return 1;
}

inline void csa_set_even_cw(csakey_t *csakey, uint8_t *even_cw) {
	struct csakey *key = (struct csakey *) csakey;
	aes_set_even_control_word(key->libaeskey, even_cw);
}

inline void csa_set_odd_cw(csakey_t *csakey, uint8_t *odd_cw) {
	struct csakey *key = (struct csakey *) csakey;
	aes_set_odd_control_word(key->libaeskey, odd_cw);
}

inline void csa_decrypt_single_packet(csakey_t *csakey, uint8_t *ts_packet) {
	struct csakey *key = (struct csakey *) csakey;
	aes_decrypt_packet(key->libaeskey, ts_packet);
}

inline void csa_decrypt_multiple_even(csakey_t *csakey, struct csa_batch *batch) {
	struct csakey *key = (struct csakey *) csakey;
	dvbcsa_bs_decrypt(key->bs_csakey[0], (struct dvbcsa_bs_batch_s *) batch,
			184);
}

inline void csa_decrypt_multiple_odd(csakey_t *csakey, struct csa_batch *batch) {
	struct csakey *key = (struct csakey *) csakey;
	dvbcsa_bs_decrypt(key->bs_csakey[1], (struct dvbcsa_bs_batch_s *) batch,
			184);
}

inline void csa_decrypt_multiple_ff(csakey_t *csakey, uint8_t **cluster) {
	struct csakey *key = (struct csakey *) csakey;
	ffdecsa_decrypt_packets(key->ff_csakey, cluster);
}

void libaesdec_benchmark(void) {
	struct timeval t0, t1;
	unsigned int n = 0, npackets = 0;
	uint8_t data[188];
	
	// Init keys
	uint8_t ecw[16] = { 0x12, 0x34, 0x56, 0x78, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x89, 0xab, 0xcd, 0xef };
	uint8_t ocw[16] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x12, 0x34, 0x56, 0x78, 0x89, 0xab, 0xcd, 0xef };
	void *key = aes_get_key_struct();
	aes_set_even_control_word(key, ecw);
	aes_set_odd_control_word(key, ocw);

		memset(data, rand(), 188);
                data[0] = 0x47;
                data[1] = 0x01;
                data[2] = 0x02;
                data[3] = 0x91;

	
	printf(" Decrypting %6u mpegts packets\r", n);
	fflush(stdout);

	gettimeofday(&t0, NULL);
	for (n = 0; n < (1 << 20); n++) {
		aes_decrypt_packet(key, data);
		data[3] = 0x91;
		npackets ++;
	}
	gettimeofday(&t1, NULL);

	unsigned long long usec = timeval_diff_usec(&t0, &t1);
	printf(
			"DONE: %u packets (%u bytes) decrypted in %llu ms = %.1f Mbits/s\n\n",
			npackets, npackets * 188, usec / 1000,
			(double) (npackets * 188 * 8) / (double) usec);

	free(key);
}

void csa_benchmark(void) {
	srand(time(0));
	printf("Single threaded AES decoding benchmark : %s\n", DLIB);
	libaesdec_benchmark();
}
