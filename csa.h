/*
 * CSA functions
 * Copyright (C) 2012 Unix Solutions Ltd.
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
#ifndef CSA_H
#define CSA_H

// The following *MUST* be the same as struct dvbcsa_bs_batch_s from libdvbcsa
struct csa_batch {
	uint8_t			*data;	// Pointer to payload
	unsigned int	len;	// Payload bytes lenght
};


#define use_dvbcsa 0
#define dvbcsa_key_t void
#define dvbcsa_bs_key_t void
#define dvbcsa_bs_batch_s csa_batch
static inline dvbcsa_key_t *	dvbcsa_key_alloc(void) { return NULL; }
static inline void				dvbcsa_key_free(dvbcsa_key_t *key) { (void)key; }
static inline void				dvbcsa_key_set(const uint8_t *cw, dvbcsa_key_t *key) { (void)cw; (void)key; }
static inline void				dvbcsa_decrypt(const uint8_t *key, uint8_t *data, unsigned int len) { (void)key; (void)data; (void)len; }
static inline unsigned int		dvbcsa_bs_batch_size(void) { return 0; }
static inline dvbcsa_bs_key_t *	dvbcsa_bs_key_alloc(void) { return NULL; }
static inline void				dvbcsa_bs_key_free(dvbcsa_bs_key_t *key) { (void)key; }
static inline void				dvbcsa_bs_key_set(uint8_t *cw, dvbcsa_bs_key_t *key) { (void)cw; (void)key; }
static inline void				dvbcsa_bs_decrypt(const dvbcsa_bs_key_t *key, const struct dvbcsa_bs_batch_s *pcks, unsigned int maxlen) { (void)key; (void)pcks; (void)maxlen; }

#define ffdecsa_key_t void


#define use_ffdecsa 0
static inline int				ffdecsa_get_internal_parallelism(void) { return 0; }
static inline int				ffdecsa_get_suggested_cluster_size(void) { return 0; }
static inline ffdecsa_key_t *	ffdecsa_key_alloc(void) { return NULL; }
static inline void				ffdecsa_key_free(ffdecsa_key_t *keys) { (void)keys; }
static inline void				ffdecsa_set_cw(ffdecsa_key_t *keys, const uint8_t *even, const uint8_t *odd) { (void)keys; (void)even; (void)odd; }
static inline void				ffdecsa_set_even_cw(void *keys, const uint8_t *even) { (void)keys; (void)even; }
static inline void				ffdecsa_set_odd_cw(ffdecsa_key_t *keys, const uint8_t *odd) { (void)keys; (void)odd; }
static inline int				ffdecsa_decrypt_packets(ffdecsa_key_t *keys, uint8_t **cluster) { (void)keys; (void)cluster; return 0; }

#define libaes_key_t void

#include "libaesdec/libaesdec.h"
#define use_libaesdec 1
static inline libaes_key_t *	libaes_key_alloc(void) { return aes_get_key_struct(); }

#include "data.h"

struct csakey {
	dvbcsa_key_t		*s_csakey[2];
	dvbcsa_bs_key_t		*bs_csakey[2];
	ffdecsa_key_t		*ff_csakey;
	libaes_key_t		*libaeskey;
};

csakey_t *		csa_key_alloc		(void);
void			csa_key_free		(csakey_t **pcsakey);

unsigned int	csa_get_batch_size	(void);

void			csa_set_even_cw		(csakey_t *csakey, uint8_t *even_cw);
void			csa_set_odd_cw		(csakey_t *csakey, uint8_t *odd_cw);

void			csa_decrypt_single_packet	(csakey_t *csakey, uint8_t *ts_packet);
void			csa_decrypt_multiple_even	(csakey_t *csakey, struct csa_batch *batch);
void			csa_decrypt_multiple_odd	(csakey_t *csakey, struct csa_batch *batch);

void			csa_decrypt_multiple_ff		(csakey_t *csakey, uint8_t **cluster);

void csa_benchmark(void);

#endif
