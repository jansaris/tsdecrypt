/*
 * libaesdec.c
 *
 *  Created on: Jun 22, 2014
 *      Author: root
 */

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "openssl/aes.h"

#include "libaesdec.h"

#ifndef NULL
#define NULL 0
#endif

//#define DEBUG
#ifdef DEBUG
#define DBG(a) a
#else
#define DBG(a)
#endif

struct aes_key_t {
	AES_KEY aesk;
	unsigned char iA[10];  // TimeStamp
};

struct aes_keys_t {
	AES_KEY even; // table 0x80
	AES_KEY odd; // table 0x81
};


/*static void aes_schedule_key(struct aes_key_t *key, const unsigned char *pk) {





}*/

void aes_set_even_control_word(void *keys, const unsigned char *pk) {
	AES_set_decrypt_key(pk, 128, &((struct aes_keys_t *) keys)->even);
//	aes_schedule_key(&((struct aes_keys_t *) keys)->even, pk);
}

void aes_set_odd_control_word(void *keys, const unsigned char *pk) {
	AES_set_decrypt_key(pk, 128, &((struct aes_keys_t *) keys)->odd);
	//aes_schedule_key(&((struct aes_keys_t *) aes_keys)->odd, pk);
}

//-----set control words
void aes_set_control_words(void *keys, const unsigned char *ev,
		const unsigned char *od) {

	AES_set_decrypt_key(ev, 128, &((struct aes_keys_t *) keys)->even);
	AES_set_decrypt_key(od, 128, &((struct aes_keys_t *) keys)->odd);
	//aes_schedule_key(&((struct aes_keys_t *) keys)->even, ev);
	//aes_schedule_key(&((struct aes_keys_t *) keys)->odd, od);
}



//-----key structure

void *aes_get_key_struct(void) {
	struct aes_keys_t *keys = (struct aes_keys_t *) malloc(
			sizeof(struct aes_keys_t));
	if (keys) {
		static const unsigned char pk[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0 };
		aes_set_control_words(keys, pk, pk);
	}
	return keys;
}

void free_key_struct(void *keys) {
	return free(keys);
}

//----- decrypt

int aes_decrypt_packet(void *keys, unsigned char *packet) {
	int stat_no_scramble;
	int stat_reserved;
	int group_ev_od = 0;
	int advanced = 0;
	int can_advance;

	unsigned char *pkt;
	int xc0, ev_od, len, offset, n;

	AES_KEY k;
	pkt = packet;

	// TODO check all flags

	do { // handle this packet
		xc0 = pkt[3] & 0xc0;         // encrypted
		DBG(fprintf(stderr,"   exam pkt=%p, xc0=%02x, can_adv=%i\n",pkt,xc0,can_advance));
		if (xc0 == 0x00) {
			DBG(fprintf(stderr,"skip clear pkt %p (can_advance is %i)\n",pkt,can_advance));
			advanced += can_advance;
			stat_no_scramble++;
			return advanced;
		}
		if (xc0 == 0x40) {
			DBG(fprintf(stderr,"skip reserved pkt %p (can_advance is %i)\n",pkt,can_advance));
			advanced += can_advance;
			stat_reserved++;
			return advanced;
		}
		if (xc0 == 0x80 || xc0 == 0xc0) { // encrypted     TODO Find our encryption flag
			ev_od = (xc0 & 0x40) >> 6; // 0 even, 1 odd   TODO Find our key flag

			pkt[3] &= 0x3f;  // consider it decrypted now
			if (pkt[3] & 0x20) { // incomplete packet
				offset = 4 + pkt[4] + 1;
				len = 188 - offset;
				n = len >> 3;
				//residue = len - (n << 3);
				if (n == 0) { // decrypted==encrypted!
					DBG(fprintf(stderr,"DECRYPTED MINI! (can_advance is %i)\n",can_advance));
					advanced += can_advance;
					return advanced;  // this doesn't need more processing
				}

			} else {
				can_advance = 0;
				DBG(fprintf(stderr,"skip pkt %p and can_advance set to 0\n",pkt));
				return advanced; // skip and go on
			}
		}
	} while (0);

	//INIT
//#define INITIALIZE_UNUSED_INPUT
#ifdef INITIALIZE_UNUSED_INPUT
// unnecessary zeroing.
// without this, we operate on uninitialized memory
// when grouped<GROUP_PARALLELISM, but it's not a problem,
// as final results will be discarded.
// random data makes debugging sessions difficult.
	for(j=0;j<GROUP_PARALLELISM*8;j++) stream_in[j]=0;
	DBG(fprintf(stderr,"--- WARNING: you could gain speed by not initializing unused memory ---\n"));
#else
	DBG(fprintf(stderr,"--- WARNING: DEBUGGING IS MORE DIFFICULT WHEN PROCESSING RANDOM DATA CHANGING AT EVERY RUN! ---\n"));
#endif

	// choose key
	if (group_ev_od == 0) {
		k = ((struct aes_keys_t *) keys)->even;
	} else {
		k = ((struct aes_keys_t *) keys)->odd;
	}

	len = sizeof(pkt);

	if (remainder(len, 16) != 0) {
		DBG(fprintf(stderr,"pkt does not have correct length"));
	}

	int i;
	for (i = 0; i < len; i += 16) {
		AES_ecb_encrypt(pkt + i, pkt + i, &k, AES_DECRYPT);
	}

	return advanced;
}
