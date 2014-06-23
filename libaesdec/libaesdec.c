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
	struct aes_key_t even; // table 0x80
	struct aes_key_t odd; // table 0x81
};

struct aes_keys_t aes_keys;
struct aes_key_t aes_key;

void set_even_control_word(void *keys, const unsigned char *pk) {
	schedule_key(&((struct aes_keys_t *) keys)->even, pk);
}

void set_odd_control_word(void *keys, const unsigned char *pk) {
	schedule_key(&((struct aes_keys_t *) aes_keys)->odd, pk);
}

//-----set control words
void set_control_words(void *keys, const unsigned char *ev, const unsigned char *od){
  schedule_key(&((struct aes_keys_t *)keys)->even,ev);
  schedule_key(&((struct aes_keys_t *)keys)->odd,od);
}

static void schedule_key(struct aes_key_t *key, const unsigned char *pk) {
	AES_set_decrypt_key(pk, 128, aes_keys->even);
}


//-----key structure

void *get_key_struct(void){
  struct aes_keys_t *keys=(struct aes_keys_t *)MALLOC(sizeof(struct aes_keys_t));
  if(keys) {
    static const unsigned char pk[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    set_control_words(keys,pk,pk);
    }
  return keys;
}

void free_key_struct(void *keys){
  return FREE(keys);
}


//----- decrypt

int decrypt_packet(void *keys, unsigned char *packet) {
	int stat_no_scramble;
	int stat_reserved;
	int grouped;
	int group_ev_od;
	int advanced;
	int can_advance;

	unsigned char *pkt;
	int xc0, ev_od, len, offset, n, residue;
	struct csa_key_t* k;
	int i, j, iter, g;
	int t23, tsmall;
	int alive[24];

	pkt = packet;

	AES_ecb_encrypt(,,AES_DECRYPT);

	do { // handle this packet
		xc0 = pkt[3] & 0xc0;
		DBG(fprintf(stderr,"   exam pkt=%p, xc0=%02x, can_adv=%i\n",pkt,xc0,can_advance));
		if (xc0 == 0x00) {
			DBG(fprintf(stderr,"skip clear pkt %p (can_advance is %i)\n",pkt,can_advance));
			advanced += can_advance;
			stat_no_scramble++;
			break;
		}
		if (xc0 == 0x40) {
			DBG(fprintf(stderr,"skip reserved pkt %p (can_advance is %i)\n",pkt,can_advance));
			advanced += can_advance;
			stat_reserved++;
			break;
		}
		if (xc0 == 0x80 || xc0 == 0xc0) { // encrypted
			ev_od = (xc0 & 0x40) >> 6; // 0 even, 1 odd
			if (grouped == 0)
				group_ev_od = ev_od; // this group will be all even (or odd)
			if (group_ev_od == ev_od) { // could be added to group
				pkt[3] &= 0x3f;  // consider it decrypted now
				if (pkt[3] & 0x20) { // incomplete packet
					offset = 4 + pkt[4] + 1;
					len = 188 - offset;
					n = len >> 3;
					residue = len - (n << 3);
					if (n == 0) { // decrypted==encrypted!
						DBG(fprintf(stderr,"DECRYPTED MINI! (can_advance is %i)\n",can_advance));
						advanced += can_advance;
						break; // this doesn't need more processing
					}
				} else {
					len = 184;
					offset = 4;
					n = 23;
					residue = 0;
				}

			} else {
				can_advance = 0;
				DBG(fprintf(stderr,"skip pkt %p and can_advance set to 0\n",pkt));
				break; // skip and go on
			}
		}
	} while (0);

	DBG(fprintf(stderr,"-- result: grouped %i pkts, advanced %i pkts\n",grouped,advanced));

	if (grouped == 0) {
		// no processing needed
		return advanced;
	}

	//  sort them, longest payload first
	//  we expect many n=23 packets and a few n<23
	DBG(fprintf(stderr,"PRESORTING\n"));
	for (i = 0; i < grouped; i++) {
		DBG(fprintf(stderr,"%2i of %2i: pkt=%p len=%03i n=%2i residue=%i\n",i,grouped,g_pkt[i],g_len[i],g_n[i],g_residue[i]));
	}

	// choose key
	if (group_ev_od == 0) {
		k = &((struct aes_keys_t *) keys)->even;
	} else {
		k = &((struct aes_keys_t *) keys)->odd;
	}

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

	return advanced;
}
