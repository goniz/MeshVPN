/***************************************************************************
*   Copyright (C) 2013 by Tobias Volk                                     *
*   mail@tobiasvolk.de                                                    *
*                                                                         *
*   This program is free software: you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation, either version 3 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
*   This program is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
*   GNU General Public License for more details.                          *
*                                                                         *
*   You should have received a copy of the GNU General Public License     *
*   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
***************************************************************************/


#ifndef H_DH
#define H_DH


#include "crypto.h"
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/bn.h>


// Maximum and minimum sizes of DH public key in bytes.
#define dh_MINSIZE 96
#define dh_MAXSIZE 768


// The DH state structure.
struct s_dh_state {
    DH *dh;
    BIGNUM *bn;
    unsigned char pubkey[dh_MAXSIZE];
    int pubkey_size;
};


// Load DH parameters.
int dhLoadParams(struct s_dh_state *dhstate, unsigned char *dhpem, const int dhpem_size);

// Load default DH parameters.
int dhLoadDefaultParams(struct s_dh_state *dhstate);

// Generate a key.
int dhGenKey(struct s_dh_state *dhstate);

// Create a DH state object.
int dhCreate(struct s_dh_state *dhstate);

// Destroy a DH state object.
void dhDestroy(struct s_dh_state *dhstate);

// Get size of binary encoded DH public key in bytes.
int dhGetPubkeySize(const struct s_dh_state *dhstate);

// Get binary encoded DH public key. Returns length if successful.
int dhGetPubkey(unsigned char *buf, const int buf_size, const struct s_dh_state *dhstate);

// Generate symmetric keys. Returns 1 if succesful.
int dhGenCryptoKeys(struct s_crypto *ctx, const int ctx_count, const struct s_dh_state *dhstate, const unsigned char *peerkey, const int peerkey_len, const unsigned char *nonce, const int nonce_len);

#endif // H_DH