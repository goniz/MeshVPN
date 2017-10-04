/*
 * MeshVPN - A open source peer-to-peer VPN (forked from PeerVPN)
 *
 * Copyright (C) 2012-2016  Tobias Volk <mail@tobiasvolk.de>
 * Copyright (C) 2016       Hideman Developer <company@hideman.net>
 * Copyright (C) 2017       Benjamin Kübler <b.kuebler@kuebler-it.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef H_RSA
#define H_RSA

#include <stdio.h>
#include <stdlib.h>

#include "logging.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

// Minimum size of DER encoded RSA public key in bytes.
#define RSA_MINSIZE 48

// Maximum size of DER encoded RSA public key in bytes.
#define RSA_MAXSIZE 416


// The RSA structure.
struct s_rsa {
        int isvalid;
        int isprivate;
        EVP_PKEY *key;
        EVP_MD_CTX *md;
        BIGNUM *bn;
};

// Get SHA-256 fingerprint of public key
int rsaGetFingerprint(unsigned char *buf, const int buf_size, const struct s_rsa *rsa);

/**
 * Loading private key from PEM encoded file
 * keypath should be accessable
 */
int rsaImportKey(struct s_rsa * rsa, const char *keypath);

/**
 * Generate RSA key pair
 * @NOTE: we don't cleanup anything because in case of failure we are going to exit
 */
int rsaGenerate(struct s_rsa *rsa, const int key_size);

/**
 * Export our private key file to PEM format
 */
int rsaExportKey(struct s_rsa * rsa, const char * keypath);

// Load DER encoded public key.
int rsaLoadDER(struct s_rsa *rsa, const unsigned char *pubkey, const int pubkey_size);

// Load PEM encoded public key.
int rsaLoadPEM(struct s_rsa *rsa, unsigned char *pubkey, const int pubkey_size);

// Load PEM encoded private key.
int rsaLoadPrivatePEM(struct s_rsa *rsa, unsigned char *privkey, const int privkey_size);

// Return maximum size of a signature.
int rsaSignSize(const struct s_rsa *rsa);

// Generate signature. Returns length of signature if successful.
int rsaSign(struct s_rsa *rsa, unsigned char *sign_buf, const int sign_len, const unsigned char *in_buf, const int in_len);

// Verify signature. Returns 1 if successful.
int rsaVerify(struct s_rsa *rsa, const unsigned char *sign_buf, const int sign_len, const unsigned char *in_buf, const int in_len);

// Reset a RSA object.
void rsaReset(struct s_rsa *rsa);

// Create a RSA object.
int rsaCreate(struct s_rsa *rsa);

// Destroy a RSA object.
void rsaDestroy(struct s_rsa *rsa);

#endif // H_RSA
