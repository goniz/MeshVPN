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

#ifndef H_NODEID
#define H_NODEID
#include "rsa.h"

#define NODEID_SIZE 32

// NodeID size in bytes.
#define nodeid_SIZE 32


// Maximum and minumum sizes of DER encoded NodeKey in bytes.
#define nodekey_MINSIZE RSA_MINSIZE
#define nodekey_MAXSIZE RSA_MAXSIZE


// The nodeid structure.
struct s_nodeid {
        unsigned char id[NODEID_SIZE];
};


// The nodekey structure.
struct s_nodekey {
        struct s_nodeid nodeid;
        struct s_rsa key;
};

void nodeidExtract(char * buffer, struct s_nodeid * node);

// Create a NodeKey object.
int nodekeyCreate(struct s_nodekey *nodekey);

// Get DER encoded public key from NodeKey object. Returns length if successful.
int nodekeyGetDER(unsigned char *buf, const int buf_size, const struct s_nodekey *nodekey);

// Generate a new NodeKey with public/private key pair.
int nodekeyGenerate(struct s_nodekey *nodekey, const int key_size);

/**
 * Export nodekey to file
 */
int nodekeyExport(struct s_nodekey * nodekey, const char * keypath);

int nodekeyImport(struct s_nodekey * nodekey, const char * keypath);

// Load NodeKey from DER encoded public key.
int nodekeyLoadDER(struct s_nodekey *nodekey, const unsigned char *pubkey, const int pubkey_size);

// Load NodeKey from PEM encoded public key.
int nodekeyLoadPEM(struct s_nodekey *nodekey, unsigned char *pubkey, const int pubkey_size);

// Load NodeKey from PEM encoded private key.
int nodekeyLoadPrivatePEM(struct s_nodekey *nodekey, unsigned char *privkey, const int privkey_size);

// Destroy a NodeKey object.
void nodekeyDestroy(struct s_nodekey *nodekey);

#endif // H_NODEID
