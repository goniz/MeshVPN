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

#ifndef H_AUTH
#define H_AUTH

#include "dh.h"
#include "logging.h"
#include "rsa.h"
#include "util.h"
#include "nodeid.h"

#include "idsp.h"
#include "p2p.h"

// Auth state definitions.
#define auth_IDLE 0
#define auth_S0a 1
#define auth_S0b 2
#define auth_S1a 3
#define auth_S1b 4
#define auth_S2a 5
#define auth_S2b 6
#define auth_S3a 7
#define auth_S3b 8
#define auth_S4a 9
#define auth_S4b 10
#define auth_S5a 11

#define AUTH_STATE_IDLE 0
#define AUTH_STATE_INITIATED 1
#define AUTH_STATE_STARTED 1
#define AUTH_STATE_FINISHED_LOCAL 10
#define AUTH_STATE_FINISHED 11
#define AUTH_STATE_FINISH_ACK 12


// Size of HMAC tag.
#define auth_HMACSIZE 32
#define AUTH_HMACSIZE 32


// Size of identity protection IV and HMAC
#define auth_IDPHMACSIZE auth_HMACSIZE
#define auth_IDPIVSIZE 16


// Size of CNEG IV and HMAC
#define auth_CNEGHMACSIZE auth_HMACSIZE
#define auth_CNEGIVSIZE 16


// Size of nonces.
#define auth_NONCESIZE 32
#define AUTH_NONCESIZE 32


// Maximum size of auth messages in bytes.
#define auth_MAXMSGSIZE_S0 (4 + 2 + 8 + 4 + 4 + netid_SIZE)
#define auth_MAXMSGSIZE_S1 (4 + 2 + 8 + 4 + auth_NONCESIZE + 2 + dh_MAXSIZE)
#define auth_MAXMSGSIZE_S2 (4 + 2 + 2 + nodekey_MAXSIZE + 2 + nodekey_MAXSIZE + auth_HMACSIZE + auth_IDPIVSIZE + auth_IDPHMACSIZE + crypto_MAXIVSIZE)
#define auth_MAXMSGSIZE_S3 (4 + 2 + auth_NONCESIZE + seq_SIZE + 4 + 8 + auth_CNEGIVSIZE + auth_CNEGHMACSIZE + crypto_MAXIVSIZE)
#define auth_MAXMSGSIZE_S4 (4 + 2 + auth_NONCESIZE + auth_CNEGHMACSIZE)


// Size of signature input buffer
#define auth_SIGINBUFSIZE (4 + 2 + auth_NONCESIZE + auth_NONCESIZE + dh_MAXSIZE + dh_MAXSIZE)


// Crypto ctx definitions.
#define auth_CRYPTOCTX_AUTH 0
#define auth_CRYPTOCTX_IDP 1
#define auth_CRYPTOCTX_CNEG 2
#define auth_CRYPTOCTX_SESSION_A 3
#define auth_CRYPTOCTX_SESSION_B 4
#define auth_CRYPTOCTX_COUNT 5


// Constraints.
#define auth_MAXMSGSIZE 0
#if auth_MAXMSGSIZE < auth_MAXMSGSIZE_S0
#undef auth_MAXMSGSIZE
#define auth_MAXMSGSIZE auth_MAXMSGSIZE_S0
#endif
#if auth_MAXMSGSIZE < auth_MAXMSGSIZE_S1
#undef auth_MAXMSGSIZE
#define auth_MAXMSGSIZE auth_MAXMSGSIZE_S1
#endif
#if auth_MAXMSGSIZE < auth_MAXMSGSIZE_S2
#undef auth_MAXMSGSIZE
#define auth_MAXMSGSIZE auth_MAXMSGSIZE_S2
#endif
#if auth_MAXMSGSIZE < auth_MAXMSGSIZE_S3
#undef auth_MAXMSGSIZE
#define auth_MAXMSGSIZE auth_MAXMSGSIZE_S3
#endif
#if auth_MAXMSGSIZE < auth_MAXMSGSIZE_S4
#undef auth_MAXMSGSIZE
#define auth_MAXMSGSIZE auth_MAXMSGSIZE_S4
#endif
#if auth_MAXMSGSIZE > 960
#error auth_MAXMSGSIZE too big
#endif


// The auth state structure.
struct s_auth_state {
        int state;
        int remote_dhkey_size;
        int nextmsg_size;
        int local_cneg_set;
        unsigned char local_authid[4];
        unsigned char remote_authid[4];
        unsigned char local_flags[8];
        unsigned char remote_flags[8];
        unsigned char local_seq[seq_SIZE];
        unsigned char remote_seq[seq_SIZE];
        unsigned char s4msg_nonce[auth_NONCESIZE];
        unsigned char keygen_nonce[(auth_NONCESIZE + auth_NONCESIZE)];
        unsigned char local_keygen_nonce[auth_NONCESIZE];
        unsigned char remote_keygen_nonce[auth_NONCESIZE];
        unsigned char local_nonce[auth_NONCESIZE];
        unsigned char remote_nonce[auth_NONCESIZE];
        unsigned char remote_dhkey[dh_MAXSIZE];
        unsigned char nextmsg[auth_MAXMSGSIZE];
        unsigned char local_sesstoken[4];
        unsigned char remote_sesstoken[4];
        int local_peerid;
        int remote_peerid;
        struct s_nodekey *local_nodekey;
        struct s_nodekey remote_nodekey;
        struct s_crypto crypto_ctx[auth_CRYPTOCTX_COUNT];
        struct s_dh_state *dhstate;
        struct s_netid *netid;
};


// Prepare signature input buffer for remote sig(authid, msgnum, remote_nonce, local_nonce, local_dhkey, remote_dhkey).
int authGenRemoteSigIn(struct s_auth_state *authstate, unsigned char *siginbuf, const unsigned char *msgnum);

// Prepare signature input buffer for sig(authid, msgnum, local_nonce, remote_nonce, remote_dhkey, local_dhkey).
int authGenSigIn(struct s_auth_state *authstate, unsigned char *siginbuf, const unsigned char *msgnum);

// Generate auth message S0
void authGenS0(struct s_auth_state *authstate);

// Decode auth message S0
int authDecodeS0(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len);

// Generate auth message S1
void authGenS1(struct s_auth_state *authstate);

// Decode auth message S1
int authDecodeS1(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len);

// Generate auth message S2
void authGenS2(struct s_auth_state *authstate);

// Decode auth message S2
int authDecodeS2(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len);

// Generate auth message S3
void authGenS3(struct s_auth_state *authstate);

// Decode auth message S3
int authDecodeS3(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len);

// Generate auth message S4
void authGenS4(struct s_auth_state *authstate);

// Decode auth message S4
int authDecodeS4(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len);

// Generate auth message
void authGenMsg(struct s_auth_state *authstate);

// Decode auth message. Returns 1 if message is accepted.
int authDecodeMsg(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len);

// Reset auth state object.
void authReset(struct s_auth_state *authstate);

// Start new auth session.
int authStart(struct s_auth_state *authstate);

// Check if peer has completed a dh exchange.
int authIsPreauth(struct s_auth_state *authstate);

// Check if peer is authenticated.
int authIsAuthed(struct s_auth_state *authstate);

// Check if peer is authenticated & connection parameters are negotiated.
int authIsCompleted(struct s_auth_state *authstate);

// Check if peer has completed the authentication.
int authIsPeerCompleted(struct s_auth_state *authstate);

// Get remote NodeID. Returns 1 if successful.
int authGetRemoteNodeID(struct s_auth_state *authstate, struct s_nodeid *nodeid);

// Get remote PeerID. Returns 1 if successful.
int authGetRemotePeerID(struct s_auth_state *authstate, int *remote_peerid);

// Get shared session keys. Returns 1 if successful.
int authGetSessionKeys(struct s_auth_state *authstate, struct s_crypto *ctx);

// Get connection parameters. Returns 1 if successful.
int authGetConnectionParams(struct s_auth_state *authstate, int64_t *seq, int64_t *flags);

// Get next auth message.
int authGetNextMsg(struct s_auth_state *authstate, struct s_msg *out_msg);

// Set local PeerID and sequence number (required to complete auth protocol)
void authSetLocalData(struct s_auth_state *authstate, const int peerid, const int64_t seq, const int64_t flags);

// Create auth state object.
int authCreate(struct s_auth_state *authstate, struct s_netid *netid, struct s_nodekey *local_nodekey, struct s_dh_state *dhstate, const int authid);

// Destroy auth state object.
void authDestroy(struct s_auth_state *authstate);

#endif // H_AUTH
