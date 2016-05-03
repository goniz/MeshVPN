/***************************************************************************
 *   Copyright (C) 2014 by Tobias Volk                                     *
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


#ifndef F_AUTH_C
#define F_AUTH_C

#include <time.h>

#include "../../libp2psec/msg.c"
#include "../../libp2psec/seq.c"
#include "../../libp2psec/netid.c"

#include "dh.h"
#include "logging.h"
#include "rsa.h"
#include "auth.h"
#include "util.h"
#include "nodeid.h"


// Prepare signature input buffer for remote sig(authid, msgnum, remote_nonce, local_nonce, local_dhkey, remote_dhkey).
int authGenRemoteSigIn(struct s_auth_state *authstate, unsigned char *siginbuf, const unsigned char *msgnum) {
	int dhsize;
	int ret;
	memcpy(siginbuf, authstate->remote_authid, 4);
	memcpy(&siginbuf[4], msgnum, 2);
	memcpy(&siginbuf[(4 + 2)], authstate->local_nonce, auth_NONCESIZE);
	memcpy(&siginbuf[(4 + 2 + auth_NONCESIZE)], authstate->remote_nonce, auth_NONCESIZE);
	dhsize = dhGetPubkey(&siginbuf[(4 + 2 + auth_NONCESIZE + auth_NONCESIZE)], dh_MAXSIZE, authstate->dhstate);
	memcpy(&siginbuf[(4 + 2 + auth_NONCESIZE + auth_NONCESIZE + dhsize)], authstate->remote_dhkey, authstate->remote_dhkey_size);
	ret = (4 + 2 + auth_NONCESIZE + auth_NONCESIZE + dhsize + authstate->remote_dhkey_size);
	return ret;
}


// Prepare signature input buffer for sig(authid, msgnum, local_nonce, remote_nonce, remote_dhkey, local_dhkey).
int authGenSigIn(struct s_auth_state *authstate, unsigned char *siginbuf, const unsigned char *msgnum) {
	int dhsize;
	int ret;
	memcpy(siginbuf, authstate->local_authid, 4);
	memcpy(&siginbuf[4], msgnum, 2);
	memcpy(&siginbuf[(4 + 2)], authstate->remote_nonce, auth_NONCESIZE);
	memcpy(&siginbuf[(4 + 2 + auth_NONCESIZE)], authstate->local_nonce, auth_NONCESIZE);
	memcpy(&siginbuf[(4 + 2 + auth_NONCESIZE + auth_NONCESIZE)], authstate->remote_dhkey, authstate->remote_dhkey_size);
	dhsize = dhGetPubkey(&siginbuf[(4 + 2 + auth_NONCESIZE + auth_NONCESIZE + authstate->remote_dhkey_size)], dh_MAXSIZE, authstate->dhstate);
	ret = (4 + 2 + auth_NONCESIZE + auth_NONCESIZE + authstate->remote_dhkey_size + dhsize);
	return ret;
}


/**
 * Generate auth message S0
 * It has following structure:
 *
 * 4 bytes  - remote auth ID
 * 2 bytes  - current state on our side (msgnum)
 * 8 bytes  - SHA 256 checksum
 * 4 bytes  - local auth ID
 * 4 bytes  - session token
 * 32 bytes - network ID
 * 
 */
void authGenS0(struct s_auth_state *authstate) {
	// generate msg(remote_authid, msgnum, checksum, authid, sesstoken, netid)
	int msgnum = authstate->state;
	memcpy(authstate->nextmsg, authstate->remote_authid, 4);
	utilWriteInt16(&authstate->nextmsg[4], msgnum);
    
    memset(&authstate->nextmsg[(4 + 2)], '\0', 8);
	memcpy(&authstate->nextmsg[(4 + 2 + 8)], &authstate->local_authid, 4);
	memcpy(&authstate->nextmsg[(4 + 2 + 8 + 4)], &authstate->local_sesstoken, 4);
	memcpy(&authstate->nextmsg[(4 + 2 + 8 + 4 + 4)], authstate->netid->id, NETID_SIZE);
	
    // calculate 8 bytes hash
    if(!cryptoCalculateSHA256(&authstate->nextmsg[(4 + 2)], 8, &authstate->nextmsg[(4 + 2 + 8)], (4 + 4 + NETID_SIZE))) {
        authstate->nextmsg_size = 0;
        debug("failed to create S0 SHA checksum");
        return;
    }
    
    authstate->nextmsg_size = (4 + 2 + 8 + 4 + 4 + NETID_SIZE);
    debugf("Generated S0 message, size %d bytes, RemoteID: %d", authstate->nextmsg_size, authstate->remote_authid);
}



// Decode auth message S0
int authDecodeS0(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len) {
    int msgnum;
    unsigned char checksum[8];
    if(msg_len < (4 + 2 + 8 + 4 + 4 + NETID_SIZE)) {
        debugf("wrong S0 message size: %d", msg_len);
        return 0;
    }
    
    msgnum = utilReadInt16(&msg[4]);
    int expected_state = authstate->state + 1;
    if(msgnum != expected_state) {
        debugf("wrong S0 msgnum: %d, waiting for %d", msgnum, expected_state);
        return 0;
    }
    
    if(!cryptoCalculateSHA256(checksum, 8, &msg[(4 + 2 + 8)], (4 + 4 + NETID_SIZE))) {
        debug("unable to create SHA256 sum for S0 message");
        return 0;
    }
    
    if(memcmp(checksum, &msg[(4 + 2)], 8) != 0) {
        debug("checksum verification failed for S0");
        return 0;
    }
    
    if(memcmp(authstate->netid->id, &msg[(4 + 2 + 8 + 4 + 4)], NETID_SIZE) != 0) {
        debug("NetID verification failed for S0 message");
        return 0;
    }
    
    memcpy(authstate->remote_authid, &msg[(4 + 2 + 8)], 4);
    memcpy(authstate->remote_sesstoken, &msg[(4 + 2 + 8 + 4)], 4);
    
    debugf("S0 message is valid. Remote AuthID: %d, Session token: %d",authstate->remote_authid, authstate->remote_sesstoken);
    
    return 1;
}

/**
 * Generate auth message S1
 * Structure:
 * 4 bytes - remote_authid
 * 2 bytes - msgnum
 * 8 bytes - checksum
 * 4 bytes - session token
 
 */
void authGenS1(struct s_auth_state *authstate) {
	// generate msg(remote_authid, msgnum, checksum, sesstoken, nonce, dhkey_len, dhkey)
	int msgnum = authstate->state;
	int dhsize;
    
	memcpy(authstate->nextmsg, authstate->remote_authid, 4);
	utilWriteInt16(&authstate->nextmsg[4], msgnum);
    memset(&authstate->nextmsg[(4 + 2)], '\0', 8);
	memcpy(&authstate->nextmsg[(4 + 2 + 8)], &authstate->remote_sesstoken, 4);
	memcpy(&authstate->nextmsg[(4 + 2 + 8 + 4)], authstate->local_nonce, auth_NONCESIZE);
    
	dhsize = dhGetPubkey(&authstate->nextmsg[(4 + 2 + 8 + 4 + AUTH_NONCESIZE + 2)], dh_MAXSIZE, authstate->dhstate);
	
    if(dhsize < dh_MINSIZE || dhsize > dh_MAXSIZE) {
        debugf("wrong DH size passed %d", dhsize);
        authstate->nextmsg_size = 0;
        return;
    }
    
    utilWriteInt16(&authstate->nextmsg[(4 + 2 + 8 + 4 + AUTH_NONCESIZE)], dhsize);
    
    if(!cryptoCalculateSHA256(&authstate->nextmsg[(4 + 2)], 8, &authstate->nextmsg[(4 + 2 + 8)], (4 + AUTH_NONCESIZE + 2 + dhsize))) {
        debug("failed to calculate S1 SHA checksum");
        authstate->nextmsg_size = 0;
        return;
    }
    
    
    authstate->nextmsg_size = (4 + 2 + 8 + 4 + AUTH_NONCESIZE + 2 + dhsize);
}


// Decode auth message S1
int authDecodeS1(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len) {
	int msgnum;
	int dhsize;
	unsigned char shared_nonce[auth_NONCESIZE + auth_NONCESIZE];
	unsigned char checksum[8];
    int min_msg_len = (4 + 2 + 8 + 4 + auth_NONCESIZE + 2);
    
    if(msg_len <= min_msg_len) {
        debugf("wrong msg_len %d, minimum %d", msg_len, min_msg_len);
        return 0;
    }
    
    msgnum = utilReadInt16(&msg[4]);
    int expected_state = authstate->state + 1;
    if(msgnum != expected_state) {
        debugf("wrong msg_num, current %d, expected %d", msgnum, expected_state);
        return 0;
    }
    
    if(memcmp(authstate->local_sesstoken, &msg[(4 + 2 + 8)], 4) != 0) {
        debug("different local and remote session tokens");
        return 0;
    }
    
    dhsize = utilReadInt16(&msg[(4 + 2 + 8 + 4 + auth_NONCESIZE)]);
    if(!((dhsize > dh_MINSIZE) && (dhsize <= dh_MAXSIZE) && (msg_len >= (4 + 2 + 8 + 4 + auth_NONCESIZE + 2 + dhsize)))) {
        debug("DH size error");
        return 0;
    }
    
    if(!cryptoCalculateSHA256(checksum, 8, &msg[(4 + 2 + 8)], (4 + auth_NONCESIZE + 2 + dhsize))) {
        debug("failed to calculate SHA256");
        return 0;
    }
    
    if(memcmp(checksum, &msg[(4 + 2)], 8) != 0) {
        debug("checksum verification failed");
        return 0;
    }
    
    authstate->remote_dhkey_size = dhsize;
    memcpy(authstate->remote_dhkey, &msg[(4 + 2 + 8 + 4 + auth_NONCESIZE + 2)], dhsize);
    memcpy(authstate->remote_nonce, &msg[(4 + 2 + 8 + 4)], auth_NONCESIZE);
    
    if(memcmp(authstate->local_nonce, authstate->remote_nonce, auth_NONCESIZE) == 0) {
        debug("different local and remote nonce");
        return 0;
    }
    
    if((msgnum % 2) == 0) {
        memcpy(&shared_nonce[0], &msg[(4 + 2 + 8 + 4)], auth_NONCESIZE);
        memcpy(&shared_nonce[auth_NONCESIZE], authstate->local_nonce, auth_NONCESIZE);
    } else {
        memcpy(&shared_nonce[0], authstate->local_nonce, auth_NONCESIZE);
        memcpy(&shared_nonce[auth_NONCESIZE], &msg[(4 + 2 + 8 + 4)], auth_NONCESIZE);
    }
    
    if(!dhGenCryptoKeys(authstate->crypto_ctx, auth_CRYPTOCTX_COUNT, authstate->dhstate, &msg[(4 + 2 + 8 + 4 + auth_NONCESIZE + 2)], dhsize, shared_nonce, (auth_NONCESIZE + auth_NONCESIZE))) {
        debug("failed to generate DH crypto keys");
        return 0;
    }
    
    debugf("S1 message decoded for Remote %d <-> Local %d", authstate->remote_authid, authstate->local_authid);
	return 1;
}


/**
 * Generate auth message S2
 * 4 bytes - remote_authid
 * 2 bytes - msgnum
 * enc(
 *   2 bytes - pubkey_len
 *   76 - 416 bytes - public key
 *   ?? bytes - RSA signature size
 *   ?? bytes - signature (authid, msgnum, local_nonce, remote_nonce, remote_dhkey, local_dhkey), 
 *   32 bytes - hmac(pubkey)
 * )
 
 */
void authGenS2(struct s_auth_state * as) {
	// generate msg(remote_authid, msgnum, enc(pubkey_len, pubkey, sig_len, sig(authid, msgnum, local_nonce, remote_nonce, remote_dhkey, local_dhkey), hmac(pubkey)))
	unsigned char unencrypted_nextmsg[auth_MAXMSGSIZE_S2];
	int unencrypted_nextmsg_size;
	int msgnum = as->state;
	unsigned char siginbuf[auth_SIGINBUFSIZE];
	struct s_nodekey *local_nodekey;
	struct s_rsa *rsakey;
	int siginbuf_size;
	int nksize;
	int signsize;
	int encsize;
	memcpy(unencrypted_nextmsg, as->remote_authid, 4);
	utilWriteInt16(&unencrypted_nextmsg[4], msgnum);
	memcpy(as->nextmsg, unencrypted_nextmsg, 6);
	siginbuf_size = authGenSigIn(as, siginbuf, &unencrypted_nextmsg[4]);
	local_nodekey = as->local_nodekey;
	nksize = nodekeyGetDER(&unencrypted_nextmsg[(4 + 2 + 2)], nodekey_MAXSIZE, local_nodekey);
	
    if(nksize <= nodekey_MINSIZE) {
        as->nextmsg_size = 0;
        debugf("wrong local nodekey size, got %d", nksize);
        return;
    }
    
    utilWriteInt16(&unencrypted_nextmsg[(4 + 2)], nksize);
    rsakey = &local_nodekey->key;
    signsize = rsaSign(rsakey, &unencrypted_nextmsg[(4 + 2 + 2 + nksize + 2)], nodekey_MAXSIZE, siginbuf, siginbuf_size);
    if(signsize <= 0) {
        as->nextmsg_size = 0;
        debug("wrong RSA signature size");
        return;
    }
    
    utilWriteInt16(&unencrypted_nextmsg[(4 + 2 + 2 + nksize)], signsize);
    if(!cryptoHMAC(&as->crypto_ctx[auth_CRYPTOCTX_AUTH], &unencrypted_nextmsg[(4 + 2 + 2 + nksize + 2 + signsize)], auth_HMACSIZE, &unencrypted_nextmsg[(4 + 2 + 2)], nksize)) {
        as->nextmsg_size = 0;
        debug("failed to generate HMAC");
        return;
    }
    
    unencrypted_nextmsg_size = (4 + 2 + 2 + nksize + 2 + signsize + auth_HMACSIZE);
    encsize = cryptoEnc(&as->crypto_ctx[auth_CRYPTOCTX_IDP], &as->nextmsg[(4 + 2)], (auth_MAXMSGSIZE - 2 - 4), &unencrypted_nextmsg[(2 + 4)], (unencrypted_nextmsg_size - 2 - 4), auth_IDPHMACSIZE, auth_IDPIVSIZE);
    
    if(encsize <= 0) {
        debug("failed to encrypt S2 message");
        as->nextmsg_size = 0;
        return;
    }
    
    as->nextmsg_size = (encsize + 4 + 2);
    debugf("S2 message generated, size: %d, AuthID: %d", as->nextmsg_size, as->remote_authid);
}


// Decode auth message S2
int authDecodeS2(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len) {
	int msgnum;
	int nksize;
	int signsize;
	int decmsg_len;
	unsigned char hmac[auth_HMACSIZE];
	unsigned char siginbuf[auth_SIGINBUFSIZE];
	unsigned char decmsg[auth_MAXMSGSIZE_S2];
	int siginbuf_size;
	
    if(msg_len <= 10) {
        debugf("small msg_len for S2 message %d", msg_len);
        return 0;
    }
    
    memcpy(decmsg, msg, 6);
    msgnum = utilReadInt16(&decmsg[4]);
    if(msgnum != (authstate->state + 1)) {
        debugf("wrong msgnum received %d, current state: %d", msgnum, authstate->state);
        return 0;
    }
    
    decmsg_len = (4 + 2 + cryptoDec(&authstate->crypto_ctx[auth_CRYPTOCTX_IDP], &decmsg[(4 + 2)], (auth_MAXMSGSIZE_S2 - 2 - 4), &msg[(4 + 2)], (msg_len - 2 - 4), auth_IDPHMACSIZE, auth_IDPIVSIZE)); // decrypt IDP layer
    
    if(decmsg_len <= 10) {
        debugf("S2 decoded message wrong size, got: %d", decmsg_len);
        return 0;
    }
    
    nksize = utilReadInt16(&decmsg[(4 + 2)]);
    if((nksize > nodekey_MINSIZE) && (nksize <= nodekey_MAXSIZE) && (decmsg_len > (10 + nksize))) {
        signsize = utilReadInt16(&decmsg[(4 + 4 + nksize)]);
        if((signsize > 0) && (decmsg_len >= (10 + nksize + signsize + auth_HMACSIZE))) { // check message length
            if(cryptoHMAC(&authstate->crypto_ctx[auth_CRYPTOCTX_AUTH], hmac, auth_HMACSIZE, &decmsg[(4 + 4)], nksize)) { // generate HMAC tag
                if(memcmp(&decmsg[(10 + nksize + signsize)], hmac, auth_HMACSIZE) == 0) { // verify HMAC tag
                    if(nodekeyLoadDER(&authstate->remote_nodekey, &decmsg[(4 + 4)], nksize)) { // load remote public key
                        if(memcmp(authstate->remote_nodekey.nodeid.id, authstate->local_nodekey->nodeid.id, nodeid_SIZE) != 0) { // check if remote public key is different from local public key
                            siginbuf_size = authGenRemoteSigIn(authstate, siginbuf, &decmsg[4]);
                            if(rsaVerify(&authstate->remote_nodekey.key, &decmsg[(10 + nksize)], signsize, siginbuf, siginbuf_size)) { // verify signature
                                return 1;
                            }
                        }
                    }
                }
            }
        }
    }
    
	return 0;
}


// Generate auth message S3
void authGenS3(struct s_auth_state *authstate) {
	// generate msg(remote_authid, msgnum, enc(keygen_nonce, local_seq, local_peerid, local_flags))
	unsigned char unencrypted_nextmsg[auth_MAXMSGSIZE_S3];
	int unencrypted_nextmsg_size = (4 + 2 + auth_NONCESIZE + seq_SIZE + 4 + 8);
	int msgnum = authstate->state;
	int encsize;
	if(authstate->local_cneg_set) {
		memcpy(unencrypted_nextmsg, authstate->remote_authid, 4);
		utilWriteInt16(&unencrypted_nextmsg[4], msgnum);
		memcpy(authstate->nextmsg, unencrypted_nextmsg, 6);
		memcpy(&unencrypted_nextmsg[(4 + 2)], authstate->local_keygen_nonce, auth_NONCESIZE);
		memcpy(&unencrypted_nextmsg[(4 + 2 + auth_NONCESIZE)], authstate->local_seq, seq_SIZE);
		utilWriteInt32(&unencrypted_nextmsg[(4 + 2 + auth_NONCESIZE + seq_SIZE)], authstate->local_peerid);
		memcpy(&unencrypted_nextmsg[(4 + 2 + auth_NONCESIZE + seq_SIZE + 4)], authstate->local_flags, 8);
		encsize = cryptoEnc(&authstate->crypto_ctx[auth_CRYPTOCTX_CNEG], &authstate->nextmsg[(4 + 2)], (auth_MAXMSGSIZE - 2 - 4), &unencrypted_nextmsg[(4 + 2)], (unencrypted_nextmsg_size - 2 - 4), auth_CNEGHMACSIZE, auth_CNEGIVSIZE);
		if(encsize > 0) {
			authstate->nextmsg_size = (encsize + 4 + 2);
		}
		else {
			authstate->nextmsg_size = 0;
		}
	}
	else {
		authstate->nextmsg_size = 0;
	}
}


// Decode auth message S3
int authDecodeS3(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len) {
	int msgnum;
	int decmsg_len;
	unsigned char decmsg[auth_MAXMSGSIZE_S3];
	if(msg_len > 6) {
		memcpy(decmsg, msg, 6);
		msgnum = utilReadInt16(&decmsg[4]);
		if(msgnum == (authstate->state + 1)) {
			decmsg_len = (4 + 2 + cryptoDec(&authstate->crypto_ctx[auth_CRYPTOCTX_CNEG], &decmsg[(4 + 2)], (auth_MAXMSGSIZE_S3 - 2 - 4), &msg[(4 + 2)], (msg_len - 2 - 4), auth_CNEGHMACSIZE, auth_CNEGIVSIZE));
			if(decmsg_len >= (4 + 2 + auth_NONCESIZE + seq_SIZE + 4 + 8)) {
				memcpy(authstate->remote_keygen_nonce, &decmsg[(4 + 2)], auth_NONCESIZE);
				if((msgnum % 2) == 0) {
					memcpy(&authstate->keygen_nonce[0], authstate->local_keygen_nonce, auth_NONCESIZE);
					memcpy(&authstate->keygen_nonce[auth_NONCESIZE], authstate->remote_keygen_nonce, auth_NONCESIZE);
				}
				else {
					memcpy(&authstate->keygen_nonce[0], authstate->remote_keygen_nonce, auth_NONCESIZE);
					memcpy(&authstate->keygen_nonce[auth_NONCESIZE], authstate->local_keygen_nonce, auth_NONCESIZE);
				}
				memcpy(authstate->remote_seq, &decmsg[(4 + 2 + auth_NONCESIZE)], seq_SIZE);
				authstate->remote_peerid = utilReadInt32(&decmsg[(4 + 2 + auth_NONCESIZE + seq_SIZE)]);
				memcpy(authstate->remote_flags, &decmsg[(4 + 2 + auth_NONCESIZE + seq_SIZE + 4)], 8);
				return 1;
			}
		}
	}
	return 0;
}


// Generate auth message S4
void authGenS4(struct s_auth_state *authstate) {
	// generate msg(remote_authid, msgnum, nonce, hmac_nonce)
	int msgnum = authstate->state;
	memcpy(authstate->nextmsg, authstate->remote_authid, 4);
	utilWriteInt16(&authstate->nextmsg[4], msgnum);
	memcpy(&authstate->nextmsg[6], authstate->s4msg_nonce, auth_NONCESIZE);
	if(!cryptoHMAC(&authstate->crypto_ctx[auth_CRYPTOCTX_CNEG], &authstate->nextmsg[(6 + auth_NONCESIZE)], auth_CNEGHMACSIZE, authstate->s4msg_nonce, auth_NONCESIZE)) {
        authstate->nextmsg_size = 0;
        debugf("HMAC generation failed for Remote %d <-> Local %d", authstate->remote_authid, authstate->local_authid);
        return;
    }
    
    authstate->nextmsg_size = (6 + auth_NONCESIZE + auth_CNEGHMACSIZE);
    debugf("S4 message successfully generated", authstate->nextmsg_size);
}


// Decode auth message S4
int authDecodeS4(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len) {
	int msgnum;
    int min_msg_len = 6 + auth_NONCESIZE + auth_CNEGHMACSIZE;
    
	unsigned char hmac[AUTH_HMACSIZE];
    
	if(msg_len < min_msg_len) {
        debugf("S4 wrong msg_len, %d != %d", msg_len, min_msg_len);
        return 0;
    }
    
    msgnum = utilReadInt16(&msg[4]);
    if(msgnum != (authstate->state + 1)) {
        debugf("S4 wrong msgnum, got %d", msgnum);
        return 0;
    }
    
    if(!cryptoHMAC(&authstate->crypto_ctx[auth_CRYPTOCTX_CNEG], hmac, AUTH_HMACSIZE, &msg[6], auth_NONCESIZE)) {
        debug("S4 HMAC generation failed");
        return 0;
    }
    
    if(memcmp(hmac, &msg[(6 + auth_NONCESIZE)], auth_CNEGHMACSIZE) != 0) {
        debug("S4 HMAC verification failed");
        return 0;
    }
    
    debugf("S4 message successfully decoded. Remote %d <-> Local %d", authstate->remote_authid, authstate->local_authid);
    
    return 1;
}

int authDecodeS5(struct s_auth_state * authstate, const unsigned char *msg, const int msg_len) {
    int msgnum;
    
    msgnum = utilReadInt16(&msg[4]);
    if(msgnum != AUTH_STATE_FINISHED) {
        debug("S5 wrong state received");
        return 0;
    }
    
    debugf("S5 message accepted. Msgnum: %d", msgnum);
    return 1;
}

int authGenS5(struct s_auth_state *authstate) {
    // generate msg(msgnum)
    int msgnum = authstate->state;
    
    memcpy(authstate->nextmsg, authstate->remote_authid, 4);
    utilWriteInt16(&authstate->nextmsg[4], msgnum);
    memcpy(&authstate->nextmsg[(4 + 2)], &authstate->remote_authid, 4);

    authstate->nextmsg_size = 4 + 2 + 4;
    
    debugf("S5 message successfully generated, size %d, state: %d", authstate->nextmsg_size, msgnum);
}

// Generate auth message
void authGenMsg(struct s_auth_state *authstate) {
	int state = authstate->state;
	
    switch(state) {
		case AUTH_STATE_INITIATED:
		case auth_S0b:
			authGenS0(authstate);
			break;
		case auth_S1a:
		case auth_S1b:
			authGenS1(authstate);
			break;
		case auth_S2a:
		case auth_S2b:
			authGenS2(authstate);
			break;
		case auth_S3a:
		case auth_S3b:
			authGenS3(authstate);
			break;
		case auth_S4a:
		case auth_S4b:
			authGenS4(authstate);
			break;
            
        // generating ACK packet and finishing it
        case AUTH_STATE_FINISHED:
            authGenS5(authstate);
            break;
            
        case AUTH_STATE_FINISH_ACK:
            authstate->nextmsg_size = 0;
            break;
            
		default:
			authstate->nextmsg_size = 0;
			break;
	}
    
    debugf("Generating state MSG, current state: %d, generated: %d", state, authstate->nextmsg_size);
}

// Decode auth message. Returns 1 if message is accepted.
int authDecodeMsg(struct s_auth_state *authstate, const unsigned char *msg, const int msg_len) {
	int state = authstate->state;
	int newstate = state;
    
	switch(state) {
		case auth_IDLE: if(authDecodeS0(authstate, msg, msg_len)) newstate = auth_S0b; break;
		case auth_S0a:  if(authDecodeS0(authstate, msg, msg_len)) newstate = auth_S1a; break;
		case auth_S0b:  if(authDecodeS1(authstate, msg, msg_len)) newstate = auth_S1b; break;
		case auth_S1a:  if(authDecodeS1(authstate, msg, msg_len)) newstate = auth_S2a; break;
		case auth_S1b:  if(authDecodeS2(authstate, msg, msg_len)) newstate = auth_S2b; break;
		case auth_S2a:  if(authDecodeS2(authstate, msg, msg_len)) newstate = auth_S3a; break;
		case auth_S2b:  if(authDecodeS3(authstate, msg, msg_len)) newstate = auth_S3b; break;
		case auth_S3a:  if(authDecodeS3(authstate, msg, msg_len)) newstate = auth_S4a; break;
		case auth_S3b:  if(authDecodeS4(authstate, msg, msg_len)) newstate = auth_S4b; break;
		case auth_S4a:  if(authDecodeS4(authstate, msg, msg_len)) newstate = auth_S5a; break;
        case auth_S4b:  if(authDecodeS5(authstate, msg, msg_len)) newstate = AUTH_STATE_FINISH_ACK; break;
	}
    
    debugf("AUTH state request %d, newstate %d, nextmsg_size: %d", state, newstate, authstate->nextmsg_size);

    if(state == newstate) {
        debugf("Failed to change state %d => %d", state, state + 1);
        return 0;
    }
    
    debugf("AUTH state changed %d => %d", state, newstate);
    
    authstate->state = newstate;
    authGenMsg(authstate);
    
    return 1;
}


// Reset auth state object.
void authReset(struct s_auth_state *authstate) {
	authstate->state = auth_IDLE;
	memset(authstate->local_seq, 0, seq_SIZE);
	memset(authstate->remote_seq, 0, seq_SIZE);
	memset(authstate->local_flags, 0, seq_SIZE);
	memset(authstate->remote_flags, 0, seq_SIZE);
	memset(authstate->local_keygen_nonce, 0, auth_NONCESIZE);
	memset(authstate->remote_keygen_nonce, 0, auth_NONCESIZE);
	memset(authstate->keygen_nonce, 0, auth_NONCESIZE + auth_NONCESIZE);
	cryptoRand(authstate->local_nonce, auth_NONCESIZE);
	memset(authstate->remote_nonce, 0, auth_NONCESIZE);
	memset(authstate->remote_dhkey, 0, dh_MAXSIZE);
	memset(authstate->remote_authid, 0, 4);
	memset(authstate->nextmsg, 0, auth_MAXMSGSIZE);
	authstate->remote_peerid = -1;
	cryptoRand(authstate->local_sesstoken, 4);
	memset(authstate->remote_sesstoken, 0, 4);
	authstate->nextmsg_size = 0;
	authstate->local_cneg_set = 0;
	cryptoSetKeysRandom(authstate->crypto_ctx, auth_CRYPTOCTX_COUNT);
}


// Start new auth session.
int authStart(struct s_auth_state *authstate) {
	if(authstate->state != AUTH_STATE_IDLE) {
        debugf("failed to start new AUTH session, current status %d", authstate->state);
        return 0;
    }
    
    authstate->state = AUTH_STATE_INITIATED;
    authGenMsg(authstate);
    
    return 1;
}


// Check if peer has completed a dh exchange.
int authIsPreauth(struct s_auth_state *authstate) {
	if(authstate->state >= auth_S1b) {
		return 1;
	}
	else {
		return 0;
	}
}


// Check if peer is authenticated.
int authIsAuthed(struct s_auth_state *authstate) {
	if(authstate->state >= auth_S2b) {
		return 1;
	}
	else {
		return 0;
	}
}


// Check if peer is authenticated & connection parameters are negotiated.
int authIsCompleted(struct s_auth_state *authstate) {
    return (authstate->state >= auth_S3b);
}


// Check if peer has completed the authentication.
int authIsPeerCompleted(struct s_auth_state *authstate) {
    return (authstate->state >= auth_S4b);
}


// Get remote NodeID. Returns 1 if successful.
int authGetRemoteNodeID(struct s_auth_state *authstate, struct s_nodeid *nodeid) {
	if(authIsAuthed(authstate)) {
		memcpy(nodeid->id, authstate->remote_nodekey.nodeid.id, nodeid_SIZE);
		return 1;
	}
	else {
		return 0;
	}
}


// Get remote PeerID. Returns 1 if successful.
int authGetRemotePeerID(struct s_auth_state *authstate, int *remote_peerid) {
	if(authIsCompleted(authstate)) {
		*remote_peerid = authstate->remote_peerid;
		return 1;
	}
	else {
		return 0;
	}
}


// Get shared session keys. Returns 1 if successful.
int authGetSessionKeys(struct s_auth_state *authstate, struct s_crypto *ctx) {
	if(authIsCompleted(authstate)) {
		return cryptoSetSessionKeys(ctx, &authstate->crypto_ctx[auth_CRYPTOCTX_SESSION_A], &authstate->crypto_ctx[auth_CRYPTOCTX_SESSION_B], authstate->keygen_nonce, (auth_NONCESIZE + auth_NONCESIZE), crypto_AES256, crypto_SHA256);
	}
	else {
		return 0;
	}
}


// Get connection parameters. Returns 1 if successful.
int authGetConnectionParams(struct s_auth_state *authstate, int64_t *seq, int64_t *flags) {
	if(authIsCompleted(authstate)) {
		*seq = utilReadInt64(authstate->remote_seq);
		*flags = utilReadInt64(authstate->remote_flags);
		return 1;
	}
	else {
		return 0;
	}
}


// Get next auth message.
int authGetNextMsg(struct s_auth_state *authstate, struct s_msg *out_msg) {
	if(authstate->nextmsg_size <= 0) {
        return 0;
    }
    
    out_msg->msg = authstate->nextmsg;
    out_msg->len = authstate->nextmsg_size;
    
    if(authstate->state == AUTH_STATE_FINISHED) {
        authstate->nextmsg_size = 0;
        debug("we are in finished state, fire and forget about message");
    }
    
    debugf("Got next MSG, current state %d, msg size: %d", authstate->state, authstate->nextmsg_size);
    return 1;
}


// Set local PeerID and sequence number (required to complete auth protocol)
void authSetLocalData(struct s_auth_state *authstate, const int peerid, const int64_t seq, const int64_t flags) {
	authstate->local_peerid = peerid;
	cryptoRand(authstate->local_keygen_nonce, auth_NONCESIZE);
	cryptoRand(authstate->s4msg_nonce, auth_NONCESIZE);
	utilWriteInt64(authstate->local_seq, seq);
	utilWriteInt64(authstate->local_flags, flags);
	authstate->local_cneg_set = 1;
	authGenMsg(authstate);
}


// Create auth state object.
int authCreate(struct s_auth_state *authstate, struct s_netid *netid, struct s_nodekey *local_nodekey, struct s_dh_state *dhstate, const int authid) {
    debugf("Initializing auth object, ID: %d", authid);
    utilWriteInt32(authstate->local_authid, authid);
    if(dhstate == NULL) {
        debug("wrong DH state");
        return 0;
    }
    
    if(local_nodekey == NULL) {
        debug("wrong local Node key");
        return 0;
    }
    
    if(netid == NULL) {
        debug("wrong network ID");
        return 0;
    }
    
    if(!rsaIsValid(&local_nodekey->key)) {
        debug("local RSA key is invalid");
        return 0;
    }
    
	if(!rsaIsPrivate(&local_nodekey->key)) return 0;
	
	authstate->dhstate = dhstate;
	authstate->local_nodekey = local_nodekey;
	authstate->netid = netid;
	
    if(nodekeyCreate(&authstate->remote_nodekey)) {
		if(cryptoCreate(authstate->crypto_ctx, auth_CRYPTOCTX_COUNT)) {
			authReset(authstate);
			return 1;
		}
		nodekeyDestroy(&authstate->remote_nodekey);
	}
	return 0;
}


// Destroy auth state object.
void authDestroy(struct s_auth_state *authstate) {
	authReset(authstate);
	cryptoDestroy(authstate->crypto_ctx, auth_CRYPTOCTX_COUNT);
	nodekeyDestroy(&authstate->remote_nodekey);
}


#endif // F_AUTH_C
