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

#ifndef H_P2P
#define H_P2P


#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nodeid.h"
#include "dh.h"
#include "idsp.h"
#include "map.h"


struct s_dfrag {
        unsigned char *fragbuf;
        int *used;
        int *peerct;
        int *peerid;
        int64_t *seq;
        int *length;
        int *msglength;
        int fragbuf_size;
        int fragbuf_count;
        int pos;
};


// Size of sequence number in bytes.
#define seq_SIZE 8


// Window size.
#define seq_WINDOWSIZE 16384


// The sequence number state structure.
struct s_seq_state {
        int64_t start;
        uint64_t mask;
};

// The NodeDB addrdata structure.
struct s_nodedb_addrdata {
        int lastseen;
        int lastseen_t;
        int lastconnect;
        int lastconnect_t;
        int lastconntry;
        int lastconntry_t;
};


// The NodeDB structure.
struct s_nodedb {
        struct s_map *addrdb;
        int num_peeraddrs;
};



// Minimum message size supported (without fragmentation).
#define peermgt_MSGSIZE_MIN 1024


// Maximum message size supported (with or without fragmentation).
#define peermgt_MSGSIZE_MAX 8192


// Ping buffer size.
#define peermgt_PINGBUF_SIZE 64


// Number of fragment buffers.
#define peermgt_FRAGBUF_COUNT 64


// Maximum packet decode recursion depth.
#define peermgt_DECODE_RECURSION_MAX_DEPTH 2


// NodeDB settings.
#define peermgt_NODEDB_NUM_PEERADDRS 8
#define peermgt_RELAYDB_NUM_PEERADDRS 4


// States.
#define peermgt_STATE_INVALID 0
#define peermgt_STATE_AUTHED 1
#define peermgt_STATE_COMPLETE 2


// Timeouts.
#define peermgt_RECV_TIMEOUT 100
#define peermgt_KEEPALIVE_INTERVAL 10
#define peermgt_PEERINFO_INTERVAL 60
#define peermgt_NEWCONNECT_MAX_LASTSEEN 604800
#define peermgt_NEWCONNECT_MIN_LASTCONNTRY 60
#define peermgt_NEWCONNECT_RELAY_MAX_LASTSEEN 300


// Flags.
#define peermgt_FLAG_USERDATA 0x0001
#define peermgt_FLAG_RELAY 0x0002
#define peermgt_FLAG_F03 0x0004
#define peermgt_FLAG_F04 0x0008
#define peermgt_FLAG_F05 0x0010
#define peermgt_FLAG_F06 0x0020
#define peermgt_FLAG_F07 0x0040
#define peermgt_FLAG_F08 0x0080
#define peermgt_FLAG_F09 0x0100
#define peermgt_FLAG_F10 0x0200
#define peermgt_FLAG_F11 0x0400
#define peermgt_FLAG_F12 0x0800
#define peermgt_FLAG_F13 0x1000
#define peermgt_FLAG_F14 0x2000
#define peermgt_FLAG_F15 0x4000
#define peermgt_FLAG_F16 0x8000


// Constraints.
#if auth_MAXMSGSIZE > peermgt_MSGSIZE_MIN
#error auth_MAXMSGSIZE too big
#endif
#if peermgt_PINGBUF_SIZE > peermgt_MSGSIZE_MIN
#error peermgt_PINGBUF_SIZE too big
#endif

// NetID size in bytes.
#define netid_SIZE 32
#define NETID_SIZE 32

// The NetID structure.
struct s_netid {
        unsigned char id[netid_SIZE];
};

// Internal address types.
#define peeraddr_INTERNAL_INDIRECT 1


// PeerAddr size in bytes.
#define peeraddr_SIZE 24


// Constraints.
#if peeraddr_SIZE != 24
#error invalid peeraddr_SIZE
#endif


// The PeerAddr structure.
struct s_peeraddr {
        unsigned char addr[peeraddr_SIZE];
};

// The peer manager data structure.
struct s_peermgt_data {
        int conntime;
        int lastrecv;
        int lastsend;
        int lastpeerinfo;
        int lastpeerinfosendpeerid;
        struct s_peeraddr remoteaddr;
        int remoteflags;
        int remoteid;
        int64_t remoteseq;
        struct s_seq_state seq;
        int state;
};


// Timeouts.
#define authmgt_RECV_TIMEOUT 30
#define authmgt_RESEND_TIMEOUT 3

#define AUTHMGT_RECV_TIMEOUT 30
#define AUTHMGT_RESEND_TIMEOUT 3

// The auth manager structure.
struct s_authmgt {
        struct s_idsp idsp;
        struct s_auth_state *authstate;
        struct s_peeraddr *peeraddr;
        int *lastrecv;
        int *lastsend;
        int fastauth;
        int current_authed_id;
        int current_completed_id;
};


// The peer manager structure.
struct s_peermgt {
        struct s_netid netid;
        struct s_map map;
        struct s_nodedb nodedb;
        struct s_nodedb relaydb;
        struct s_authmgt authmgt;
        struct s_dfrag dfrag;
        struct s_nodekey *nodekey;
        struct s_peermgt_data *data;
        struct s_crypto *ctx;
        int localflags;
        unsigned char msgbuf[peermgt_MSGSIZE_MAX];
        unsigned char relaymsgbuf[peermgt_MSGSIZE_MAX];
        unsigned char rrmsgbuf[peermgt_MSGSIZE_MAX];
        int msgsize;
        int msgpeerid;
        struct s_msg outmsg;
        int outmsgpeerid;
        int outmsgbroadcast;
        int outmsgbroadcastcount;
        struct s_msg rrmsg;
        int rrmsgpeerid;
        int rrmsgtype;
        int rrmsgusetargetaddr;
        struct s_peeraddr rrmsgtargetaddr;
        int loopback;
        int fragmentation;
        int fragoutpeerid;
        int fragoutcount;
        int fragoutsize;
        int fragoutpos;
        int lastconntry;
        int tinit;
};


struct s_p2psec {
        struct s_peermgt mgt;
        struct s_nodekey nk;
        struct s_dh_state dh;
        int started;
        int key_loaded;
        int dh_loaded;
        int peer_count;
        int auth_count;
        int loopback_enable;
        int fastauth_enable;
        int fragmentation_enable;
        int flags;
        char password[1024];
        int password_len;
        char netname[1024];
        int netname_len;
};

int netidSet(struct s_netid *netid, const char *netname, const int netname_len);

// Returns true if PeerAddr is internal.
int peeraddrIsInternal(const struct s_peeraddr *peeraddr);

// Returns type of internal PeerAddr or -1 if it is not internal.
int peeraddrGetInternalType(const struct s_peeraddr *peeraddr);

// Get indirect PeerAddr attributes. Returns 1 on success or 0 if the PeerAddr is not indirect.
int peeraddrGetIndirect(const struct s_peeraddr *peeraddr, int *relayid, int *relayct, int *peerid);

// Construct indirect PeerAddr.
void peeraddrSetIndirect(struct s_peeraddr *peeraddr, const int relayid, const int relayct, const int peerid);

#define CREATE_HUMAN_IP(variable) char humanIp[60]; peeraddrToHuman(humanIp, variable);

/**
 * Copy human readable peer address to buffer
 */
void peeraddrToHuman(char * buffer, const struct s_peeraddr * peeraddr);

// Initialize NodeDB.
void nodedbInit(struct s_nodedb *db);

// Update NodeDB entry.
void nodedbUpdate(struct s_nodedb *db, struct s_nodeid *nodeid, struct s_peeraddr *addr, const int update_lastseen, const int update_lastconnect, const int update_lastconntry);

// Returns a NodeDB ID that matches the specified criteria, with explicit nid/tnow.
int nodedbGetDBIDByID(struct s_nodedb *db, const int nid, const int tnow, const int max_lastseen, const int max_lastconnect, const int min_lastconntry);

// Returns a NodeDB ID that matches the specified criteria.
int nodedbGetDBID(struct s_nodedb *db, struct s_nodeid *nodeid, const int max_lastseen, const int max_lastconnect, const int min_lastconntry);

// Returns node ID of specified NodeDB ID.
struct s_nodeid *nodedbGetNodeID(struct s_nodedb *db, const int db_id);

// Returns node address of specified NodeDB ID.
struct s_peeraddr *nodedbGetNodeAddress(struct s_nodedb *db, const int db_id);

// Create NodeDB.
int nodedbCreate(struct s_nodedb *db, const int size, const int num_peeraddrs);

// Destroy NodeDB.
void nodedbDestroy(struct s_nodedb *db);

// Generate NodeDB status report.
void nodedbStatus(struct s_nodedb *db, char *report, const int report_len);

int nodedbNodeAddrExists(struct s_nodedb* db, struct s_peeraddr* addr);

// size of packet header fields in bytes
#define packet_PEERID_SIZE 4 // peer ID
#define packet_HMAC_SIZE 32 // hmac that includes sequence number, node ID, pl* fields (pllen, pltype, plopt) and payload
#define packet_IV_SIZE 16 // IV
#define packet_SEQ_SIZE seq_SIZE // packet sequence number
#define packet_PLLEN_SIZE 2 // payload length
#define packet_PLTYPE_SIZE 1 // payload type
#define packet_PLOPT_SIZE 1 // payload options
#define packet_CRHDR_SIZE (packet_SEQ_SIZE + packet_PLLEN_SIZE + packet_PLTYPE_SIZE + packet_PLOPT_SIZE)


// position of packet header fields
#define packet_CRHDR_SEQ_START (0)
#define packet_CRHDR_PLLEN_START (packet_CRHDR_SEQ_START + packet_SEQ_SIZE)
#define packet_CRHDR_PLTYPE_START (packet_CRHDR_PLLEN_START + packet_PLLEN_SIZE)
#define packet_CRHDR_PLOPT_START (packet_CRHDR_PLTYPE_START + packet_PLTYPE_SIZE)


// @deprecated
#define packet_PLTYPE_USERDATA 0
#define packet_PLTYPE_USERDATA_FRAGMENT 1
#define packet_PLTYPE_AUTH 2
#define packet_PLTYPE_PEERINFO 3
#define packet_PLTYPE_PING 4
#define packet_PLTYPE_PONG 5
#define packet_PLTYPE_RELAY_IN 6
#define packet_PLTYPE_RELAY_OUT 7


// payload types
#define PACKET_PLTYPE_USERDATA 0
#define PACKET_PLTYPE_USERDATA_FRAGMENT 1
#define PACKET_PLTYPE_AUTH 2
#define PACKET_PLTYPE_PEERINFO 3
#define PACKET_PLTYPE_PING 4
#define PACKET_PLTYPE_PONG 5
#define PACKET_PLTYPE_RELAY_IN 6
#define PACKET_PLTYPE_RELAY_OUT 7

// constraints
#if packet_PEERID_SIZE != 4
#error invalid packet_PEERID_SIZE
#endif
#if packet_SEQ_SIZE != 8
#error invalid packet_SEQ_SIZE
#endif
#if packet_PLLEN_SIZE != 2
#error invalid packet_PLLEN_SIZE
#endif
#if packet_CRHDR_SIZE < (3 * packet_PEERID_SIZE)
#error invalid packet_CRHDR_SIZE
#endif


// packet data structure
struct s_packet_data {
        int peerid;
        int64_t seq;
        int pl_length;
        int pl_type;
        int pl_options;
        unsigned char *pl_buf;
        int pl_buf_size;
};


// return the peer ID
int packetGetPeerID(const unsigned char *pbuf);

int packetVerifyPacket(const unsigned char* pbuf, const int pbuf_size, struct s_crypto* ctx);

// encode packet
int packetEncode(unsigned char *pbuf, const int pbuf_size, const struct s_packet_data *data, struct s_crypto *ctx);

// decode packet
int packetDecode(struct s_packet_data *data, const unsigned char *pbuf, const int pbuf_size, struct s_crypto *ctx, struct s_seq_state *seqstate);

// Reset fragment buffer structure.
void dfragReset(struct s_dfrag *dfrag);

// Returns 1 if the specified message has the specified ID.
int dfragIsID(struct s_dfrag *dfrag, const int peerct, const int peerid, const int64_t seq, const int id);

// Return message ID.
int dfragGetID(struct s_dfrag *dfrag, const int peerct, const int peerid, const int64_t seq);

// Allocate message ID.
int dfragAllocateID(struct s_dfrag *dfrag, const int fragment_count);

// Clear message.
void dfragClear(struct s_dfrag *dfrag, const int id);

// Return length of completed message.
int dfragLength(struct s_dfrag *dfrag, const int id);

// Return pointer to message (dfragLength should be called first to get the message length).
unsigned char *dfragGet(struct s_dfrag *dfrag, const int id);

// Calculate message length and save result.
int dfragCalcLength(struct s_dfrag *dfrag, const int id);

// Combine fragments to a message. Returns an ID if the message is completed or -1 in every other case.
int dfragAssemble(struct s_dfrag *dfrag, const int peerct, const int peerid, const int64_t seq, const unsigned char *fragment, const int fragment_len, const int fragment_pos, const int fragment_count);

// Create fragment buffer structure.
int dfragCreate(struct s_dfrag *dfrag, const int size, const int count);

// Destroy fragment buffer structure.
void dfragDestroy(struct s_dfrag *dfrag);

// Get sequence number state.
int64_t seqGet(struct s_seq_state *state);

// Initialize sequence number state.
void seqInit(struct s_seq_state *state, const int64_t seq);

// Verify sequence number. Returns 1 if accepted, else 0.
int seqVerify(struct s_seq_state *state, const int64_t seq);

// Returns the amount of received sequence numbers out of the last 64.
int seqRQ(struct s_seq_state *state);

int p2psecStart(struct s_p2psec *p2psec);

void p2psecStop(struct s_p2psec *p2psec);

int p2psecGetAddrSize();

int p2psecGetNodeIDSize();
/**
 * Initialize node private keys. If there is no file by keypath we will generate keys and export them to file
 * otherwise we will try to load it.
 * keypath - should be writable path, might be in chrooted dir, because private keys readed before priveleges revoke
 */
int p2psecInitPrivateKey(struct s_p2psec *p2psec, const int bits, const char *keypath);

int p2psecImportPrivkey(struct s_p2psec * p2psec, const char * keypath);

/**
 * Export key to
 */
int p2psecExportPrivkey(struct s_p2psec * p2psec, const char * keypath);

/**
 * Generate or load private key from file
 */
int p2psecGeneratePrivkey(struct s_p2psec *p2psec, const int bits);

int p2psecLoadDH(struct s_p2psec *p2psec);

void p2psecSetMaxConnectedPeers(struct s_p2psec *p2psec, const int peer_count);

void p2psecSetAuthSlotCount(struct s_p2psec *p2psec, const int auth_slot_count);

void p2psecSetNetname(struct s_p2psec *p2psec, const char *netname, const int netname_len);

void p2psecSetPassword(struct s_p2psec *p2psec, const char *password, const int password_len);

void p2psecEnableLoopback(struct s_p2psec *p2psec);

void p2psecDisableLoopback(struct s_p2psec *p2psec);

void p2psecEnableFastauth(struct s_p2psec *p2psec);

void p2psecDisableFastauth(struct s_p2psec *p2psec);

void p2psecEnableFragmentation(struct s_p2psec *p2psec);

void p2psecDisableFragmentation(struct s_p2psec *p2psec);

void p2psecSetFlag(struct s_p2psec *p2psec, const int flag, const int enable);

void p2psecEnableUserdata(struct s_p2psec *p2psec);

void p2psecDisableUserdata(struct s_p2psec *p2psec);

void p2psecEnableRelay(struct s_p2psec *p2psec);

void p2psecDisableRelay(struct s_p2psec *p2psec);

int p2psecLoadDefaults(struct s_p2psec *p2psec);

struct s_p2psec *p2psecCreate();

void p2psecDestroy(struct s_p2psec *p2psec);

void p2psecStatus(struct s_p2psec *p2psec, char *status_report, const int status_report_len);

void p2psecNodeDBStatus(struct s_p2psec *p2psec, char *status_report, const int status_report_len);

int p2psecConnect(struct s_p2psec *p2psec, const unsigned char *destination_addr);

int p2psecInputPacket(struct s_p2psec *p2psec, const unsigned char *packet_input, const int packet_input_len, const unsigned char *packet_source_addr);

unsigned char *p2psecRecvMSG(struct s_p2psec *p2psec, unsigned char *source_nodeid, int *message_len);

unsigned char *p2psecRecvMSGFromPeerID(struct s_p2psec *p2psec, int *source_peerid, int *source_peerct, int *message_len);

int p2psecSendMSG(struct s_p2psec *p2psec, const unsigned char *destination_nodeid, unsigned char *message, int message_len);

int p2psecSendBroadcastMSG(struct s_p2psec *p2psec, unsigned char *message, int message_len);

int p2psecSendMSGToPeerID(struct s_p2psec *p2psec, const int destination_peerid, const int destination_peerct, unsigned char *message, int message_len);

int p2psecOutputPacket(struct s_p2psec *p2psec, unsigned char *packet_output, const int packet_output_len, unsigned char *packet_destination_addr);

int p2psecPeerCount(struct s_p2psec *p2psec);

int p2psecUptime(struct s_p2psec *p2psec);

// Return number of connected peers.
int peermgtPeerCount(struct s_peermgt *mgt);

// Check if PeerID is valid.
int peermgtIsValidID(struct s_peermgt *mgt, const int peerid);

// Check if PeerID is active (ready to send/recv data).
int peermgtIsActiveID(struct s_peermgt *mgt, const int peerid);

// Check if PeerID is active and matches the specified connection time.
int peermgtIsActiveIDCT(struct s_peermgt *mgt, const int peerid, const int conntime);

// Check if PeerID is active and remote (> 0).
int peermgtIsActiveRemoteID(struct s_peermgt *mgt, const int peerid);

// Check if PeerID is active, remote (> 0) and matches the specified connection time.
int peermgtIsActiveRemoteIDCT(struct s_peermgt *mgt, const int peerid, const int conntime);

// Check if indirect PeerAddr is valid.
int peermgtIsValidIndirectPeerAddr(struct s_peermgt *mgt, const struct s_peeraddr *addr);

// Return the next valid PeerID.
int peermgtGetNextID(struct s_peermgt *mgt);

// Return the next valid PeerID, starting from specified ID.
int peermgtGetNextIDN(struct s_peermgt *mgt, const int start);

// Get PeerID of NodeID. Returns -1 if it is not found.
int peermgtGetID(struct s_peermgt *mgt, const struct s_nodeid *nodeid);

// Returns PeerID if active PeerID + PeerCT or NodeID is specified. Returns -1 if it is not found or both IDs are specified and don't match the same node.
int peermgtGetActiveID(struct s_peermgt *mgt, const struct s_nodeid *nodeid, const int peerid, const int peerct);

// Get NodeID of PeerID. Returns 1 on success.
int peermgtGetNodeID(struct s_peermgt *mgt, struct s_nodeid *nodeid, const int peerid);

// Reset the data for an ID.
void peermgtResetID(struct s_peermgt *mgt, const int peerid);

// Register new peer.
int peermgtNew(struct s_peermgt *mgt, const struct s_nodeid *nodeid, const struct s_peeraddr *addr);

// Unregister a peer using its NodeID.
void peermgtDelete(struct s_peermgt *mgt, const struct s_nodeid *nodeid);

// Unregister a peer using its ID.
void peermgtDeleteID(struct s_peermgt *mgt, const int peerid);

// Connect to a new peer.
int peermgtConnect(struct s_peermgt *mgt, const struct s_peeraddr *remote_addr);

// Enable/Disable loopback messages.
void peermgtSetLoopback(struct s_peermgt *mgt, const int enable);

// Enable/disable fastauth (ignore send delay after auth status change).
void peermgtSetFastauth(struct s_peermgt *mgt, const int enable);

// Enable/disable packet fragmentation.
void peermgtSetFragmentation(struct s_peermgt *mgt, const int enable);

// Set flags.
void peermgtSetFlags(struct s_peermgt *mgt, const int flags);

// Get single flag.
int peermgtGetFlag(struct s_peermgt *mgt, const int flag);

// Get single remote flag.
int peermgtGetRemoteFlag(struct s_peermgt *mgt, const int peerid, const int flag);

// Generate peerinfo packet.
void peermgtGenPacketPeerinfo(struct s_packet_data *data, struct s_peermgt *mgt, const int peerid);

// Send ping to PeerAddr. Return 1 if successful.
int peermgtSendPingToAddr(struct s_peermgt *mgt, const struct s_nodeid *tonodeid, const int topeerid, const int topeerct, const struct s_peeraddr *peeraddr);

// Generate next peer manager packet. Returns length if successful.
int peermgtGetNextPacketGen(struct s_peermgt *mgt, unsigned char *pbuf, const int pbuf_size, const int tnow, struct s_peeraddr *target);

// Get next peer manager packet. Also encapsulates packets for relaying if necessary. Returns length if successful.
int peermgtGetNextPacket(struct s_peermgt *mgt, unsigned char *pbuf, const int pbuf_size, struct s_peeraddr *target);

// Decode auth packet
int peermgtDecodePacketAuth(struct s_peermgt *mgt, const struct s_packet_data *data, const struct s_peeraddr *source_addr);

// Decode peerinfo packet
int peermgtDecodePacketPeerinfo(struct s_peermgt *mgt, const struct s_packet_data *data);

// Decode ping packet
int peermgtDecodePacketPing(struct s_peermgt *mgt, const struct s_packet_data *data);

// Decode pong packet
int peermgtDecodePacketPong(struct s_peermgt *mgt, const struct s_packet_data *data);

// Decode relay-in packet
int peermgtDecodePacketRelayIn(struct s_peermgt *mgt, const struct s_packet_data *data);

// Decode fragmented packet
int peermgtDecodeUserdataFragment(struct s_peermgt *mgt, struct s_packet_data *data);

// Decode input packet recursively. Decapsulates relayed packets if necessary.
int peermgtDecodePacketRecursive(struct s_peermgt *mgt, const unsigned char *packet, const int packet_len, const struct s_peeraddr *source_addr, const int tnow, const int depth);


// Decode input packet. Returns 1 on success.
int peermgtDecodePacket(struct s_peermgt *mgt, const unsigned char *packet, const int packet_len, const struct s_peeraddr *source_addr);

// Return received user data. Return 1 if successful.
int peermgtRecvUserdata(struct s_peermgt *mgt, struct s_msg *recvmsg, struct s_nodeid *fromnodeid, int *frompeerid, int *frompeerct);

// Send user data. Return 1 if successful.
int peermgtSendUserdata(struct s_peermgt *mgt, const struct s_msg *sendmsg, const struct s_nodeid *tonodeid, const int topeerid, const int topeerct);

// Send user data to all connected peers. Return 1 if successful.
int peermgtSendBroadcastUserdata(struct s_peermgt *mgt, const struct s_msg *sendmsg);

// Set NetID from network name.
int peermgtSetNetID(struct s_peermgt *mgt, const char *netname, const int netname_len);

// Set shared group password.
int peermgtSetPassword(struct s_peermgt *mgt, const char *password, const int password_len);

// Initialize peer manager object.
int peermgtInit(struct s_peermgt *mgt);
// Return peer manager uptime in seconds.
int peermgtUptime(struct s_peermgt *mgt);

// Generate peer manager status report.
void peermgtStatus(struct s_peermgt *mgt, char *report, const int report_len);

// Create peer manager object.
// @NOTE: i'm not going to clean resources during failed init because whole app will break down if something goes wrong
int peermgtCreate(struct s_peermgt *mgt, const int peer_slots, const int auth_slots, struct s_nodekey *local_nodekey, struct s_dh_state *dhstate);

// Destroy peer manager object.
void peermgtDestroy(struct s_peermgt *mgt);

// Return number of auth slots.
int authmgtSlotCount(struct s_authmgt *mgt);

// Return number of used auth slots.
int authmgtUsedSlotCount(struct s_authmgt *mgt);

// Create new auth session. Returns ID of session if successful.
int authmgtNew(struct s_authmgt *mgt, const struct s_peeraddr *peeraddr);

// Delete auth session.
void authmgtDelete(struct s_authmgt *mgt, const int authstateid);

// Start new auth session. Returns 1 on success.
int authmgtStart(struct s_authmgt *mgt, const struct s_peeraddr *peeraddr);

// Check if auth manager has an authed peer.
int authmgtHasAuthedPeer(struct s_authmgt *mgt);

// Get the NodeID of the current authed peer.
int authmgtGetAuthedPeerNodeID(struct s_authmgt *mgt, struct s_nodeid *nodeid);

// Accept the current authed peer.
void authmgtAcceptAuthedPeer(struct s_authmgt *mgt, const int local_peerid, const int64_t seq, const int64_t flags);

// Reject the current authed peer.
void authmgtRejectAuthedPeer(struct s_authmgt *mgt);

// Check if auth manager has a completed peer.
int authmgtHasCompletedPeer(struct s_authmgt *mgt);

// Get the local PeerID of the current completed peer.
int authmgtGetCompletedPeerLocalID(struct s_authmgt *mgt);

// Get the NodeID of the current completed peer.
int authmgtGetCompletedPeerNodeID(struct s_authmgt *mgt, struct s_nodeid *nodeid);

// Get the remote PeerID and PeerAddr of the current completed peer.
int authmgtGetCompletedPeerAddress(struct s_authmgt *mgt, int *remote_peerid, struct s_peeraddr *remote_peeraddr);

// Get the shared session keys of the current completed peer.
int authmgtGetCompletedPeerSessionKeys(struct s_authmgt *mgt, struct s_crypto *ctx);

// Get the connection parameters of the current completed peer.
int authmgtGetCompletedPeerConnectionParams(struct s_authmgt *mgt, int64_t *remoteseq, int64_t *remoteflags);

// Finish the current completed peer.
void authmgtFinishCompletedPeer(struct s_authmgt *mgt);

// Get next auth manager message.
int authmgtGetNextMsg(struct s_authmgt *mgt, struct s_msg *out_msg, struct s_peeraddr *target);

// Find auth session with specified PeerAddr.
int authmgtFindAddr(struct s_authmgt *mgt, const struct s_peeraddr *addr);

// Find unused auth session.
int authmgtFindUnused(struct s_authmgt *mgt);

// Decode auth message. Returns 1 if message is accepted.
int authmgtDecodeMsg(struct s_authmgt *mgt, const unsigned char *msg, const int msg_len, const struct s_peeraddr *peeraddr);

// Enable/disable fastauth (ignore send timeout after auth status change)
void authmgtSetFastauth(struct s_authmgt *mgt, const int enable);

// Reset auth manager object.
void authmgtReset(struct s_authmgt *mgt);

// Create auth manager object.
int authmgtCreate(struct s_authmgt *mgt, struct s_netid *netid, const int auth_slots, struct s_nodekey *local_nodekey, struct s_dh_state *dhstate);


// Destroy auth manager object.
void authmgtDestroy(struct s_authmgt *mgt);

#endif // F_P2PSEC_H
