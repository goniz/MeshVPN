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

#ifndef H_MAP
#define H_MAP

#include <stdlib.h>
#include <string.h>
#include "idsp.h"

// The map struct.
struct s_map {
        struct s_idsp idsp;
        unsigned char *key;
        unsigned char *value;
        int *left;
        int *right;
        int maxnode;
        int rootid;
        int key_size;
        int value_size;
        int replace_old;
};

// Enables replacing of old entries if map is full.
void mapEnableReplaceOld(struct s_map *map);

// Disables replacing of old entries if map is full.
void mapDisableReplaceOld(struct s_map *map);

// Return the size of a stored key.
int mapGetKeySize(struct s_map *map);

// Return the size of a stored value.
int mapGetValueSize(struct s_map *map);

// Return 1 if ID is valid.
int mapIsValidID(struct s_map *map, const int id);

// Return a pointer to key[id].
void *mapGetKeyByID(struct s_map *map, const int id);

// Compare stored prefix to an external prefix.
int mapComparePrefixExt(struct s_map *map, const int id, const void *prefix, const int prefixlen);

// Compare stored key to an external key.
int mapCompareKeysExt(struct s_map *map, const int id, const void *key);

// Move the node with the specified key prefix to the root. Return 1 if the key has been found, or 0 if not.
int mapSplayPrefix(struct s_map *map, const void *prefix, const int prefixlen);

// Move the node with the specified key to the root. Return 1 if the key has been found, or 0 if not.
int mapSplayKey(struct s_map *map, const void *key);

// Initialize the map. This removes all key/value pairs.
void mapInit(struct s_map *map);

// Return the map size.
int mapGetMapSize(struct s_map *map);

// Return the current amount of stored keys.
int mapGetKeyCount(struct s_map *map);

// Return the next ID of a valid key.
int mapGetNextKeyID(struct s_map *map);

// Return the next ID of a valid key, starting from specified ID.
int mapGetNextKeyIDN(struct s_map *map, const int start);

// Get the ID of a key that starts with the specified prefix. Returns the ID or -1 if no key is found.
int mapGetPrefixID(struct s_map *map, const void *prefix, const int prefixlen);

// Get the ID of specified key. Returns the ID or -1 if the key is not found.
int mapGetKeyID(struct s_map *map, const void *key);

// Get the ID of an "old" key (located near the bottom of the tree).
int mapGetOldKeyID(struct s_map *map);

// Return a pointer to value[id].
void *mapGetValueByID(struct s_map *map, const int id);

// Set new value[id].
void mapSetValueByID(struct s_map *map, const int id, const void *value);

// Remove the specified key/value pair. Returns removed key ID on success or -1 if the operation fails.
int mapRemoveReturnID(struct s_map *map, const void *key);

// Remove the specified key/value pair. Returns 1 on success or 0 if the operation fails.
int mapRemove(struct s_map *map, const void *key);

// Add the specified key/value pair. Returns added key ID on success or -1 if the operation fails.
int mapAddReturnID(struct s_map *map, const void *key, const void *value);

// Add the specified key/value pair. Returns 1 on success or 0 if the operation fails.
int mapAdd(struct s_map *map, const void *key, const void *value);

// Sets the specified key/value pair. The key will be added if it doesn't exist yet. Returns key ID on success or -1 if the operation fails.
int mapSetReturnID(struct s_map *map, const void *key, const void *value);

// Sets the specified key/value pair. The key will be created if it doesn't exist yet. Returns 1 on success or 0 if the operation fails.
int mapSet(struct s_map *map, const void *key, const void *value);

// Return a pointer to the value of a key that matches the specified prefix.
void *mapGetN(struct s_map *map, const void *prefix, const int prefixlen);

// Return a pointer to the value of the specified key.
void *mapGet(struct s_map *map, const void *key);

// Calculate required memory size for map.
int mapMemSize(const int map_size, const int key_size, const int value_size);

// Set up map data structure on preallocated memory.
int mapMemInit(struct s_map *map, const int mem_size, const int map_size, const int key_size, const int value_size);

// Allocate memory for the map.
int mapCreate(struct s_map *map, const int map_size, const int key_size, const int value_size);

// Free the memory used by the map.
int mapDestroy(struct s_map *map);


#define mapStrNPrepKey(map, str, len) \
        int key_size = map->key_size; \
        char key[key_size]; \
        int x; \
        if((key_size - 1) < len) { \
                x = (key_size - 1); \
        } \
        else { \
                x = len; \
        } \
        memset(key, 0, key_size); \
        memcpy(key, str, x);


#define mapStrAdd(map, str, value) mapStrNAdd(map, str, strlen(str), value)
int mapStrNAdd(struct s_map *map, const char *str, const int len, const void *value);

#define mapStrGet(map, str) mapStrNGet(map, str, strlen(str))
void *mapStrNGet(struct s_map *map, const char *str, const int len);

#define mapStrGetN(map, str) mapStrNGetN(map, str, strlen(str))
void *mapStrNGetN(struct s_map *map, const char *str, const int len);

#define mapStrRemove(map, str) mapStrNRemove(map, str, strlen(str))
int mapStrNRemove(struct s_map *map, const char *str, const int len);

#define mapStrSet(map, str, value) mapStrNSet(map, str, strlen(str), value)
int mapStrNSet(struct s_map *map, const char *str, const int len, const void *value);

#endif // F_MAP_C
