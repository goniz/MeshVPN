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

#ifndef H_IDSP
#define H_IDSP



#define idsp_ALIGN_BOUNDARY 16

// The MSG structure.
struct s_msg {
        unsigned char *msg;
        int len;
};

struct s_idsp {
        int *idfwd;
        int *idlist;
        int count;
        int used;
        int iter;
};



void idspReset(struct s_idsp *idsp);

int idspMemSize(const int size);

int idspMemInit(struct s_idsp *idsp, const int mem_size, const int size);

int idspCreate(struct s_idsp *idsp, const int size);

int idspNextN(struct s_idsp *idsp, const int start);

int idspNext(struct s_idsp *idsp);

int idspNew(struct s_idsp *idsp);

int idspGetPos(struct s_idsp *idsp, const int id);

void idspDelete(struct s_idsp *idsp, const int id);

int idspIsValid(struct s_idsp *idsp, const int id);

int idspUsedCount(struct s_idsp *idsp);

int idspSize(struct s_idsp *idsp);

void idspDestroy(struct s_idsp *idsp);

#endif
