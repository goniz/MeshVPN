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