#ifndef H_PLATFORM
#define H_PLATFORM


// Enables seccomp filtering. Returns 1 on success.
int seccompEnable();

// No seccomp support.
int seccompEnable();

// drop privileges
void dropPrivileges(char *username, char *groupname, char *chrootdir);

// drop privileges (automatic version, without specified user and group name)
void dropPrivilegesAuto();

// Execute command.
int ifconfigExec(const char *cmd);

// Check & copy input.
int ifconfigCheckCopyInput(char *out, const int out_len, const char *in, const int in_len);

// Split input.
int ifconfigSplit(char *a_out, const int a_len, char *b_out, const int b_len, const char *in, const int in_len, const char split_char);

// Calculate netmask from prefixlen.
void ifconfig4Netmask(char *out, const int prefixlen);

// Configure IPv4 address on specified interface.
int ifconfig4(const char *ifname, const int ifname_len, const char *addr, const int addr_len);

// Configure IPv6 address on specified interface.
int ifconfig6(const char *ifname, const int ifname_len, const char *addr, const int addr_len);


#endif