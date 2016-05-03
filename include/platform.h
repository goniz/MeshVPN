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

#endif