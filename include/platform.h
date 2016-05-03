#ifndef H_PLATFORM
#define H_PLATFORM


// Enables seccomp filtering. Returns 1 on success.
int seccompEnable();

// No seccomp support.
int seccompEnable();

#endif