#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#include <stdbool.h>

typedef int pid_t;

void syscall_init (void);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);

#endif /* userprog/syscall.h */
