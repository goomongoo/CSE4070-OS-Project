#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#include <stdbool.h>
#include <list.h>
#include <stddef.h>

typedef int pid_t;

struct mmap_entry
  {
    mapid_t mapid;
    void *vaddr;
    struct file *file;
    size_t file_length;
    struct list_elem elem;
  };

void syscall_init (void);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapid);

void munmap_handler (struct mmap_entry *target);

#endif /* userprog/syscall.h */
