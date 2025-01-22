#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void init_fd_table (struct thread *t);
void clean_fd_table (struct thread *t);
//void fd_pool_push (struct thread *t, int fd);
//int fd_pool_pop (struct thread *t);
//bool fd_pool_full (struct thread *t);
//bool fd_pool_empty (struct thread *t);
int get_new_fd (struct thread *t);
struct thread *get_child_thread_by_tid (tid_t child_tid);

#endif /* userprog/process.h */
