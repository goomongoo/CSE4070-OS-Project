#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static void syscall (struct intr_frame *);
static void check_vaddr (const void *vaddr);

struct lock f_lock;

void
syscall_init (void) 
{
  lock_init (&f_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall, "syscall");
}

/* Project_1 - begin */
void
halt (void)
{
  shutdown_power_off ();
}

void
exit (int status)
{
  struct thread *t = thread_current ();

  t->exit_status = status;
  printf("%s: exit(%d)\n", thread_name (), status);
  //deinit_fd (t);
  thread_exit();
}

pid_t
exec (const char *cmd_line)
{
  return process_execute (cmd_line);
}

int
wait (pid_t pid)
{
  return process_wait (pid);
}

int
fibonacci (int n)
{
  int *dp;
  int i;
  int ret;

  if (n <= 0)
    return 0;
  
  if (n == 1)
    return 1;

  dp = malloc (sizeof (int) * 47);
  if (dp == NULL)
    exit (-1);

  dp[0] = 0;
  dp[1] = 1;
  for (i = 2; i <= n; i++)
    dp[i] = dp[i - 1] + dp[i - 2];
  
  ret = dp[n];
  free(dp);

  return ret;
}

int
max_of_four_int (int a, int b, int c, int d)
{
  return MAX(MAX (a, b), MAX (c, d));
}
/* Project_1 - end */

/* Project_2 - begin */
bool
create (const char *file, unsigned initial_size)
{
  if (file == NULL)
    exit (-1);

  return filesys_create (file, initial_size);
}

bool
remove (const char *file)
{
  bool ret;

  if (file == NULL)
    exit (-1);
  
  lock_acquire (&f_lock);
  ret = filesys_remove (file);
  lock_release (&f_lock);

  return ret;
}

int
open (const char *file)
{
  int fd;
  struct file *f;
  struct thread *t = thread_current ();

  if (file == NULL)
    exit (-1);

  fd = get_new_fd (t);
  if (fd == -1)
    exit (-1);

  lock_acquire (&f_lock);
  f = filesys_open (file);
  lock_release (&f_lock);

  if (f == NULL)
    return -1;
  t->fd_table[fd] = f;

  return fd;
}

int
filesize (int fd)
{
  struct file *file;
  struct thread *t = thread_current ();

  file = (t->fd_table)[fd];
  if (file == NULL)
    return -1;

  return file_length (file);
}

int
read (int fd, void *buffer, unsigned size)
{
  uint8_t *bufptr = (uint8_t *) buffer;
  struct file *file;
  struct thread *t = thread_current ();
  int bytes_read = -1;

  check_vaddr (buffer);

  lock_acquire (&f_lock);
  if (fd == STDIN_FILENO)
    {
      unsigned i;
      bytes_read = 0;
      for (i = 0; i < size; i++)
        {
          bufptr[i] = input_getc ();
          bytes_read++;
        }
    }
  else if (fd >= 2)
    {
      file = (t->fd_table)[fd];
      if (file == NULL)
        {
          lock_release (&f_lock);
          exit (-1);
        }
      bytes_read = file_read (file, bufptr, size);
    }
  lock_release (&f_lock);
  
  return bytes_read;
}

int
write (int fd, const void *buffer, unsigned size)
{
  const char *bufptr = buffer;
  struct file *file;
  struct thread *t = thread_current ();
  int bytes_written = 0;

  if (bufptr == NULL)
    exit (-1);

  lock_acquire (&f_lock);
  if (fd == STDOUT_FILENO)
    {
      putbuf(bufptr, size);
      bytes_written = size;
    }
  else if (fd >= 2)
    {
      file = (t->fd_table)[fd];
      if (file == NULL)
        {
          lock_release (&f_lock);
          exit (-1);
        }
      bytes_written = file_write (file, bufptr, size);
    }
  lock_release (&f_lock);
  
  return bytes_written;
}

void
seek (int fd, unsigned position)
{
  struct file *file;
  struct thread *t = thread_current ();

  file = (t->fd_table)[fd];
  if (file == NULL)
    return;

  return file_seek (file, position);
}

unsigned
tell (int fd)
{
  struct file *file;
  struct thread *t = thread_current ();

  file = (t->fd_table)[fd];
  if (file == NULL)
    return (unsigned) -1;

  return file_tell (file);
}

void
close (int fd)
{
  struct file *file;
  struct thread *t = thread_current ();

  file = (t->fd_table)[fd];
  if (file == NULL)
    return;
  
  file_close (file);
  (t->fd_table)[fd] = NULL;
}
/* Project_2 - end */

static void
check_vaddr (const void *vaddr)
{
  if (is_kernel_vaddr (vaddr))
    exit(-1);
}

static void
syscall (struct intr_frame *f) 
{
  int syscall_nr;

  check_vaddr (f->esp);
  syscall_nr = (int) * (uint32_t *) (f->esp);
  switch (syscall_nr)
    {
      case SYS_HALT:
        halt ();
        break;
      case SYS_EXIT:
        check_vaddr (f->esp + 4);
        exit ((int) * (uint32_t *) (f->esp + 4));
        break;
      case SYS_EXEC:
        check_vaddr (f->esp + 4);
        f->eax = exec ((char *) * (uint32_t *) (f->esp + 4));
        break;
      case SYS_WAIT:
        check_vaddr (f->esp + 4);
        f->eax = wait ((pid_t) * (uint32_t *) (f->esp + 4));
        break;
      case SYS_CREATE:
        check_vaddr (f->esp + 4);
        check_vaddr (f->esp + 8);
        f->eax = create ((const char *) * (uint32_t *) (f->esp + 4), (unsigned) * (uint32_t *) (f->esp + 8));
        break;
      case SYS_REMOVE:
        check_vaddr (f->esp + 4);
        f->eax = remove ((const char *) * (uint32_t *) (f->esp + 4));
        break;
      case SYS_OPEN:
        check_vaddr (f->esp + 4);
        f->eax = open ((const char *) * (uint32_t *) (f->esp + 4));
        break;
      case SYS_FILESIZE:
        check_vaddr (f->esp + 4);
        f->eax = filesize ((int) * (uint32_t *) (f->esp + 4));
        break;
      case SYS_READ:
        check_vaddr (f->esp + 4);
        check_vaddr (f->esp + 8);
        check_vaddr (f->esp + 12);
        f->eax = read ((int) * (uint32_t *) (f->esp + 4), (void *) * (uint32_t *) (f->esp + 8), (unsigned) * (uint32_t *) (f->esp + 12));
        break;
      case SYS_WRITE:
        check_vaddr (f->esp + 4);
        check_vaddr (f->esp + 8);
        check_vaddr (f->esp + 12);
        f->eax = write ((int) * (uint32_t *) (f->esp + 4), (const void *) * (uint32_t *) (f->esp + 8), (unsigned) * (uint32_t *) (f->esp + 12));
        break;
      case SYS_SEEK:
        check_vaddr (f->esp + 4);
        check_vaddr (f->esp + 8);
        seek ((int) * (uint32_t *) (f->esp + 4), (unsigned) * (uint32_t *) (f->esp + 8));
        break;
      case SYS_TELL:
        check_vaddr (f->esp + 4);
        f->eax = tell ((int) * (uint32_t *) (f->esp + 4));
        break;
      case SYS_CLOSE:
        check_vaddr (f->esp + 4);
        close ((int) * (uint32_t *) (f->esp + 4));
        break;
      case SYS_FIBONACCI:
        check_vaddr (f->esp + 4);
        f->eax = fibonacci ((int) * (uint32_t *) (f->esp + 4));
        break;
      case SYS_MAX_OF_FOUR_INT:
        check_vaddr (f->esp + 4);
        check_vaddr (f->esp + 8);
        check_vaddr (f->esp + 12);
        check_vaddr (f->esp + 16);
        f->eax = max_of_four_int ((int) * (uint32_t *) (f->esp + 4), (int) * (uint32_t *) (f->esp + 8), (int) * (uint32_t *) (f->esp + 12), (int) * (uint32_t *) (f->esp + 16));
        break;
    }
}