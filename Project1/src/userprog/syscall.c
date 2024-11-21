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

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static void syscall (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall, "syscall");
}

/* Project_1 : System Call Handling - begin */
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
read (int fd, void *buffer, unsigned size)
{
  uint8_t *bufptr = (uint8_t *) buffer;
  int bytes_read = -1;

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
  
  return bytes_read;
}

int
write (int fd, const void *buffer, unsigned size)
{
  const char *bufptr = buffer;
  int bytes_written = 0;

  if (fd == STDOUT_FILENO)
    {
      putbuf(bufptr, size);
      bytes_written = size;
    }
  
  return bytes_written;
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
/* Project_1 : System Call Handling - end */