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
#include <string.h>
#include "vm/frame.h"
#include "vm/page.h"
#include <list.h>
#include "userprog/pagedir.h"

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static void syscall (struct intr_frame *);
static void check_vaddr (const void *vaddr);

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

  check_vaddr (file);
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
  memset (buffer, 0, size);

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
  
  lock_acquire (&f_lock);
  file_close (file);
  lock_release (&f_lock);
  (t->fd_table)[fd] = NULL;
}
/* Project_2 - end */

mapid_t
mmap (int fd, void *addr)
{
  struct thread *cur = thread_current ();
  struct mmap_entry *mmap_entry;
  struct file *file;
  struct file *reopened_file;

  check_vaddr (addr);
  if (fd <= 1 || addr == NULL || pg_ofs (addr) != 0)
    return -1;
  
  file = get_file_by_fd (fd);
  if (file == NULL || file_length (file) == 0)
    return -1;
  
  reopened_file = file_reopen (file);
  if (reopened_file == NULL)
    return -1;
  
  mmap_entry = malloc (sizeof (struct mmap_entry));
  if (mmap_entry == NULL)
    {
      file_close (reopened_file);
      return -1;
    }
  
  mmap_entry->mapid = cur->next_mapid++;
  mmap_entry->vaddr = addr;
  mmap_entry->file = reopened_file;
  mmap_entry->file_length = file_length (reopened_file);

  off_t offset = 0;
  uint8_t *upage = mmap_entry->vaddr;
  uint32_t read_bytes = mmap_entry->file_length;

  while (read_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      if (!spt_create_filesys (&cur->spt, upage, mmap_entry->file, offset, page_read_bytes, page_zero_bytes, true))
        {
          file_close (mmap_entry->file);
          free (mmap_entry);
          return -1;
        }
      
      read_bytes -= page_read_bytes;
      upage += PGSIZE;
      offset += page_read_bytes;
    }
  
  list_push_back (&cur->mmap_list, &mmap_entry->elem);

  return mmap_entry->mapid;
}

void
munmap_handler (struct mmap_entry *target)
{
  struct thread *cur = thread_current ();
  off_t offset = 0;
  uint8_t *upage = target->vaddr;
  uint32_t read_bytes = target->file_length;

  while (read_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct spt_entry *spte = spt_find_entry (&cur->spt, upage);

      if (spte != NULL)
        {
          if (spte->location == PAGE_IN_FRAME)
            {
              void *kpage = pagedir_get_page (cur->pagedir, upage);

              if (pagedir_is_dirty (cur->pagedir, upage))
                {
                  if (!lock_held_by_current_thread (&f_lock))
                    {
                      lock_acquire (&f_lock);
                      file_write_at (target->file, kpage, page_read_bytes, offset);
                      lock_release (&f_lock);
                    }
                  else
                    {
                      file_write_at (target->file, kpage, page_read_bytes, offset);
                    }
                }
              
              frame_free (kpage);
              pagedir_clear_page (cur->pagedir, upage);
            }

          spt_remove_entry (&cur->spt, upage);
        }

      read_bytes -= page_read_bytes;
      upage += PGSIZE;
      offset += page_read_bytes;
    }

  list_remove (&target->elem);
  file_close (target->file);
  free (target);
}

void
munmap (mapid_t mapid)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->mmap_list); e != list_end (&cur->mmap_list); e = list_next (e))
    {
      struct mmap_entry *mmap_entry = list_entry (e, struct mmap_entry, elem);

      if (mmap_entry->mapid == mapid)
        {
          munmap_handler (mmap_entry);
          return;
        }
    }
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
      case SYS_MMAP:
        check_vaddr (f->esp + 4);
        check_vaddr (f->esp + 8);
        f->eax = mmap ((int) * (uint32_t *) (f->esp + 4), (void *) * (uint32_t *) (f->esp + 8));
        break;
      case SYS_MUNMAP:
        check_vaddr (f->esp + 4);
        munmap ((mapid_t) * (uint32_t *) (f->esp + 4));
        break;
    }
}