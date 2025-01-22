#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "../src/devices/timer.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  struct thread *t;
  char *execute_file;
  int execute_file_len;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  /* Project_1 : Make a copy of file name to execute */
  execute_file_len = 0;
  while (fn_copy[execute_file_len] != ' ' && fn_copy[execute_file_len] != '\0')
    execute_file_len++;
  execute_file = malloc (sizeof (char) * (execute_file_len + 1));
  if (execute_file == NULL)
    return -1;
  strlcpy(execute_file, fn_copy, execute_file_len + 1);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (execute_file, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    {
      palloc_free_page (fn_copy);
      return tid;
    }
  
  /* Wait until load is done (either success or fail) */
  t = get_thread_by_tid (tid);
  sema_down(&(t->load_sema));
  if (!t->load_success)
    {
      return -1;
    }
  
  free (execute_file);
  
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  struct thread *t;
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  t = thread_current ();
  spt_init (&t->spt);
  list_init (&t->mmap_list);
  t->next_mapid = 0;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  t->load_success = success;
  sema_up (&(t->load_sema));
  if (!success)
  {
    exit (-1);
  }

  init_fd_table (t);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *child_thread;
  int exit_status;

  if (child_tid == TID_ERROR)
    return -1;
  
  child_thread = get_child_thread_by_tid (child_tid);
  if (child_thread == NULL)
    return -1;

  sema_down (&(child_thread->wait_sema));
  exit_status = child_thread->exit_status;
  list_remove (&(child_thread->child_elem));
  sema_up (&(child_thread->free_sema));

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  // debugging
  //printf("%s: Exiting process : %d\n", cur->name, cur->tid);
  mmap_clear ();

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      frame_free_thread (cur);
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  
  spt_destroy (&cur->spt);
  clean_fd_table (cur);
  if (cur->file_self)
    {
      file_allow_write (cur->file_self);
      file_close (cur->file_self);
    }
  sema_up (&(cur->wait_sema));
  sema_down (&(cur->free_sema));
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Project_1 : Declaration */
  char **argv;
  int argc;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Project_1 : Parsing command line - begin */
  char *ptr;
  char *saveptr;

  argv = malloc (sizeof (char *) * 128);
  if (argv == NULL)
    goto done;

  i = 0;
  ptr = strtok_r ((char *) file_name, " ", &saveptr);
  while (ptr)
    {
      argv[i++] = ptr;
      ptr = strtok_r (NULL, " ", &saveptr);
    }
  argv[i] = NULL;
  argc = i;
  /* Project_1 : Parsing command line - end */

  /* Open executable file. */
  lock_acquire (&f_lock);
  file = filesys_open (file_name);
  lock_release (&f_lock);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  //t->file_self = filesys_open (file_name);

  /* Read and verify executable header. */
  lock_acquire (&f_lock);
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      lock_release (&f_lock);
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
  lock_release (&f_lock);

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      lock_acquire (&f_lock);
      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        {
          lock_release (&f_lock);
          goto done;
        }
      lock_release (&f_lock);
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;
  
  /* Project_1 : Pushing arguments into stack - begin */
  int argv_total_len = 0;
  int word_align;

  for (i = argc - 1; i >= 0; i--)
    {
      int len = strlen (argv[i]) + 1;
      argv_total_len += len;
      *esp -= len;
      strlcpy (*esp, argv[i], len);
      argv[i] = *esp;
    }

  word_align = 4 - (argv_total_len % 4);
  *esp -= word_align;
  memset (*esp, 0, word_align);

  for (i = argc; i >= 0; i--)
    {
      *esp -= 4;
      ** (uint32_t **) esp = (uint32_t) argv[i];
    }
  *esp -= 4;
  ** (uint32_t **) esp = (uint32_t) (*esp + 4);
  *esp -= 4;
  ** (uint32_t **) esp = (uint32_t) argc;
  *esp -= 4;
  ** (uint32_t **) esp = 0;

  free (argv);

  // debugging
  //hex_dump ((uintptr_t) *esp, *esp, 100, true);
  /* Project_1 : Pushing arguments into stack - end */

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (file != NULL)
    {
      t->file_self = file;
      file_deny_write (t->file_self);
    }
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      if (!spt_create_filesys (&thread_current ()->spt, upage, file, ofs, page_read_bytes, page_zero_bytes, writable))
        return false;

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  bool success = false;
  void *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;

  if (spt_create_zero (&thread_current ()->spt, upage, true))
    {
      success = true;
      *esp = PHYS_BASE;
    }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Project_2 : begin */
void
init_fd_table (struct thread *t)
{
  memset (t->fd_table, 0, sizeof (t->fd_table));
}

void
clean_fd_table (struct thread *t)
{
  for (int i = 0; i < 131; i++)
    file_close ((t->fd_table)[i]);
}

int
get_new_fd (struct thread *t)
{ 
  for (int i = 2; i < 131; i++)
    {
      if ((t->fd_table)[i] == NULL)
        return i;
    }
  
  return -1;
}
/* Project_2 : end */

struct file *
get_file_by_fd (int fd)
{
  struct file **fd_table = thread_current ()->fd_table;

  if (fd_table[fd] != NULL)
    return fd_table[fd];
  
  return NULL;
}

bool
page_fault_handler (void *fault_addr, void *esp)
{
  void *fault_upage = pg_round_down (fault_addr);
  struct thread *t = thread_current ();
  struct spt_entry *spte = spt_find_entry (&t->spt, fault_upage);

  if (spte == NULL)
    {
      if (fault_upage >= PHYS_BASE || fault_upage < (void *) (PHYS_BASE - MAX_STACK_SIZE) || fault_addr < esp - 32)
        return false;
      
      void *kpage = frame_alloc (PAL_USER | PAL_ZERO, fault_upage);
      if (kpage == NULL)
        return false;
      
      if (!install_page (fault_upage, kpage, true))
        {
          frame_free (kpage);
          return false;
        }

      return true;
    }
  
  void *kpage = NULL;
  if (spte->location == PAGE_IN_FILESYS)
    {
      kpage = frame_alloc (PAL_USER, spte->upage);
      if (kpage == NULL)
        return false;

      if (!lock_held_by_current_thread (&f_lock))
        {
          lock_acquire (&f_lock);
          file_seek (spte->file, spte->file_offset);
          if (file_read(spte->file, kpage, spte->read_bytes) != (off_t) spte->read_bytes)
            {
              lock_release (&f_lock);
              frame_free (kpage);
              return false;
            }
          lock_release (&f_lock);
        }
      else
        {
          file_seek (spte->file, spte->file_offset);
          if (file_read(spte->file, kpage, spte->read_bytes) != (off_t) spte->read_bytes)
            {
              frame_free (kpage);
              return false;
            }
        }
      memset (kpage + spte->read_bytes, 0, spte->zero_bytes);
    }
  else if (spte->location == PAGE_ZERO)
    {
      kpage = frame_alloc (PAL_USER | PAL_ZERO, spte->upage);
      if (kpage == NULL)
        return false;
    }
  else if (spte->location == PAGE_IN_SWAP)
    {
      kpage = frame_alloc (PAL_USER, spte->upage);
      if (kpage == NULL)
        return false;
      
      swap_in (spte->swap_index, kpage);
      swap_free (spte->swap_index);
      spte->swap_index = -1;
    }
  else
    {
      return false;
    }
  
  if (!install_page (spte->upage, kpage, spte->writable))
    {
      frame_free (kpage);
      return false;
    }
  spte->location = PAGE_IN_FRAME;

  return true;
}

void
mmap_clear (void)
{
  struct thread *cur = thread_current ();
  
  while (!list_empty (&cur->mmap_list))
    {
      struct mmap_entry *mmap_entry = list_entry (list_pop_front (&cur->mmap_list), struct mmap_entry, elem);

      munmap_handler (mmap_entry);
    }
}