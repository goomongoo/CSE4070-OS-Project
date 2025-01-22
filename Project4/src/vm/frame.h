#include <stdbool.h>
#include <hash.h>
#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"

struct frame_table_entry
  {
    void              *upage;
    void              *kpage;
    struct thread     *owner;
    struct hash_elem  hash_elem;
    struct list_elem  list_elem;
  };

void frame_init (void);
void *frame_alloc (enum palloc_flags flags, void *upage);
void frame_free (void *kpage);
void frame_free_thread (struct thread *t);