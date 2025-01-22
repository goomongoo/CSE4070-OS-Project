#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

static struct hash frame_table;
static struct lock frame_table_lock;

static struct frame_table_entry *select_victim_frame (void);
static unsigned frame_table_hash_func (const struct hash_elem *e, void *aux UNUSED);
static bool frame_table_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

void
frame_init (void)
{
  lock_init (&frame_table_lock);
  hash_init (&frame_table, frame_table_hash_func, frame_table_less_func, NULL);
}

void *
frame_alloc (enum palloc_flags flags, void *upage)
{
  lock_acquire (&frame_table_lock);

  void *kpage = palloc_get_page (flags | PAL_USER);
  if (kpage == NULL)
    {
      struct frame_table_entry *victim = select_victim_frame ();
      if (victim == NULL)
        {
          lock_release (&frame_table_lock);
          return NULL;
        }
      
      struct spt_entry *spte = spt_find_entry (&victim->owner->spt, victim->upage);
      if (spte == NULL)
        {
          lock_release (&frame_table_lock);
          return NULL;
        }
      
      spte->swap_index = swap_out (victim->kpage);
      if (spte->swap_index == -1)
        {
          lock_release (&frame_table_lock);
          return NULL;
        }
      spte->location = PAGE_IN_SWAP;
      
      pagedir_clear_page (victim->owner->pagedir, spte->upage);
      palloc_free_page (victim->kpage);
      hash_delete (&frame_table, &victim->hash_elem);
      free (victim);

      kpage = palloc_get_page (flags | PAL_USER);
      if (kpage == NULL)
        {
          lock_release (&frame_table_lock);
          return NULL;
        }
    }
  
  struct frame_table_entry *fte = malloc (sizeof (struct frame_table_entry));
  if (fte == NULL)
    {
      palloc_free_page (kpage);
      lock_release (&frame_table_lock);
      return NULL;
    }
  
  fte->upage = upage;
  fte->kpage = kpage;
  fte->owner = thread_current ();
  hash_insert (&frame_table, &fte->hash_elem);

  lock_release (&frame_table_lock);

  return kpage;
}

void
frame_free (void *kpage)
{
  lock_acquire (&frame_table_lock);

  struct frame_table_entry temp;
  struct hash_elem *e;

  temp.kpage = kpage;
  e = hash_find (&frame_table, &temp.hash_elem);
  if (e != NULL)
    {
      struct frame_table_entry *fte = hash_entry (e, struct frame_table_entry, hash_elem);
    
      hash_delete (&frame_table, &fte->hash_elem);
      palloc_free_page (fte->kpage);
      free (fte);
    }
  
  lock_release (&frame_table_lock);
}

void
frame_free_thread (struct thread *t)
{
  struct hash_iterator iter;
  struct list to_delete;

  list_init (&to_delete);
  lock_acquire (&frame_table_lock);

  hash_first (&iter, &frame_table);
  while (hash_next (&iter))
    {
      struct frame_table_entry *fte = hash_entry (hash_cur (&iter), struct frame_table_entry, hash_elem);
      
      if (fte->owner == t)
        list_push_back (&to_delete, &fte->list_elem);
    }
  
  while (!list_empty (&to_delete))
    {
      struct frame_table_entry *fte = list_entry (list_pop_front (&to_delete), struct frame_table_entry, list_elem);

      hash_delete (&frame_table, &fte->hash_elem);
      palloc_free_page (fte->kpage);
      free (fte);
    }
  
  lock_release (&frame_table_lock);
}

static struct frame_table_entry *
select_victim_frame(void)
{
  static struct hash_iterator iter;

  if (hash_size (&frame_table) == 0)
    return NULL;

  hash_first (&iter, &frame_table);
  while (hash_next (&iter))
    {
      struct frame_table_entry *fte = hash_entry (hash_cur (&iter), struct frame_table_entry, hash_elem);

      if (!pagedir_is_accessed (fte->owner->pagedir, fte->upage))
        return fte;

      pagedir_set_accessed (fte->owner->pagedir, fte->upage, false);

      if (!hash_next (&iter))
        hash_first (&iter, &frame_table);
    }
  
  return NULL;
}

static unsigned
frame_table_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  const struct frame_table_entry *fte = hash_entry (e, struct frame_table_entry, hash_elem);

  return hash_bytes (&fte->upage, sizeof (fte->upage));
}

static bool
frame_table_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct frame_table_entry *fte_a = hash_entry (a, struct frame_table_entry, hash_elem);
  const struct frame_table_entry *fte_b = hash_entry (b, struct frame_table_entry, hash_elem);

  return fte_a->upage < fte_b->upage;
}