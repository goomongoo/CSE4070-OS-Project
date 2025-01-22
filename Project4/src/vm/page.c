#include "vm/page.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/thread.h"

static unsigned spt_hash_func (const struct hash_elem *e, void *aux UNUSED);
static bool spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void spt_destructor (struct hash_elem *e, void *aux UNUSED);

void
spt_init (struct hash *spt)
{
  hash_init (spt, spt_hash_func, spt_less_func, NULL);
}

void
spt_destroy (struct hash *spt)
{
  hash_destroy (spt, spt_destructor);
}

struct spt_entry *
spt_find_entry (struct hash *spt, void *upage)
{
  struct spt_entry temp;
  struct hash_elem *e;

  temp.upage = upage;
  e = hash_find (spt, &temp.hash_elem);

  return e ? hash_entry (e, struct spt_entry, hash_elem) : NULL;
}

bool
spt_remove_entry (struct hash *spt, void *upage)
{
  struct spt_entry temp;
  struct hash_elem *e;

  temp.upage = upage;
  e = hash_find (spt, &temp.hash_elem);
  if (e != NULL)
    {
      struct spt_entry *spte = hash_entry (e, struct spt_entry, hash_elem);
      hash_delete (spt, &spte->hash_elem);
      free (spte);
      return true;
    }
  
  return false;
}

bool
spt_create_filesys (struct hash *spt, void *upage, struct file *file, off_t offset, size_t read_bytes, size_t zero_bytes, bool writable)
{
  struct spt_entry *spte = malloc (sizeof (struct spt_entry));
  if (spte == NULL)
    return false;

  spte->upage = upage;
  spte->location = PAGE_IN_FILESYS;
  spte->writable = writable;
  spte->file = file;
  spte->file_offset = offset;
  spte->read_bytes = read_bytes;
  spte->zero_bytes = zero_bytes;
  spte->swap_index = -1;

  if (hash_insert (spt, &spte->hash_elem) != NULL)
    {
      free (spte);
      return false;
    }
  
  return true;
}

bool
spt_create_zero (struct hash *spt, void *upage, bool writable)
{
  struct spt_entry *spte = malloc (sizeof (struct spt_entry));
  if (spte == NULL)
    return false;
  
  spte->upage = upage;
  spte->location = PAGE_ZERO;
  spte->writable = writable;
  spte->swap_index = -1;

  if (hash_insert (spt, &spte->hash_elem) != NULL)
    {
      free (spte);
      return false;
    }
  
  return true;
}

static unsigned
spt_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  const struct spt_entry *spte = hash_entry (e, struct spt_entry, hash_elem);

  return hash_bytes (&spte->upage, sizeof (spte->upage));
}

static bool
spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct spt_entry *spte_a = hash_entry (a, struct spt_entry, hash_elem);
  const struct spt_entry *spte_b = hash_entry (b, struct spt_entry, hash_elem);

  return spte_a->upage < spte_b->upage;
}

static void
spt_destructor (struct hash_elem *e, void *aux UNUSED)
{
  struct spt_entry *spte = hash_entry (e, struct spt_entry, hash_elem);

  if (spte->location == PAGE_IN_SWAP && spte->swap_index != -1)
    swap_free (spte->swap_index);
  free (spte);
}