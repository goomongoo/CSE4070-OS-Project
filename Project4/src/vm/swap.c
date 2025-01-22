#include "vm/swap.h"
#include <bitmap.h>
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "vm/frame.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct block *swap_block;
static struct bitmap *swap_table;
static struct lock swap_lock;

void swap_init(void)
{
  swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block == NULL)
    PANIC ("No swap block device found!");
  
  size_t swap_size = block_size (swap_block) / SECTORS_PER_PAGE;
  swap_table = bitmap_create (swap_size);
  if (swap_table == NULL)
    PANIC ("Failed to create swap table!");
  
  bitmap_set_all (swap_table, true);
  lock_init (&swap_lock);
}

int
swap_out (void *kpage)
{
  lock_acquire (&swap_lock);

  size_t free_slot = bitmap_scan_and_flip (swap_table, 0, 1, true);
  if (free_slot == BITMAP_ERROR)
    return -1;
  
  block_sector_t start_sector = free_slot * SECTORS_PER_PAGE;
  for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    block_write (swap_block, start_sector + i, (uint8_t *) kpage + i * BLOCK_SECTOR_SIZE);
  
  lock_release (&swap_lock);

  return (int) free_slot;
}

void
swap_in (size_t index, void *kpage)
{
  lock_acquire (&swap_lock);

  block_sector_t start_sector = index * SECTORS_PER_PAGE;
  for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    block_read (swap_block, start_sector + i, (uint8_t *) kpage + i * BLOCK_SECTOR_SIZE);
  
  bitmap_set (swap_table, index, true);

  lock_release (&swap_lock);
}

void
swap_free (size_t index)
{
  lock_acquire (&swap_lock);
  bitmap_set (swap_table, index, true);
  lock_release (&swap_lock);
}