#include <hash.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/file.h"
#include <stddef.h>

enum page_location
  {
    PAGE_IN_FRAME = 0,
    PAGE_IN_FILESYS,
    PAGE_IN_SWAP,
    PAGE_ZERO
  };

struct spt_entry
  {
    void                *upage;
    enum page_location  location;
    bool                writable;

    struct file         *file;
    off_t               file_offset;
    size_t              read_bytes;
    size_t              zero_bytes;

    int                 swap_index;

    struct hash_elem    hash_elem;
  };

void spt_init (struct hash *spt);
void spt_destroy (struct hash *spt);
struct spt_entry *spt_find_entry (struct hash *spt, void *upage);
bool spt_create_filesys (struct hash *spt, void *upage, struct file *file, off_t offset, size_t read_bytes, size_t zero_bytes, bool writable);
//spt_create_swap
bool spt_create_zero (struct hash *spt, void *upage, bool writable);
bool spt_remove_entry (struct hash *spt, void *upage);