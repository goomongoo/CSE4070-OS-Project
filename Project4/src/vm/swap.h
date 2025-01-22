#include <stddef.h>
#include "devices/block.h"

void swap_init (void);
int swap_out (void *kpage);
void swap_in (size_t index, void *kpage);
void swap_free (size_t index);