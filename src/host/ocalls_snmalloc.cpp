#include <stddef.h>

extern "C" void* snmalloc_reserve_shared(size_t* size, size_t align)
  __attribute__((weak));

extern "C" void* host_reserve(size_t size, size_t align)
{
  return snmalloc_reserve_shared(&size, align);
}
