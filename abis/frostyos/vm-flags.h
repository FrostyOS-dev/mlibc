#ifndef _ABIBITS_MMAP_FLAGS_H
#define _ABIBITS_MMAP_FLAGS_H

#define MAP_FAILED ((void *)(-1))
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4

#define MAP_PRIVATE 1
#define MAP_SHARED 2
#define MAP_ANONYMOUS 4
#define MAP_ANON MAP_ANONYMOUS
#define MAP_FIXED 8
#define MAP_POPULATE 16
#define MAP_FIXED_NOREPLACE 32

#endif /* _ABIBITS_MMAP_FLAGS_H */
