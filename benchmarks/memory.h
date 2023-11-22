#ifndef MEMORY_INFO_LEAKAGE_H
#define MEMORY_INFO_LEAKAGE_H

#include <stddef.h>

#define SEED_MEMORY(seed) { srand(seed); enableMemWrap(); initRepeatedVal(); }

void initRepeatedVal(void);
void enableMemWrap(void);
void disableMemWrap(void);
void *__wrap_malloc(size_t);
void *get_stack_top(void);
void *get_cur_stack_bottom(void);
void *get_min_stack_bottom(void);

// void fill_stack(void);

#define FILL_STACK() { \
  uint64_t *__stack_bottom = (uint64_t *)get_cur_stack_bottom(); \
  uint64_t repeatedVal = (uint64_t)rand() << 48 | (uint64_t)rand() << 32 | (uint64_t)rand() << 16 | (uint64_t)rand(); \
  volatile uint64_t *stack_loc; \
  asm("mov %%rsp, %0;" /* load the stack pointer addr */ \
        :"=r"(stack_loc) /* write-only stack_loc */ \
    ); \
 \
  do { \
    *stack_loc = repeatedVal; \
  } while (stack_loc-- > __stack_bottom + 1); \
 \
  stack_loc = (uint64_t *)repeatedVal; \
  __stack_bottom = (uint64_t *)repeatedVal; \
}


/* uint64_t *__stack_bottom_ptr, *__stack_top_ptr; \
 uint64_t *__stack_backup; \
 { \
   uint64_t *__stack_bottom = (uint64_t *)get_cur_stack_bottom(); \
   uint64_t repeatedVal = (uint64_t)rand() << 48 | (uint64_t)rand() << 32 | (uint64_t)rand() << 16 | (uint64_t)rand(); \
   volatile uint64_t *stack_loc; stack_loc = (void *)(&stack_loc); \
   __stack_backup = malloc(1 + stack_loc - __stack_bottom); \
   __stack_bottom_ptr = __stack_bottom; __stack_top_ptr = (uint64_t *)stack_loc; \
   uint64_t *backup = __stack_backup; \
  \
   do { \
     *backup = *stack_loc; backup++; \
     *stack_loc = repeatedVal; \
   } while (stack_loc-- > __stack_bottom + 1); \
  \
   stack_loc = (uint64_t *)repeatedVal; \
   __stack_bottom = (uint64_t *)repeatedVal; \
 }  
*/

/* #define RESTORE_STACK() { \
   volatile uint64_t *stack_loc = __stack_top_ptr; \
  \
   do { \
     *stack_loc = *__stack_backup; __stack_backup++; \
   } while (stack_loc-- > __stack_bottom_ptr); \
  \
 }  
*/

#endif
