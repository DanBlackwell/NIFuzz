#ifndef MEMORY_INFO_LEAKAGE_H
#define MEMORY_INFO_LEAKAGE_H

#include <stddef.h>
#include <stdint.h>

void initHeapMemFillBuf(const uint8_t *buf, const uint32_t len);
void enableHeapMemWrap(void);
void disableHeapMemWrap(void);
void *get_stack_top(void);
void *get_cur_stack_bottom(void);
void *get_min_stack_bottom(void);

extern uint8_t *__stack_top;
extern uint8_t *__cur_addr;
extern uint64_t __cur_buf_pos;

// void fill_stack(void);

#ifdef __aarch64__
  #define GET_SP(var) asm(\
    "MOV	%0, sp" \
    : "=r" (var) \
    )
#else 
  #define GET_SP(var) asm("mov %%rsp, %0;" /* load the stack pointer addr */ \
          :"=r"(var) /* write-only stack_loc */ \
    )
#endif 

#define FILL_STACK(buf, len) { \
  if (len) { \
    __cur_addr = (uint8_t *)get_cur_stack_bottom() + 1; \
    __cur_buf_pos = 0; \
    GET_SP(__stack_top); \
   \
    do { \
      *__cur_addr = buf[__cur_buf_pos]; \
      __cur_addr++; \
      __cur_buf_pos++; \
      if (__cur_buf_pos >= len) __cur_buf_pos = 0; \
    } while (__cur_addr < __stack_top); \
  } \
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
