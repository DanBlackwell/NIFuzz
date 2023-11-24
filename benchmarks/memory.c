#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>

#ifdef __APPLE__
  #include <dlfcn.h>

  void* (*__real_malloc)(size_t bytes);
  void (*__real_free)(void *);
  void* (*__real_realloc)(void *, size_t);
#else
  extern void *malloc(size_t);
  extern void *__real_malloc(size_t);
  extern void __real_free(void *);
  extern void *__real_realloc(void *, size_t);
#endif

uint64_t repeatedVal = 0;
int memWrapEnabled = 0;

void initRepeatedVal() {
  repeatedVal = (uint64_t)rand() << 48 | (uint64_t)rand() << 32 | (uint64_t)rand() << 16 | (uint64_t)rand();
}

void enableMemWrap() {
  memWrapEnabled = 1;
}

void disableMemWrap() {
  memWrapEnabled = 0;
}

void *__wrap_malloc(size_t bytes) {
#ifdef __APPLE__
  if (!__real_malloc) {
    __real_malloc = dlsym(RTLD_NEXT, "malloc");
  }
#endif

  if (!memWrapEnabled) return __real_malloc(bytes);

  size_t adjusted_bytes = bytes + 32; // Add some extra bytes padding
  uint64_t *raw = (uint64_t *)__real_malloc(adjusted_bytes);

  uint64_t reps = adjusted_bytes / sizeof(repeatedVal);
  for (size_t i = 0; i < reps; i++) {
    raw[i] = repeatedVal;
  }
  for (size_t i = 0; i < adjusted_bytes % sizeof(repeatedVal); i++) {
    ((uint8_t *)(raw + reps))[i] = repeatedVal >> (8 * i) & 0xFF;
  }

  return (void *)(raw + 2);
}

void __wrap_free(void *ptr) {
#ifdef __APPLE__
  if (!__real_free) {
    __real_free = dlsym(RTLD_NEXT, "free");
  }
#endif

  if (!memWrapEnabled) { 
    __real_free(ptr);
    return;
  }
  __real_free(((uint64_t *)ptr) - 2);
}

void *__wrap_realloc(void *ptr, size_t new_size) {
#ifdef __APPLE__
  if (!__real_realloc) {
    __real_realloc = dlsym(RTLD_NEXT, "realloc");
  }
#endif

  if (!memWrapEnabled) return __real_realloc(ptr, new_size);

  __wrap_free(ptr);
  return __wrap_malloc(new_size);
}

void *get_stack_top() {

  FILE *file = fopen("/proc/self/maps", "r");
  char buf[4096];
  uintptr_t start, end, offset, major, minor, unknown;
  char flags[5];
  char name[400];

  while (fgets(buf, sizeof(buf), file)) {
    sscanf(buf, "%lx-%lx %4c %lx %ld:%ld %ld %s", &start, &end, flags, &offset, &major, &minor, &unknown, name);
    if (strcmp("[stack]", name) == 0) {
      break;
    }
  }

  return (void *)end;
}

void *get_cur_stack_bottom() {
  FILE *file = fopen("/proc/self/maps", "r");
  char buf[4096];
  uintptr_t start, end, offset, major, minor, unknown;
  char flags[5];
  char name[400];

  while (fgets(buf, sizeof(buf), file)) {
    sscanf(buf, "%lx-%lx %4c %lx %ld:%ld %ld %s", &start, &end, flags, &offset, &major, &minor, &unknown, name);
    if (strcmp("[stack]", name) == 0) {
      break;
    }
  }

  fclose(file);

  return (void *)start;
}

void *get_min_stack_bottom() {
  void *min = get_stack_top();

  struct rlimit limit;
  getrlimit (RLIMIT_STACK, &limit);
  return (char *)min - limit.rlim_cur;
}

void fill_stack() {
  uint64_t *__stack_bottom = (uint64_t *)get_cur_stack_bottom();
  if (!repeatedVal)
    initRepeatedVal();
  volatile uint64_t *stack_loc; stack_loc = (void *)(&stack_loc - 1);

  for (; stack_loc > __stack_bottom; stack_loc--) {
    *stack_loc = repeatedVal;
  }

  stack_loc = (uint64_t *)repeatedVal;
  __stack_bottom = (uint64_t *)repeatedVal;
}

