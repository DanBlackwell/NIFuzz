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
  extern void *__real_malloc(size_t);
  extern void __real_free(void *);
  extern void *__real_realloc(void *, size_t);
#endif

static uint8_t memFillBuf[1024 * 1024]; // relying on AFL max input size here...
static uint32_t memFillLen;
// Use this to keep the fills as contiguous copies of the buffer
static uint32_t memFillBufPos;

int memWrapEnabled = 0;

uint8_t *__stack_top;
uint8_t *__cur_addr;
uint64_t __cur_buf_pos;

void initMemFillBuf(const uint8_t *buf, const uint32_t len) {
//  memFillBuf = __real_malloc(len);
  memFillLen = len;
  memcpy(memFillBuf, buf, len);
}

void enableMemWrap() {
  memWrapEnabled = 1;
}

void disableMemWrap() {
  memWrapEnabled = 0;
}

#define MALLOC_PAD 32

void *__wrap_malloc(size_t bytes) {
#ifdef __APPLE__
  if (!__real_malloc) {
    __real_malloc = dlsym(RTLD_NEXT, "malloc");
  }
#endif

  if (!memWrapEnabled) return __real_malloc(bytes);

  size_t adjustedBytes = bytes + MALLOC_PAD; // Add some extra bytes padding
  uint8_t *raw = (uint8_t *)__real_malloc(adjustedBytes);

  if (!memFillLen) goto out;

  for (size_t i = 0; i < adjustedBytes; i += memFillLen) {
    uint32_t bufRemaining = memFillLen - memFillBufPos;

    // if we have more bytes remaining in buf than we need to fill
    if (adjustedBytes - i < bufRemaining) {
      uint32_t copyLen = adjustedBytes - i;
      memcpy(raw + i, memFillBuf + memFillBufPos, copyLen);
      memFillBufPos += copyLen;
    } else {
      memcpy(raw + i, memFillBuf + memFillBufPos, bufRemaining);
      memFillBufPos = 0;
    }
  }

out:
  return (void *)(raw + MALLOC_PAD / 2);
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
  __real_free(((uint8_t *)ptr) - MALLOC_PAD / 2);
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
