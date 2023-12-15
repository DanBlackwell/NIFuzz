# QuantiLeakFuzzer

Note that this repo can use a locally modified version of [https://github.com/AFLplusplus/LibAFL](LibAFL), to do this place this repo in the directory `./fuzzers/[QuantiLeakFuzzer]`. By default it pulls LibAFL from cargo.

It can be built with `cargo build` and `cargo make run` builds the fuzzer then fuzzes the program `src/program.c`.

## Building on MacOS

As discussed [https://github.com/AFLplusplus/LibAFL/issues/1214](here), the recent MacOS versions clang is too new to support the AFL++ pass. To fix this, I did `brew install llvm@14`, then
`export LLVM_CONFIG=/opt/homebrew/opt/llvm@14/bin/llvm-config` before running `cargo build`.

# Fuzzing Harness

You can get the parts of the fuzzer generated testcase using the following macros:
```
EXPLICIT_PUBLIC_IN
EXPLICIT_PUBLIC_LEN

EXPLICIT_SECRET_IN
EXPLICIT_SECRET_LEN

STACK_MEM_IN
STACK_MEM_LEN

HEAP_MEM_IN
HEAP_MEM_LEN
```

for example:

```
#include "memory.h" // this gives us the stack and heap filling tools

__AFL_FUZZ_INIT();

int main(void) {
    __AFL_INIT();


}
```