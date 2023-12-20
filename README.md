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

for example, the following program uses all features of QuantiLeakFuzzer:

```C
#include "memory.h" // this gives us the stack and heap filling tools

__AFL_FUZZ_INIT(); // Needs to be somewhere in global space

typedef struct {
    char option; // Note that there is likely to be 3 bytes padding between option and value
    int  value;
} example_struct;

int test_func(char opt, int val, example_struct *output) {
    example_struct res;

    switch opt {
        case 'a':
            res.option = 1;
            res.value = val; // We copy the explicit secret input val to output here!
            break;
        case 'b':
            res.option = 2;
            res.value = 42;
            break;
        default:
            res.option = 0;
            res.value = 0;
            break;
    }

    // We copy stack memory from `res` padding to `output` here!
    memcpy(output, &res, sizeof(res));
    return 0;
}

int main(void) {
    /* call __AFL_INIT(); macro when the forkserver should start (heavy 
       initialisation that does not require input can be done before this to 
       speed up fuzzing) */
    __AFL_INIT();

    /* Only use `static` variables in the main function to give the stack fill approach 
       the best chance of succeeding */
    static example_struct result;
    static char option;
    if (PUBLIC_LEN < sizeof(option)) { return 1; }
    option = PUBLIC_IN[0];

    static int secret_val;
    if (SECRET_LEN < sizeof(secret_val)) { return 1; }
    secret_val = *(int *)EXPLICIT_SECRET_IN;

    /* initHeapMemFillBuf uses HEAP_MEM_IN to set a fill pattern for all new 
       malloc'd memory. */
    initHeapMemFillBuf(HEAP_MEM_IN, HEAP_MEM_LEN);

    /* The `disableHeapMemWrap()` and corresponding `enableHeapMemWrap()` 
       functions disable and re-enable the filling of heap allocated memory.
       This can be useful for programs like OpenSSL that expect early allocations
       to be all zeroes (whether or not they should do this is for another 
       discussion) */
    disableHeapMemWrap();
    char *test = malloc(100); // this will be unfilled (likely all zeroes)
    free(test);
    enableHeapMemWrap();

    static int res;

    /* Delay the macro call FILL_STACK until you are ready to call your target
       function. Allocating any variables in main as either `static` or as 
       globals gives this the best chance of behaving well. */
    FILL_STACK(STACK_MEM_IN, STACK_MEM_LEN);
    /* Now call your target function! */
    res = test_func(option, secret_val, &output);

    /* write the raw value of res direct to stdout (1) */
    write(1, &res, sizeof(res));
    /* write the raw value of output direct to stdout (1) */
    write(1, &output, sizeof(output));

    return 0;
}
```

Corpus seeds must be provided in Base64 encoded strings in a JSON dictionary with the following (optional) keys:

```
{
  "EXPLICIT_PUBLIC": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
  "EXPLICIT_SECRET": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
  "STACK_MEM_SECRET": "MDAwMA==",
  "HEAP_MEM_SECRET": "MDAwMA=="
}
```

Note that as JSON, there should be no trailing comma. Any keys that are missing in the seed are not populated by the fuzzer; this allows for more efficient fuzzing of programs that do not have `EXPLICIT_SECRET` inputs for example (by omitting a key-value pair for `EXPLICIT_SECRET`).