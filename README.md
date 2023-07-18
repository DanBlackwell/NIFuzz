# QuantiLeakFuzzer

Note that this repo can use a locally modified version of [https://github.com/AFLplusplus/LibAFL](LibAFL), to do this place this repo in the directory `./fuzzers/[QuantiLeakFuzzer]`. By default it pulls LibAFL `0.10.1` from cargo.

It can be built with `cargo build` and `cargo make run` builds the fuzzer then fuzzes the program `src/program.c`.

