use std::env;

use libafl_cc::{ClangWrapper, CompilerWrapper, LLVMPasses, ToolWrapper};

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ wrapper was called. Expected {dir:?} to end with c or cxx"),
        };

        let is_asm = args.iter().fold(false, |acc, x| {
            if acc { return acc; } 
            let splitted = x.split("."); 
            splitted.clone().count() == 2 && splitted.last().unwrap().to_lowercase() == "s"
        });

        dir.pop();

        let mut cc = ClangWrapper::new();
        cc.silence(true)
          // silence the compiler wrapper output, needed for some configure scripts.
          .dont_optimize()
          .parse_args(&args)
          .expect("Failed to parse the command line")
          // Link with libafl's forkserver implementation
          .link_staticlib(&dir, "libforkserver_libafl_cc");

        if !is_asm {
            cc.add_pass(LLVMPasses::AFLCoverage)
              .cpp(is_cpp)
                          // Enable libafl's coverage instrumentation
              .add_arg("-mllvm")
              .add_arg("-ctx"); // Context sensitive coverage
              // Imitate afl-cc's compile definitions 
              let fuzz_init = "-D__AFL_FUZZ_INIT()=\
                int __afl_sharedmem_fuzzing = 1;\
                extern unsigned int *__afl_fuzz_len;\
                extern unsigned char *__afl_fuzz_ptr;\
                unsigned char __afl_fuzz_alt[1048576];\
                unsigned char *__afl_fuzz_alt_ptr = __afl_fuzz_alt;\
                void libafl_start_forkserver(void);\
                enum { HAS_EXPLICIT_PUB_IN = 0x80, HAS_EXPLICIT_SEC_IN = 0x40, HAS_STACK_MEM_IN = 0x20, HAS_HEAP_MEM_IN = 0x10 };\
                unsigned char *__data;\
                int __len;\
                uint32_t _explicit_public_len = 0, _explicit_secret_len = 0, _stack_mem_len = 0, _heap_mem_len = 0;\
                uint8_t *_explicit_public_in = NULL, *_explicit_secret_in = NULL, *_stack_mem_in = NULL, *_heap_mem_in = NULL;";
            cc.add_arg(fuzz_init)
              .add_arg("-D__AFL_FUZZ_TESTCASE_LEN=(__afl_fuzz_ptr ? *__afl_fuzz_len : (*__afl_fuzz_len = read(0, __afl_fuzz_alt_ptr, 1048576)) == 0xffffffff ? 0 : *__afl_fuzz_len)")
              .add_arg("-D__AFL_FUZZ_TESTCASE_BUF=(__afl_fuzz_ptr ? __afl_fuzz_ptr : __afl_fuzz_alt_ptr)")
              .add_arg("-D__AFL_INIT()=libafl_start_forkserver();\
                __data=__AFL_FUZZ_TESTCASE_BUF;\
                __len =__AFL_FUZZ_TESTCASE_LEN;\
                uint32_t __pos = 0;\
                uint8_t _input_parts_indicator = __data[__pos++];\
                CHECK_AND_PARSE_LEN(HAS_EXPLICIT_PUB_IN, _explicit_public_len);\
                CHECK_AND_PARSE_LEN(HAS_EXPLICIT_SEC_IN, _explicit_secret_len);\
                CHECK_AND_PARSE_LEN(HAS_STACK_MEM_IN, _stack_mem_len);\
                CHECK_AND_PARSE_LEN(HAS_HEAP_MEM_IN, _heap_mem_len);\
                CHECK_AND_PARSE_VAL(HAS_EXPLICIT_PUB_IN, _explicit_public_in, _explicit_public_len);\
                CHECK_AND_PARSE_VAL(HAS_EXPLICIT_SEC_IN, _explicit_secret_in, _explicit_secret_len);\
                CHECK_AND_PARSE_VAL(HAS_STACK_MEM_IN, _stack_mem_in, _stack_mem_len);\
                CHECK_AND_PARSE_VAL(HAS_HEAP_MEM_IN, _heap_mem_in, _heap_mem_len);");

            let extra_defines = [
                "-DCHECK_AND_PARSE_LEN(flag, var)=if (_input_parts_indicator & flag) { var = *(typeof(var) *)(__data + __pos); __pos += sizeof(var); }",
                "-DCHECK_AND_PARSE_VAL(flag, buf, len)=if (_input_parts_indicator & flag) { buf = __data + __pos; __pos += len; }",
                "-DEXPLICIT_PUBLIC_IN=_explicit_public_in",
                "-DEXPLICIT_PUBLIC_LEN=_explicit_public_len",
                "-DEXPLICIT_SECRET_IN=_explicit_secret_in",
                "-DEXPLICIT_SECRET_LEN=_explicit_secret_len",
                "-DSTACK_MEM_IN=_stack_mem_in",
                "-DSTACK_MEM_LEN=_stack_mem_len",
                "-DHEAP_MEM_IN=_heap_mem_in",
                "-DHEAP_MEM_LEN=_heap_mem_len",
            ];
            for define in extra_defines {
                cc.add_arg(define);
            }
        }

        if let Some(code) = cc.run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}

