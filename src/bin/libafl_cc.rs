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
              .add_arg("-ctx") // Context sensitive coverage
              // Imitate afl-cc's compile definitions 
              .add_arg("-D__AFL_FUZZ_INIT()=int __afl_sharedmem_fuzzing = 1;extern unsigned int *__afl_fuzz_len;extern unsigned char *__afl_fuzz_ptr;unsigned char __afl_fuzz_alt[1048576];unsigned char *__afl_fuzz_alt_ptr = __afl_fuzz_alt;unsigned char *Data; int Size;uint32_t public_len, secret_len;uint8_t *public_in, *secret_in;void libafl_start_forkserver(void)")
              .add_arg("-D__AFL_FUZZ_TESTCASE_BUF=(__afl_fuzz_ptr ? __afl_fuzz_ptr : __afl_fuzz_alt_ptr)")
              .add_arg("-D__AFL_FUZZ_TESTCASE_LEN=(__afl_fuzz_ptr ? *__afl_fuzz_len : (*__afl_fuzz_len = read(0, __afl_fuzz_alt_ptr, 1048576)) == 0xffffffff ? 0 : *__afl_fuzz_len)")
              .add_arg("-DPUBLIC_IN=public_in")
              .add_arg("-DPUBLIC_LEN=public_len")
              .add_arg("-DSECRET_IN=secret_in")
              .add_arg("-DSECRET_LEN=secret_len")
              .add_arg("-D__AFL_INIT()=libafl_start_forkserver();Data=__AFL_FUZZ_TESTCASE_BUF;Size=__AFL_FUZZ_TESTCASE_LEN;public_len=*(uint32_t *)Data;secret_len=Size - public_len - sizeof(public_len);public_in=Data + sizeof(public_len);secret_in=public_in + public_len;");
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

