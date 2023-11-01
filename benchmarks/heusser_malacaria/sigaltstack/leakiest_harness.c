#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#define SS_ONSTACK      1
#define SS_DISABLE      2

#define MINSIGSTKSZ     2048

#define EPERM            1      /* Operation not permitted */
#define ENOMEM          12      /* Out of memory */
#define EFAULT          14      /* Bad address */
#define EINVAL          22      /* Invalid argument */

typedef struct task_struct_t {
	void *sas_ss_sp;
	// char *sas_ss_sp;
	size_t sas_ss_size;
} task_struct;

task_struct _current;
task_struct *current = &_current;

typedef struct sigaltstack {
	void /*__user*/ *ss_sp;
	int ss_flags; // 4 bytes padding on 64-bit systems
	size_t ss_size;
} stack_t;

static inline int on_sig_stack(unsigned long sp)
{
	// return 1;
	return (sp - (uintptr_t)current->sas_ss_sp < current->sas_ss_size);
}

static inline int sas_ss_flags(unsigned long sp)
{
        return (current->sas_ss_size == 0 ? SS_DISABLE
                : on_sig_stack(sp) ? SS_ONSTACK : 0);
}

int copy_to_user(void *user_dest, void *kernel_buf, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		printf("%hhx", ((char *)kernel_buf)[i]);
	}

	return 0;
}

// uss: user signal-stack
// uoss: user old signal-stack
int
do_sigaltstack (const stack_t /*__user*/ *uss, stack_t /*__user*/ *uoss, unsigned long sp)
{
	stack_t oss;
	int error;

	if (uoss) {
		oss.ss_sp = (void /*__user*/ *) current->sas_ss_sp;
		oss.ss_size = current->sas_ss_size;
		oss.ss_flags = sas_ss_flags(sp);
	}

	if (uss) {
		void /*__user*/ *ss_sp;
		size_t ss_size;
		int ss_flags;

		error = -EFAULT;
//		if (!access_ok(VERIFY_READ, uss, sizeof(*uss))
//		    || __get_user(ss_sp, &uss->ss_sp)
//		    || __get_user(ss_flags, &uss->ss_flags)
//		    || __get_user(ss_size, &uss->ss_size))
//			goto out;
		ss_sp = uss->ss_sp;
		ss_flags = uss->ss_flags;
		ss_size = uss->ss_size;

		error = -EPERM;
		if (on_sig_stack(sp))
			goto out;

		error = -EINVAL;
		/*
		 *
		 * Note - this code used to test ss_flags incorrectly
		 *  	  old code may have been written using ss_flags==0
		 *	  to mean ss_flags==SS_ONSTACK (as this was the only
		 *	  way that worked) - this fix preserves that older
		 *	  mechanism
		 */
		if (ss_flags != SS_DISABLE && ss_flags != SS_ONSTACK && ss_flags != 0)
			goto out;

		if (ss_flags == SS_DISABLE) {
			ss_size = 0;
			ss_sp = NULL;
		} else {
			error = -ENOMEM;
			if (ss_size < MINSIGSTKSZ)
				goto out;
		}

		current->sas_ss_sp = ss_sp;
		current->sas_ss_size = ss_size;
	}

	if (uoss) {
		error = -EFAULT;
		if (copy_to_user(uoss, &oss, sizeof(oss)))
			goto out;
	}

	error = 0;
out:
	return error;
}


///////////////////////////////////////////////////////////////////////////////
// FUZZ HARNESS
///////////////////////////////////////////////////////////////////////////////

#include "generate_random.h"
#include "memory.h"
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) 
{
	for (int i = 0; i < 1000000; i++) {
		// handle SECRET
		uint32_t seed = 0;
		FILL_RAND(seed);
		printf("(%u,", seed);
		SEED_MEMORY(seed);

		// handle PUBLIC
		stack_t uss = {0};
		FILL_RAND(uss.ss_flags);

		uss.ss_size = rand() % 20;
		uint8_t stack[20];
		FILL_RAND(stack);
		uss.ss_sp = stack;

		stack_t uoss = {0};

		current->sas_ss_sp = &uoss;
		current->sas_ss_size = 1024;

		FILL_STACK();

		// execute the function

		int res = do_sigaltstack(&uss, &uoss, 0);
		printf(" %d)\n", res);
	}

	return 0;
}
