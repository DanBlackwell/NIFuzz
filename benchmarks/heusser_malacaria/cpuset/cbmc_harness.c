#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <assert.h>

#include "distinctions.h"

// typedef long long loff_t;

#define EFAULT          14      /* Bad address */
#define EINVAL          22      /* Invalid argument */

struct file {
        /* needed for tty driver, and maybe others */
        void                    *private_data;
};

/* cpusets_tasks_read array */
struct ctr_struct {
	char *buf;
	int bufsz;
};

/* struct created to return all data for CBMC assert */
struct cbmc_result {
	ssize_t nbytes;
	char *buf;
	int bufLen;
};
  

// return type changed for CBMC
static struct cbmc_result cpuset_tasks_read(struct file *file, char /*__user*/ *buf,
						size_t nbytes, loff_t *ppos)
{
	struct cbmc_result res;
	struct ctr_struct *ctr = file->private_data;

	if (*ppos + nbytes > ctr->bufsz)
		nbytes = ctr->bufsz - *ppos;
//	if (copy_to_user(buf, ctr->buf + *ppos, nbytes)) // REMOVED for CBMC
//		return -EFAULT;
	res.buf = ctr->buf + *ppos;
	res.bufLen = nbytes;
	res.nbytes = nbytes;
	
	*ppos += nbytes;
	return res;
}

#define INIT_INPUT(num) char buf ## num[10]; \
                        struct ctr_struct internal_struct ## num = { .bufsz = sizeof(buf ## num), .buf = buf ## num }; \
			struct file file ## num = { .private_data = (void *)&internal_struct ## num };

#define GENERATE_OUTPUT(num) ppos = ppos_orig; \
    struct cbmc_result output ## num = cpuset_tasks_read(&file ## num, (char *)NULL, nbytes, &ppos);

#define OUTPUTS_EQUAL(num1, num2) (output ## num1.nbytes == output ## num2.nbytes && output ## num1.bufLen == output ## num2.bufLen && \
    !memcmp(output ## num1.buf, output ## num2.buf, output ## num1.bufLen))

int main(void) 
{
        // handle PUBLIC

        size_t nbytes;
        loff_t ppos;
	ppos %= 10; // Make sure that ppos is within the size of the file
	loff_t ppos_orig = ppos;

	CHECK_LEAKAGE()

        return 0;
}
