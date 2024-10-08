#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// typedef long long loff_t;

#define EFAULT          14      /* Bad address */
#define EINVAL          22      /* Invalid argument */

struct file {
//        /*
//         * fu_list becomes invalid after file_free is called and queued via
//         * fu_rcuhead for RCU freeing
//         */
//        union {
//                struct list_head        fu_list;
//                struct rcu_head         fu_rcuhead;
//        } f_u;
//        struct path             f_path;
//#define f_dentry        f_path.dentry
//#define f_vfsmnt        f_path.mnt
//        const struct file_operations    *f_op;
//        spinlock_t              f_lock;  /* f_ep_links, f_flags, no IRQ */
//        atomic_long_t           f_count;
//        unsigned int            f_flags;
//        fmode_t                 f_mode;
//        loff_t                  f_pos;
//        struct fown_struct      f_owner;
//        const struct cred       *f_cred;
//        struct file_ra_state    f_ra;
//
//        u64                     f_version;
//#ifdef CONFIG_SECURITY
//        void                    *f_security;
//#endif
//        /* needed for tty driver, and maybe others */
        void                    *private_data;
//
//#ifdef CONFIG_EPOLL
//        /* Used by fs/eventpoll.c to link all the hooks to this file */
//        struct list_head        f_ep_links;
//        struct list_head        f_tfile_llink;
//#endif /* #ifdef CONFIG_EPOLL */
//        struct address_space    *f_mapping;
//#ifdef CONFIG_DEBUG_WRITECOUNT
//        unsigned long f_mnt_write_state;
//#endif
};

/* cpusets_tasks_read array */
struct ctr_struct {
	char *buf;
	int bufsz;
};

int copy_to_user(void *user_dest, const void *kernel_buf, size_t size)
{
  write(1, kernel_buf, size);
  putc('\n', stdout);
  return 0;
}

#define __user 
ssize_t simple_read_from_buffer(void __user *to, size_t count, loff_t *ppos,
                                const void *from, size_t available)
{
        loff_t pos = *ppos;
        size_t ret;

        if (pos < 0)
                return -EINVAL;
        if (pos >= available || !count)
                return 0;
        if (count > available - pos)
                count = available - pos;
        ret = copy_to_user(to, from + pos, count);
        if (ret == count)
                return -EFAULT;
        count -= ret;
        *ppos = pos + count;
        return count;
}

static ssize_t cpuset_tasks_read(struct file *file, char __user *buf,
						size_t nbytes, loff_t *ppos)
{
	struct ctr_struct *ctr = file->private_data;

	if (*ppos + nbytes > ctr->bufsz)
		nbytes = ctr->bufsz - *ppos;
	if (copy_to_user(buf, ctr->buf + *ppos, nbytes))
		return -EFAULT;
	*ppos += nbytes;
	return nbytes;
	// return simple_read_from_buffer(buf, nbytes, ppos, ctr->buf, ctr->bufsz); // FIX! https://gitlab.eclipse.org/idlethread/linux/-/commit/c23e7e4c94647c2c47d2c835b21cc7d745f62d05
}

#include "memory.h"
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) 
{
  __AFL_INIT();
	
  // handle SECRET
  initHeapMemFillBuf(HEAP_MEM_IN, HEAP_MEM_LEN);
  
  // handle PUBLIC
  
  static size_t nbytes = 0;
  static loff_t ppos = 0;
  if (EXPLICIT_PUBLIC_LEN < sizeof(nbytes) + sizeof(ppos) + 4) {
    return 1;
  }
  
  static int pos = 0;
  nbytes = *(size_t *)EXPLICIT_PUBLIC_IN; 
  pos += sizeof(nbytes);
  ppos = *(loff_t *)(EXPLICIT_PUBLIC_IN + pos);
  pos += sizeof(ppos);
  
  static struct ctr_struct internal_structure = {}; 
  static int bufsz;
  bufsz = EXPLICIT_PUBLIC_LEN - pos;
  internal_structure.bufsz = bufsz;
  internal_structure.buf = malloc(bufsz);
  memcpy(internal_structure.buf, EXPLICIT_PUBLIC_IN + pos, bufsz);
  static struct file the_file = { .private_data = (void *)&internal_structure };
  
  // execute the function
  
  FILL_STACK(STACK_MEM_IN, STACK_MEM_LEN);
  cpuset_tasks_read(&the_file, NULL, nbytes, &ppos);
  
  return 0;
}

// #include "base64.h"

// int main() {
//         size_t nbytes = 2;
//         loff_t ppos = 1;

// 	char buf[sizeof(nbytes) + sizeof(ppos) + 4];
//         memcpy(buf, &nbytes, sizeof(nbytes));
//         int pos = sizeof(nbytes);
//         memcpy(buf + pos, &ppos, sizeof(ppos));
//         pos += sizeof(ppos);
//         int file_contents = 0xAABB0743;
//         memcpy(buf + pos, &file_contents, sizeof(file_contents));

// 	int enc_len = Base64encode_len(sizeof(buf));
// 	char *encoded = malloc(enc_len);
// 	int res = Base64encode(encoded, buf, sizeof(buf));
//         printf("{\n  \"PUBLIC\": \"");
// 	for (int i = 0; i < res; i++) {
// 		printf("%c", encoded[i]);
// 	}
//         printf("\",\n  \"SECRET\": \"MDAwMA==\"\n}\n");
// 	printf("\npredicted len: %d, actual: %d\n", enc_len, res);
// }
