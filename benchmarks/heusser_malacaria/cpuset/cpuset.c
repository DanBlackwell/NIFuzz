#include <sys/types.h>
#include <stdio.h>

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
	for (size_t i = 0; i < size; i++) {
		printf("%hhx", ((char *)kernel_buf)[i]);
	}
	printf("\n");
}

ssize_t simple_read_from_buffer(void /*__user*/ *to, size_t count, loff_t *ppos,
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

static ssize_t cpuset_tasks_read(struct file *file, char /*__user*/ *buf,
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


