/*
 * linux/kernel/seccomp.c
 *
 * Copyright 2004-2005  Andrea Arcangeli <andrea@cpushare.com>
 *
 * Copyright (C) 2012 Google, Inc.
 * Will Drewry <wad@chromium.org>
 *
 * This defines a simple but solid secure-computing facility.
 *
 * Mode 1 uses a fixed list of allowed system calls.
 * Mode 2 allows user-defined system call filters in the form
 *        of Berkeley Packet Filters/Linux Socket Filters.
 */

#include <linux/atomic.h>
#include <linux/audit.h>
#include <linux/compat.h>
#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <asm/syscall.h>

/* #define SECCOMP_DEBUG 1 */

#ifdef CONFIG_SECCOMP_FILTER
/**
 * struct seccomp_filter - container for seccomp BPF programs
 *
 * @usage: reference count to manage the object liftime.
 *         get/put helpers should be used when accessing an instance
 *         outside of a lifetime-guarded section.  In general, this
 *         is only needed for handling filters shared across tasks.
 * @prev: points to a previously installed, or inherited, filter
 * @insns: the BPF program instructions to evaluate
 * @len: the number of instructions in the program
 *
 * seccomp_filter objects are organized in a tree linked via the @prev
 * pointer.  For any task, it appears to be a singly-linked list starting
 * with current->seccomp.filter, the most recently attached or inherited filter.
 * However, multiple filters may share a @prev node, by way of fork(), which
 * results in a unidirectional tree existing in memory.  This is similar to
 * how namespaces work.
 *
 * seccomp_filter objects should never be modified after being attached
 * to a task_struct (other than @usage).
 */
struct seccomp_filter {
	atomic_t usage;
	struct seccomp_filter *prev;
	unsigned short len;  /* Instruction count */
	struct sock_filter insns[];
};

/* Limit any path through the tree to 5 megabytes worth of instructions. */
#define MAX_INSNS_PER_PATH ((5 << 20) / sizeof(struct sock_filter))

static void seccomp_filter_log_failure(int syscall)
{
	int compat = 0;
#ifdef CONFIG_COMPAT
	compat = is_compat_task();
#endif
	pr_info("%s[%d]: %ssystem call %d blocked at 0x%lx\n",
		current->comm, task_pid_nr(current),
		(compat ? "compat " : ""),
		syscall, KSTK_EIP(current));
}

/**
 * get_u32 - returns a u32 offset into data
 * @data: a unsigned 64 bit value
 * @index: 0 or 1 to return the first or second 32-bits
 *
 * This inline exists to hide the length of unsigned long.
 * If a 32-bit unsigned long is passed in, it will be extended
 * and the top 32-bits will be 0. If it is a 64-bit unsigned
 * long, then whatever data is resident will be properly returned.
 */
static inline u32 get_u32(u64 data, int index)
{
	return ((u32 *)&data)[index];
}

/* Helper for bpf_load below. */
#define BPF_DATA(_name) offsetof(struct seccomp_data, _name)
/**
 * bpf_load: checks and returns a pointer to the requested offset
 * @nr: int syscall passed as a void * to bpf_run_filter
 * @off: offset into struct seccomp_data to load from (must be u32 aligned)
 * @size: number of bytes to load (must be 4 bytes)
 * @buf: temporary storage supplied by bpf_run_filter (4 bytes)
 *
 * Returns a pointer to the loaded data (usually @buf).
 * On failure, returns NULL.
 */
static void *bpf_load(const void *nr, int off, unsigned int size, void *buf)
{
	unsigned long value;
	u32 *A = buf;

	if (size != sizeof(u32) || off % sizeof(u32))
		return NULL;

	if (off >= BPF_DATA(args[0]) && off < BPF_DATA(args[6])) {
		struct pt_regs *regs = task_pt_regs(current);
		int arg = (off - BPF_DATA(args[0])) / sizeof(u64);
		int index = (off % sizeof(u64)) ? 1 : 0;
		syscall_get_arguments(current, regs, arg, 1, &value);
		*A = get_u32(value, index);
	} else if (off == BPF_DATA(nr)) {
		*A = (u32)(uintptr_t)nr;
	} else if (off == BPF_DATA(arch)) {
		struct pt_regs *regs = task_pt_regs(current);
		*A = syscall_get_arch(current, regs);
	} else if (off == BPF_DATA(instruction_pointer)) {
		*A = get_u32(KSTK_EIP(current), 0);
	} else if (off == BPF_DATA(instruction_pointer) + sizeof(u32)) {
		*A = get_u32(KSTK_EIP(current), 1);
	} else {
		return NULL;
	}
	return buf;
}

/**
 * seccomp_run_filters - evaluates all seccomp filters against @syscall
 * @syscall: number of the current system call
 *
 * Returns valid seccomp BPF response codes.
 */
static u32 seccomp_run_filters(int syscall)
{
	struct seccomp_filter *f;
	static const struct bpf_load_fn fns = {
		bpf_load,
		sizeof(struct seccomp_data),
	};
	u32 ret = SECCOMP_RET_ALLOW;
	const void *sc_ptr = (const void *)(uintptr_t)syscall;

	/* Ensure unexpected behavior doesn't result in failing open. */
	if (WARN_ON(current->seccomp.filter == NULL))
		return SECCOMP_RET_KILL;

	/*
	 * All filters are evaluated in order of youngest to oldest. The lowest
	 * BPF return value (ignoring the DATA) always takes priority.
	 */
	for (f = current->seccomp.filter; f; f = f->prev) {
		u32 cur_ret = bpf_run_filter(sc_ptr, f->insns, &fns);
		if ((cur_ret & SECCOMP_RET_ACTION) < (ret & SECCOMP_RET_ACTION))
			ret = cur_ret;
	}
	return ret;
}

/**
 * seccomp_attach_filter: Attaches a seccomp filter to current.
 * @fprog: BPF program to install
 *
 * Returns 0 on success or an errno on failure.
 */
static long seccomp_attach_filter(struct sock_fprog *fprog)
{
	struct seccomp_filter *filter;
	unsigned long fp_size = fprog->len * sizeof(struct sock_filter);
	unsigned long total_insns = fprog->len;
	long ret;

	if (fprog->len == 0 || fprog->len > BPF_MAXINSNS)
		return -EINVAL;

	/* Walk the list to ensure the new instruction count is allowed. */
	for (filter = current->seccomp.filter; filter; filter = filter->prev) {
		if (total_insns > MAX_INSNS_PER_PATH - filter->len)
			return -E2BIG;
		total_insns += filter->len;
	}

	/* Allocate a new seccomp_filter */
	filter = kzalloc(sizeof(struct seccomp_filter) + fp_size, GFP_KERNEL);
	if (!filter)
		return -ENOMEM;
	atomic_set(&filter->usage, 1);
	filter->len = fprog->len;

	/* Copy the instructions from fprog. */
	ret = -EFAULT;
	if (copy_from_user(filter->insns, fprog->filter, fp_size))
		goto out;

	/* Check the fprog */
	ret = bpf_chk_filter(filter->insns, filter->len, BPF_CHK_FLAGS_NO_SKB);
	if (ret)
		goto out;

	/*
	 * Installing a seccomp filter requires that the task have
	 * CAP_SYS_ADMIN in its namespace or be running with no_new_privs.
	 * This avoids scenarios where unprivileged tasks can affect the
	 * behavior of privileged children.
	 */
	ret = -EACCES;
	if (!current->no_new_privs &&
	    security_capable_noaudit(current_cred(), current_user_ns(),
				     CAP_SYS_ADMIN) != 0)
		goto out;

	/*
	 * If there is an existing filter, make it the prev and don't drop its
	 * task reference.
	 */
	filter->prev = current->seccomp.filter;
	current->seccomp.filter = filter;
	return 0;
out:
	put_seccomp_filter(filter);  /* for get or task, on err */
	return ret;
}

/**
 * seccomp_attach_user_filter - attaches a user-supplied sock_fprog
 * @user_filter: pointer to the user data containing a sock_fprog.
 *
 * Returns 0 on success and non-zero otherwise.
 */
long seccomp_attach_user_filter(char __user *user_filter)
{
	struct sock_fprog fprog;
	long ret = -EFAULT;

	if (!user_filter)
		goto out;
#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		struct compat_sock_fprog fprog32;
		if (copy_from_user(&fprog32, user_filter, sizeof(fprog32)))
			goto out;
		fprog.len = fprog32.len;
		fprog.filter = compat_ptr(fprog32.filter);
	} else /* falls through to the if below. */
#endif
	if (copy_from_user(&fprog, user_filter, sizeof(fprog)))
		goto out;
	ret = seccomp_attach_filter(&fprog);
out:
	return ret;
}

/* get_seccomp_filter - increments the reference count of @orig. */
void get_seccomp_filter(struct seccomp_filter *orig)
{
	if (!orig)
		return;
	/* Reference count is bounded by the number of total processes. */
	atomic_inc(&orig->usage);
}

/* put_seccomp_filter - decrements the ref count of @orig and may free. */
void put_seccomp_filter(struct seccomp_filter *orig)
{
	/* Clean up single-reference branches iteratively. */
	while (orig && atomic_dec_and_test(&orig->usage)) {
		struct seccomp_filter *freeme = orig;
		orig = orig->prev;
		kfree(freeme);
	}
}

/**
 * seccomp_send_sigsys - signals the task to allow in-process syscall emulation
 * @syscall: syscall number to send to userland
 * @reason: filter-supplied reason code to send to userland (via si_errno)
 *
 * Forces a SIGSYS with a code of SYS_SECCOMP and related sigsys info.
 */
static void seccomp_send_sigsys(int syscall, int reason)
{
	struct siginfo info;
	memset(&info, 0, sizeof(info));
	info.si_signo = SIGSYS;
	info.si_code = SYS_SECCOMP;
	info.si_call_addr = (void __user *)KSTK_EIP(current);
	info.si_errno = reason;
	info.si_arch = syscall_get_arch(current, task_pt_regs(current));
	info.si_syscall = syscall;
	force_sig_info(SIGSYS, &info, current);
}
#endif	/* CONFIG_SECCOMP_FILTER */

/*
 * Secure computing mode 1 allows only read/write/exit/sigreturn.
 * To be fully secure this must be combined with rlimit
 * to limit the stack allocations too.
 */
static int mode1_syscalls[] = {
	__NR_seccomp_read, __NR_seccomp_write, __NR_seccomp_exit, __NR_seccomp_sigreturn,
	0, /* null terminated */
};

#ifdef CONFIG_COMPAT
static int mode1_syscalls_32[] = {
	__NR_seccomp_read_32, __NR_seccomp_write_32, __NR_seccomp_exit_32, __NR_seccomp_sigreturn_32,
	0, /* null terminated */
};
#endif

void __secure_computing(int this_syscall)
{
	/* Filter calls should never use this function. */
	BUG_ON(current->seccomp.mode == SECCOMP_MODE_FILTER);
	__secure_computing_int(this_syscall);
}

int __secure_computing_int(int this_syscall)
{
	int mode = current->seccomp.mode;
	int exit_code = SIGKILL;
	int *syscall;

	switch (mode) {
	case SECCOMP_MODE_STRICT:
		syscall = mode1_syscalls;
#ifdef CONFIG_COMPAT
		if (is_compat_task())
			syscall = mode1_syscalls_32;
#endif
		do {
			if (*syscall == this_syscall)
				return 0;
		} while (*++syscall);
		break;
#ifdef CONFIG_SECCOMP_FILTER
	case SECCOMP_MODE_FILTER: {
		u32 action = seccomp_run_filters(this_syscall);
		switch (action & SECCOMP_RET_ACTION) {
		case SECCOMP_RET_ERRNO:
			/* Set the low-order 16-bits as a errno. */
			syscall_set_return_value(current, task_pt_regs(current),
						 -(action & SECCOMP_RET_DATA),
						 0);
			return -1;
		case SECCOMP_RET_TRAP:
			/* Show the handler the original registers. */
			syscall_rollback(current, task_pt_regs(current));
			/* Let the filter pass back 16 bits of data. */
			seccomp_send_sigsys(this_syscall,
					    action & SECCOMP_RET_DATA);
			return -1;
		case SECCOMP_RET_TRACE:
			/* Skip these calls if there is no tracer. */
			if (!ptrace_event_enabled(current,
						  PTRACE_EVENT_SECCOMP))
				return -1;
			/* Allow the BPF to provide the event message */
			ptrace_event(PTRACE_EVENT_SECCOMP,
				     action & SECCOMP_RET_DATA);
			if (fatal_signal_pending(current))
				break;
			return 0;
		case SECCOMP_RET_ALLOW:
			return 0;
		case SECCOMP_RET_KILL:
		default:
			break;
		}
		seccomp_filter_log_failure(this_syscall);
		exit_code = SIGSYS;
		break;
	}
#endif
	default:
		BUG();
	}

#ifdef SECCOMP_DEBUG
	dump_stack();
#endif
	audit_seccomp(this_syscall);
	do_exit(exit_code);
	return -1;	/* never reached */
}

long prctl_get_seccomp(void)
{
	return current->seccomp.mode;
}

/**
 * prctl_set_seccomp: configures current->seccomp.mode
 * @seccomp_mode: requested mode to use
 * @filter: optional struct sock_fprog for use with SECCOMP_MODE_FILTER
 *
 * This function may be called repeatedly with a @seccomp_mode of
 * SECCOMP_MODE_FILTER to install additional filters.  Every filter
 * successfully installed will be evaluated (in reverse order) for each system
 * call the task makes.
 *
 * Once current->seccomp.mode is non-zero, it may not be changed.
 *
 * Returns 0 on success or -EINVAL on failure.
 */
long prctl_set_seccomp(unsigned long seccomp_mode, char __user *filter)
{
	long ret = -EINVAL;

	if (current->seccomp.mode &&
	    current->seccomp.mode != seccomp_mode)
		goto out;

	switch (seccomp_mode) {
	case SECCOMP_MODE_STRICT:
		ret = 0;
#ifdef TIF_NOTSC
		disable_TSC();
#endif
		break;
#ifdef CONFIG_SECCOMP_FILTER
	case SECCOMP_MODE_FILTER:
		ret = seccomp_attach_user_filter(filter);
		if (ret)
			goto out;
		break;
#endif
	default:
		goto out;
	}

	current->seccomp.mode = seccomp_mode;
	set_thread_flag(TIF_SECCOMP);
out:
	return ret;
}
