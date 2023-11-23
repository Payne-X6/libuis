#pragma once

#define __bpf_printk(fmt, ...)					\
({												\
	BPF_PRINTK_FMT_MOD char ____fmt[] = fmt;	\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);					\
})

/*
 * __bpf_vprintk wraps the bpf_trace_vprintk helper with variadic arguments
 * instead of an array of u64.
 */
#define __bpf_vprintk(fmt, args...)						\
({														\
	static const char ___fmt[] = fmt;					\
	unsigned long long ___param[___bpf_narg(args)];		\
														\
	_Pragma("GCC diagnostic push")						\
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")	\
	___bpf_fill(___param, args);						\
	_Pragma("GCC diagnostic pop")						\
														\
	bpf_trace_vprintk(___fmt, sizeof(___fmt),			\
			  ___param, sizeof(___param));				\
})

/* Use __bpf_printk when bpf_printk call has 3 or fewer fmt args
 * Otherwise use __bpf_vprintk
 */
#define ___bpf_pick_printk(...) \
	___bpf_nth(_, ##__VA_ARGS__, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,	\
		   __bpf_vprintk, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,		\
		   __bpf_vprintk, __bpf_vprintk, __bpf_printk /*3*/, __bpf_printk /*2*/,\
		   __bpf_printk /*1*/, __bpf_printk /*0*/)

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, args...) ___bpf_pick_printk(args)(fmt, ##args)