/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Minimal, self-contained definitions for the policy program.
 *
 * The program only needs a handful of UAPI constants and helpers, so they are
 * declared here instead of pulling in kernel or libbpf headers. That keeps the
 * object file reproducible with nothing but clang installed, independent of the
 * distribution's linux-libc-dev and libbpf-dev versions.
 */
#ifndef MNP_BPF_H
#define MNP_BPF_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
typedef __u16 __be16;
typedef __u32 __be32;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

/* BTF-style map definition helpers (same shape as libbpf's bpf_helpers.h). */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LPM_TRIE = 11,
};

#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_ANY 0
#define BPF_NOEXIST 1

/* Return codes of a TCX program (include/uapi/linux/bpf.h, enum tcx_action_base). */
#define TCX_NEXT -1
#define TCX_PASS 0
#define TCX_DROP 2

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
};

/* Helper IDs from include/uapi/linux/bpf.h (___BPF_FUNC_MAPPER). */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;

#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_HOPOPTS 0
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ICMPV6 58
#define IPPROTO_NONE 59
#define IPPROTO_DSTOPTS 60
#define IPPROTO_SCTP 132

#endif /* MNP_BPF_H */
