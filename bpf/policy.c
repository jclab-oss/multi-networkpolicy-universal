// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * MultiNetworkPolicy enforcement for pods whose traffic bypasses netfilter.
 *
 * Sandboxed runtimes such as Kata Containers move packets between the CNI
 * interface in the pod network namespace and the VM with a TC mirred redirect
 * (internetworking_model "tcfilter") or a macvtap device on top of the CNI
 * interface ("macvtap"). Neither path traverses the netfilter input/output
 * hooks the nftables backend relies on, so the policy is enforced here instead,
 * on the CNI interface (tcfilter) or on the macvtap device (macvtap):
 *
 *   mnp_ingress  TCX ingress: traffic towards the pod. On the CNI interface it
 *                runs before the runtime's legacy tc filter; TCX_NEXT hands the
 *                packet on to that filter (the redirect into the VM).
 *   mnp_egress   TCX egress: traffic from the pod, which the runtime redirects
 *                out of the CNI interface or transmits on the macvtap device.
 *
 * One object is loaded per pod interface. Policy state lives in LPM tries that
 * map an address (or a protocol/port) to the set of policy rules it satisfies,
 * as a bitmap. A packet is allowed when some rule is satisfied by both its peer
 * address and its destination port:
 *
 *   (peer_bits | wild_peer) & (port_bits | wild_port) != 0
 *
 * The user space side compiles the tries so that the longest matching prefix
 * already carries the final bitmap, including ipBlock.except, and replaces the
 * whole object atomically through bpf_link_update when the policy changes.
 *
 * Connection tracking: packets on these paths never reach nf_conntrack, so
 * accepted flows are recorded in a shared LRU map. Later packets of the flow,
 * in either direction, are accepted without evaluating the policy, like the
 * "ct state established,related accept" rule of the nftables backend.
 */

#include "include/mnp_bpf.h"

#define MNP_RULE_WORDS 8 /* 512 rules per direction and interface */

#define DIR_INGRESS 0
#define DIR_EGRESS 1

#define CFG_F_ACCEPT_ICMP (1U << 0)
#define CFG_F_ACCEPT_ICMPV6 (1U << 1)

#define PEER_F_ALLOW_COMMON (1U << 0) /* --allow-src-prefix / --allow-dst-prefix */

#define FLOW_F_REPLIED (1U << 0)
#define FLOW_F_CLOSING (1U << 1)

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_RST 0x04

#define FRAG_NONE 0
#define FRAG_FIRST 1 /* offset 0, more fragments follow: carries the L4 header */
#define FRAG_LATER 2 /* offset != 0: no L4 header */

#define PARSE_OK 0
#define PARSE_NOT_IP 1   /* ARP and other non-IP traffic: never policed */
#define PARSE_VLAN 2     /* tagged frame: the tag hides the IP header */
#define PARSE_MALFORMED 3

#define IPV6_MAX_EXT_HEADERS 6

#define ECHO_NONE 0
#define ECHO_REQUEST 1
#define ECHO_REPLY 2

/* Which orientations of a tuple a flow lookup may match. */
#define FLOW_BOTH 0
#define FLOW_FORWARD 1 /* same direction as the packet that created the flow */
#define FLOW_REVERSE 2 /* replies */

struct rule_bits {
	__u64 w[MNP_RULE_WORDS];
};

struct dir_cfg {
	__u32 isolated; /* at least one policy selects this interface for the direction */
	__u32 pad;
	struct rule_bits wild_peer; /* rules without from/to: any peer */
	struct rule_bits wild_port; /* rules without ports: any protocol and port */
};

struct ep_cfg {
	__u64 ep_id; /* identifies the pod interface in the shared flow table */
	__u32 flags;
	__u32 pad;
	__u64 tcp_established_ns;
	__u64 tcp_transitory_ns; /* unanswered or closing TCP flows */
	__u64 other_established_ns;
	__u64 other_transitory_ns; /* unanswered non-TCP flows */
	__u64 frag_ns;
	struct dir_cfg dir[2];
};

struct lpm_v4_key {
	__u32 prefixlen;
	__u8 addr[4];
};

struct lpm_v6_key {
	__u32 prefixlen;
	__u8 addr[16];
};

/* prefixlen covers proto (8 bits) followed by the port in network order. */
struct lpm_port_key {
	__u32 prefixlen;
	__u8 proto;
	__u8 port[2];
	__u8 pad;
};

struct peer_val {
	struct rule_bits rules;
	__u32 flags;
	__u32 pad;
};

struct flow_key {
	__u64 ep_id;
	__u8 saddr[16];
	__u8 daddr[16];
	__be16 sport;
	__be16 dport;
	__u8 proto;
	__u8 family;
	__u16 pad;
};

struct flow_val {
	__u64 last_seen;
	__u32 flags;
	__u32 pad;
};

struct frag_key {
	__u64 ep_id;
	__u8 saddr[16];
	__u8 daddr[16];
	__u32 id;
	__u8 proto;
	__u8 family;
	__u16 pad;
};

/* Replaced by the loader before the object is loaded. */
volatile const struct ep_cfg cfg = {};

#define LPM_MAP(name, key_t, val_t)                                                                                    \
	struct {                                                                                                       \
		__uint(type, BPF_MAP_TYPE_LPM_TRIE);                                                                   \
		__uint(map_flags, BPF_F_NO_PREALLOC);                                                                  \
		__uint(max_entries, 1);                                                                                \
		__type(key, key_t);                                                                                    \
		__type(value, val_t);                                                                                  \
	} name SEC(".maps")

LPM_MAP(peer4_ingress, struct lpm_v4_key, struct peer_val);
LPM_MAP(peer4_egress, struct lpm_v4_key, struct peer_val);
LPM_MAP(peer6_ingress, struct lpm_v6_key, struct peer_val);
LPM_MAP(peer6_egress, struct lpm_v6_key, struct peer_val);
LPM_MAP(port_ingress, struct lpm_port_key, struct rule_bits);
LPM_MAP(port_egress, struct lpm_port_key, struct rule_bits);

/* Shared by every loaded object; the loader pins them and passes them in. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct frag_key);
	__type(value, __u64);
} frags SEC(".maps");

struct pkt {
	__u8 family; /* 4 or 6 */
	__u8 proto;
	__u8 frag;
	__u8 has_ports; /* sport/dport hold L4 ports */
	__u8 flowable;  /* the flow table may track this packet */
	__u8 icmp_error;
	__u8 tcp_flags;
	__u8 icmp_type;
	__u8 echo;       /* ECHO_*: ICMP echo request or reply */
	__u8 frag_proto; /* next header of the fragmented part, same in every fragment */
	__u16 pad;
	__u8 saddr[16];
	__u8 daddr[16];
	__be16 sport;
	__be16 dport;
	__u32 frag_id;
	__u32 l4_off;
	__u32 l3_end; /* end of the IP packet; bytes past it are padding */
};

static __always_inline void copy16(__u8 *dst, const __u8 *src)
{
#pragma unroll
	for (int i = 0; i < 16; i++)
		dst[i] = src[i];
}

static __always_inline void copy4(__u8 *dst, const __u8 *src)
{
#pragma unroll
	for (int i = 0; i < 4; i++)
		dst[i] = src[i];
}

static __always_inline int is_icmp4_error(__u8 type)
{
	/* destination unreachable, source quench, redirect, time exceeded, parameter problem */
	return type == 3 || type == 4 || type == 5 || type == 11 || type == 12;
}

static __always_inline int is_icmp6_error(__u8 type)
{
	/* destination unreachable, packet too big, time exceeded, parameter problem */
	return type >= 1 && type <= 4;
}

/*
 * Parse the transport header at p->l4_off. Only called for packets that carry
 * one, i.e. not for non-first fragments.
 */
static __always_inline int l4_fits(const struct pkt *p, __u32 len)
{
	return p->l4_off + len <= p->l3_end;
}

static __always_inline int parse_l4(struct __sk_buff *skb, struct pkt *p)
{
	__u8 l4[8];

	switch (p->proto) {
	case IPPROTO_TCP:
		if (!l4_fits(p, 14) || bpf_skb_load_bytes(skb, p->l4_off, l4, 4) < 0)
			return PARSE_MALFORMED;
		if (bpf_skb_load_bytes(skb, p->l4_off + 13, &p->tcp_flags, 1) < 0)
			return PARSE_MALFORMED;
		break;
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		if (!l4_fits(p, 4) || bpf_skb_load_bytes(skb, p->l4_off, l4, 4) < 0)
			return PARSE_MALFORMED;
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		if (!l4_fits(p, 8) || bpf_skb_load_bytes(skb, p->l4_off, l4, 8) < 0)
			return PARSE_MALFORMED;
		p->icmp_type = l4[0];
		/* echo request/reply are tracked by their identifier */
		if (p->proto == IPPROTO_ICMP) {
			p->icmp_error = is_icmp4_error(l4[0]);
			p->echo = l4[0] == 8 ? ECHO_REQUEST : l4[0] == 0 ? ECHO_REPLY : ECHO_NONE;
		} else {
			p->icmp_error = is_icmp6_error(l4[0]);
			p->echo = l4[0] == 128 ? ECHO_REQUEST : l4[0] == 129 ? ECHO_REPLY : ECHO_NONE;
		}
		p->flowable = p->echo != ECHO_NONE;
		if (p->flowable) {
			/* same value on both sides so the reversed key matches */
			__builtin_memcpy(&p->sport, &l4[4], 2);
			p->dport = p->sport;
		}
		return PARSE_OK;
	default:
		/* other protocols are tracked by address pair only */
		p->flowable = 1;
		return PARSE_OK;
	}
	__builtin_memcpy(&p->sport, &l4[0], 2);
	__builtin_memcpy(&p->dport, &l4[2], 2);
	p->has_ports = 1;
	p->flowable = 1;
	return PARSE_OK;
}

static __always_inline int parse_ipv4(struct __sk_buff *skb, struct pkt *p, __u32 off)
{
	__u8 h[20];

	if (bpf_skb_load_bytes(skb, off, h, sizeof(h)) < 0)
		return PARSE_MALFORMED;
	if ((h[0] >> 4) != 4)
		return PARSE_MALFORMED;
	__u32 ihl = (h[0] & 0x0f) * 4;
	if (ihl < 20)
		return PARSE_MALFORMED;

	p->family = 4;
	p->proto = h[9];
	p->frag_proto = h[9];
	copy4(p->saddr, &h[12]);
	copy4(p->daddr, &h[16]);
	p->l4_off = off + ihl;

	/* A total length of 0 marks a BIG TCP packet; take the skb's length. */
	__u32 tot_len = ((__u32)h[2] << 8) | h[3];
	if (tot_len == 0)
		p->l3_end = skb->len;
	else if (tot_len < ihl)
		return PARSE_MALFORMED;
	else
		p->l3_end = off + tot_len;

	__u16 frag_off = ((__u16)h[6] << 8) | h[7];
	if (frag_off & 0x1fff)
		p->frag = FRAG_LATER;
	else if (frag_off & 0x2000)
		p->frag = FRAG_FIRST;
	p->frag_id = ((__u32)h[4] << 8) | h[5];

	if (p->frag == FRAG_LATER)
		return PARSE_OK;
	return parse_l4(skb, p);
}

static __always_inline int parse_ipv6(struct __sk_buff *skb, struct pkt *p, __u32 off)
{
	__u8 h[40];

	if (bpf_skb_load_bytes(skb, off, h, sizeof(h)) < 0)
		return PARSE_MALFORMED;
	if ((h[0] >> 4) != 6)
		return PARSE_MALFORMED;

	p->family = 6;
	copy16(p->saddr, &h[8]);
	copy16(p->daddr, &h[24]);

	/* A payload length of 0 marks a jumbogram (BIG TCP); take the skb's length. */
	__u32 payload_len = ((__u32)h[4] << 8) | h[5];
	p->l3_end = payload_len ? off + 40 + payload_len : skb->len;

	__u8 next = h[6];
	__u32 cur = off + 40;

#pragma unroll
	for (int i = 0; i < IPV6_MAX_EXT_HEADERS; i++) {
		__u8 ext[8];

		switch (next) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			if (bpf_skb_load_bytes(skb, cur, ext, 2) < 0)
				return PARSE_MALFORMED;
			next = ext[0];
			cur += ((__u32)ext[1] + 1) * 8;
			continue;
		case 51: /* authentication header */
			if (bpf_skb_load_bytes(skb, cur, ext, 2) < 0)
				return PARSE_MALFORMED;
			next = ext[0];
			cur += ((__u32)ext[1] + 2) * 4;
			continue;
		case IPPROTO_FRAGMENT: {
			if (bpf_skb_load_bytes(skb, cur, ext, 8) < 0)
				return PARSE_MALFORMED;
			__u16 fo = ((__u16)ext[2] << 8) | ext[3];
			p->frag_id = ((__u32)ext[4] << 24) | ((__u32)ext[5] << 16) | ((__u32)ext[6] << 8) | ext[7];
			p->frag_proto = ext[0];
			next = ext[0];
			cur += 8;
			if (fo & 0xfff8) {
				p->frag = FRAG_LATER;
				p->proto = next;
				p->l4_off = cur;
				return PARSE_OK;
			}
			if (fo & 0x1)
				p->frag = FRAG_FIRST;
			continue;
		}
		default:
			p->proto = next;
			p->l4_off = cur;
			if (cur > p->l3_end)
				return PARSE_MALFORMED;
			return parse_l4(skb, p);
		}
	}
	/* extension header chain longer than we are willing to walk */
	return PARSE_MALFORMED;
}

static __always_inline int parse(struct __sk_buff *skb, struct pkt *p)
{
	__be16 proto;

	if (bpf_skb_load_bytes(skb, 12, &proto, sizeof(proto)) < 0)
		return PARSE_NOT_IP;
	switch (bpf_ntohs(proto)) {
	case ETH_P_IP:
		return parse_ipv4(skb, p, ETH_HLEN);
	case ETH_P_IPV6:
		return parse_ipv6(skb, p, ETH_HLEN);
	case ETH_P_8021Q:
	case ETH_P_8021AD:
		return PARSE_VLAN;
	default:
		return PARSE_NOT_IP;
	}
}

static __always_inline __u64 flow_timeout(const struct flow_key *k, const struct flow_val *v)
{
	if (k->proto == IPPROTO_TCP) {
		if ((v->flags & FLOW_F_REPLIED) && !(v->flags & FLOW_F_CLOSING))
			return cfg.tcp_established_ns;
		return cfg.tcp_transitory_ns;
	}
	if (v->flags & FLOW_F_REPLIED)
		return cfg.other_established_ns;
	return cfg.other_transitory_ns;
}

static __always_inline void flow_key_of(struct flow_key *k, __u8 family, __u8 proto, const __u8 *saddr,
					const __u8 *daddr, __be16 sport, __be16 dport)
{
	k->ep_id = cfg.ep_id;
	k->family = family;
	k->proto = proto;
	copy16(k->saddr, saddr);
	copy16(k->daddr, daddr);
	k->sport = sport;
	k->dport = dport;
}

/*
 * Look the tuple up in both orientations. A hit in the reverse orientation is
 * a reply and marks the flow as answered.
 */
static __always_inline struct flow_val *flow_find(struct flow_key *k, __u64 now)
{
	struct flow_val *v = bpf_map_lookup_elem(&flows, k);

	if (!v || now - v->last_seen > flow_timeout(k, v))
		return 0;
	return v;
}

static __always_inline int flow_lookup(__u8 family, __u8 proto, const __u8 *saddr, const __u8 *daddr, __be16 sport,
				       __be16 dport, __u8 tcp_flags, __u64 now, int mode)
{
	struct flow_key k = {};
	struct flow_val *v = 0;

	if (mode != FLOW_REVERSE) {
		flow_key_of(&k, family, proto, saddr, daddr, sport, dport);
		v = flow_find(&k, now);
	}
	if (!v) {
		if (mode == FLOW_FORWARD)
			return 0;
		flow_key_of(&k, family, proto, daddr, saddr, dport, sport);
		v = flow_find(&k, now);
		if (!v)
			return 0;
		v->flags |= FLOW_F_REPLIED;
	}
	if (proto == IPPROTO_TCP && (tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)))
		v->flags |= FLOW_F_CLOSING;
	v->last_seen = now;
	return 1;
}

static __always_inline void flow_create(const struct pkt *p, __u64 now)
{
	struct flow_key k = {};
	struct flow_val v = { .last_seen = now };

	flow_key_of(&k, p->family, p->proto, p->saddr, p->daddr, p->sport, p->dport);
	if (p->proto == IPPROTO_TCP && (p->tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)))
		v.flags |= FLOW_F_CLOSING;
	bpf_map_update_elem(&flows, &k, &v, BPF_ANY);
}

static __always_inline void frag_key_of(struct frag_key *k, const struct pkt *p)
{
	k->ep_id = cfg.ep_id;
	k->family = p->family;
	k->proto = p->frag_proto;
	k->id = p->frag_id;
	copy16(k->saddr, p->saddr);
	copy16(k->daddr, p->daddr);
}

static __always_inline void frag_record(const struct pkt *p, __u64 now)
{
	struct frag_key k = {};

	frag_key_of(&k, p);
	bpf_map_update_elem(&frags, &k, &now, BPF_ANY);
}

/* Non-first fragments carry no ports; they follow the verdict of the first one. */
static __always_inline int frag_accepted(const struct pkt *p, __u64 now)
{
	struct frag_key k = {};
	__u64 *seen;

	frag_key_of(&k, p);
	seen = bpf_map_lookup_elem(&frags, &k);
	if (!seen || now - *seen > cfg.frag_ns)
		return 0;
	*seen = now;
	return 1;
}

static __always_inline int addr_equal(const __u8 *a, const __u8 *b)
{
	__u8 diff = 0;

#pragma unroll
	for (int i = 0; i < 16; i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

/*
 * An ICMP error is related to an accepted flow when the packet it quotes
 * belongs to that flow and the error goes back to that packet's sender, like
 * conntrack's RELATED state. The error does not refresh the flow.
 */
static __always_inline int icmp_error_related(struct __sk_buff *skb, const struct pkt *p, __u64 now)
{
	__u8 saddr[16] = {}, daddr[16] = {};
	__be16 sport = 0, dport = 0;
	__u8 proto, l4[8];
	__u32 inner = p->l4_off + 8, l4_off;

	if (p->family == 4) {
		__u8 h[20];

		if (bpf_skb_load_bytes(skb, inner, h, sizeof(h)) < 0 || (h[0] >> 4) != 4)
			return 0;
		proto = h[9];
		copy4(saddr, &h[12]);
		copy4(daddr, &h[16]);
		l4_off = inner + (h[0] & 0x0f) * 4;
	} else {
		__u8 h[40];

		if (bpf_skb_load_bytes(skb, inner, h, sizeof(h)) < 0 || (h[0] >> 4) != 6)
			return 0;
		proto = h[6];
		copy16(saddr, &h[8]);
		copy16(daddr, &h[24]);
		l4_off = inner + 40;
	}

	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		if (bpf_skb_load_bytes(skb, l4_off, l4, 4) < 0)
			return 0;
		__builtin_memcpy(&sport, &l4[0], 2);
		__builtin_memcpy(&dport, &l4[2], 2);
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		if (bpf_skb_load_bytes(skb, l4_off, l4, 8) < 0)
			return 0;
		__builtin_memcpy(&sport, &l4[4], 2);
		dport = sport;
		break;
	default:
		break;
	}
	/* Without this, a quoted tuple of any flow would carry the error, and
	 * whatever follows it, to an arbitrary destination. */
	if (!addr_equal(p->daddr, saddr))
		return 0;

	struct flow_key k = {};

	flow_key_of(&k, p->family, proto, saddr, daddr, sport, dport);
	if (flow_find(&k, now))
		return 1;
	flow_key_of(&k, p->family, proto, daddr, saddr, dport, sport);
	return flow_find(&k, now) != 0;
}

static __always_inline int rules_intersect(const struct rule_bits *peer, const volatile struct rule_bits *wild_peer,
					   const struct rule_bits *port, const volatile struct rule_bits *wild_port)
{
	__u64 any = 0;

#pragma unroll
	for (int i = 0; i < MNP_RULE_WORDS; i++) {
		__u64 a = wild_peer->w[i], b = wild_port->w[i];

		if (peer)
			a |= peer->w[i];
		if (port)
			b |= port->w[i];
		any |= a & b;
	}
	return any != 0;
}

static __always_inline int policy_allows(const struct pkt *p, int dir)
{
	const volatile struct dir_cfg *dc = &cfg.dir[dir];
	const __u8 *peer_addr = dir == DIR_INGRESS ? p->saddr : p->daddr;
	struct peer_val *peer;
	struct rule_bits *port = 0;

	if (p->family == 4 && p->proto == IPPROTO_ICMP && (cfg.flags & CFG_F_ACCEPT_ICMP))
		return 1;
	if (p->family == 6 && p->proto == IPPROTO_ICMPV6) {
		if (cfg.flags & CFG_F_ACCEPT_ICMPV6)
			return 1;
		/* router/neighbor solicitation and advertisement keep IPv6 working */
		if (p->frag != FRAG_LATER && p->icmp_type >= 133 && p->icmp_type <= 136)
			return 1;
	}

	if (p->family == 4) {
		struct lpm_v4_key k = { .prefixlen = 32 };

		copy4(k.addr, peer_addr);
		peer = bpf_map_lookup_elem(dir == DIR_INGRESS ? (void *)&peer4_ingress : (void *)&peer4_egress, &k);
	} else {
		struct lpm_v6_key k = { .prefixlen = 128 };

		copy16(k.addr, peer_addr);
		peer = bpf_map_lookup_elem(dir == DIR_INGRESS ? (void *)&peer6_ingress : (void *)&peer6_egress, &k);
	}
	if (peer && (peer->flags & PEER_F_ALLOW_COMMON))
		return 1;

	if (p->has_ports) {
		struct lpm_port_key k = { .prefixlen = 24, .proto = p->proto };

		__builtin_memcpy(k.port, &p->dport, 2);
		port = bpf_map_lookup_elem(dir == DIR_INGRESS ? (void *)&port_ingress : (void *)&port_egress, &k);
	}

	return rules_intersect(peer ? &peer->rules : 0, &dc->wild_peer, port, &dc->wild_port);
}

static __always_inline int decide(struct __sk_buff *skb, int dir)
{
	struct pkt p = {};
	int isolated = cfg.dir[dir].isolated;
	int res = parse(skb, &p);
	__u64 now;

	if (res == PARSE_NOT_IP)
		return TCX_NEXT;
	if (res != PARSE_OK)
		return isolated ? TCX_DROP : TCX_NEXT;

	now = bpf_ktime_get_ns();

	if (p.frag == FRAG_LATER) {
		if (!isolated || frag_accepted(&p, now))
			return TCX_NEXT;
		return TCX_DROP;
	}

	int mode = p.echo == ECHO_REQUEST ? FLOW_FORWARD : p.echo == ECHO_REPLY ? FLOW_REVERSE : FLOW_BOTH;

	if (p.flowable && flow_lookup(p.family, p.proto, p.saddr, p.daddr, p.sport, p.dport, p.tcp_flags, now, mode))
		goto accept;
	if (p.icmp_error && icmp_error_related(skb, &p, now))
		goto accept;
	if (isolated && !policy_allows(&p, dir))
		return TCX_DROP;

	/*
	 * Record the flow even when this direction is not isolated: the reply
	 * travels the other direction, which may be. Interfaces no policy
	 * isolates record nothing, so they cannot fill the shared table. An echo
	 * reply never creates a flow; requests would match it.
	 */
	if (p.flowable && p.echo != ECHO_REPLY && (cfg.dir[DIR_INGRESS].isolated || cfg.dir[DIR_EGRESS].isolated))
		flow_create(&p, now);
accept:
	if (p.frag == FRAG_FIRST)
		frag_record(&p, now);
	return TCX_NEXT;
}

SEC("tcx/ingress")
int mnp_ingress(struct __sk_buff *skb)
{
	return decide(skb, DIR_INGRESS);
}

SEC("tcx/egress")
int mnp_egress(struct __sk_buff *skb)
{
	return decide(skb, DIR_EGRESS);
}

char __license[] SEC("license") = "Dual BSD/GPL";
