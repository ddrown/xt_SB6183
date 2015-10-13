/*
 * A module for rewiring TCP Timestamp options to work around a bug in the
 * SB6183 cable modem
 *
 * Copyright (C) 2015 Dan Drown <dan-github@drown.org>
 * Copyright (C) 2007 Sven Schnelle <svens@bitebene.org>
 * Copyright © CC Computer Consultants GmbH, 2007
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <linux/netfilter/x_tables.h>

#include "xt_SB6183.h"

static inline unsigned int optlen(const u_int8_t *opt, unsigned int offset)
{
	/* Beware zero-length options: make finite progress */
	if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0)
		return 1;
	else
		return opt[offset+1];
}

static unsigned int
sb6183_mangle_packet(struct sk_buff *skb,
			  const struct xt_action_param *par,
			  unsigned int tcphoff, unsigned int minlen)
{
	unsigned int optl, i;
	struct tcphdr *tcph;
	u_int16_t n, o;
	u_int8_t *opt;
	int len, tcp_hdrlen;

	/* This is a fragment, no TCP header is available */
	if (par->fragoff != 0)
		return XT_CONTINUE;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	len = skb->len - tcphoff;
	if (len < (int)sizeof(struct tcphdr))
		return NF_DROP;

	tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
	tcp_hdrlen = tcph->doff * 4;

	if (len < tcp_hdrlen)
		return NF_DROP;

	opt  = (u_int8_t *)tcph;

	for (i = sizeof(struct tcphdr); i < tcp_hdrlen - 1; i += optl) {
		optl = optlen(opt, i);

		if (i + optl > tcp_hdrlen)
			break;

		if (opt[i] != TCPOPT_TIMESTAMP)
			continue;

                o = opt[i];
                n = 253; // TCPOPT_EXPERIMENTAL
                if(i % 2 == 0) {
                        o <<= 8;
                        n <<= 8;
                }
                inet_proto_csum_replace2(&tcph->check, skb, htons(o), htons(n), 0);
                opt[i] = 253;
	}

	return XT_CONTINUE;
}

static unsigned int
sb6183_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	return sb6183_mangle_packet(skb, par, ip_hdrlen(skb),
	       sizeof(struct iphdr) + sizeof(struct tcphdr));
}

#if IS_ENABLED(CONFIG_IP6_NF_MANGLE)
static unsigned int
sb6183_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	int tcphoff;
	u_int8_t nexthdr;
	__be16 frag_off;

	nexthdr = ipv6h->nexthdr;
	tcphoff = ipv6_skip_exthdr(skb, sizeof(*ipv6h), &nexthdr, &frag_off);
	if (tcphoff < 0)
		return NF_DROP;

	return sb6183_mangle_packet(skb, par, tcphoff,
	       sizeof(*ipv6h) + sizeof(struct tcphdr));
}
#endif

static struct xt_target sb6183_tg_reg[] __read_mostly = {
	{
		.name       = "SB6183",
		.family     = NFPROTO_IPV4,
		.table      = "mangle",
		.proto      = IPPROTO_TCP,
		.target     = sb6183_tg4,
		.targetsize = sizeof(struct xt_sb6183_target_info),
		.me         = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_MANGLE)
	{
		.name       = "SB6183",
		.family     = NFPROTO_IPV6,
		.table      = "mangle",
		.proto      = IPPROTO_TCP,
		.target     = sb6183_tg6,
		.targetsize = sizeof(struct xt_sb6183_target_info),
		.me         = THIS_MODULE,
	},
#endif
};

static int __init sb6183_tg_init(void)
{
	return xt_register_targets(sb6183_tg_reg,
				   ARRAY_SIZE(sb6183_tg_reg));
}

static void __exit sb6183_tg_exit(void)
{
	xt_unregister_targets(sb6183_tg_reg,
			      ARRAY_SIZE(sb6183_tg_reg));
}

module_init(sb6183_tg_init);
module_exit(sb6183_tg_exit);
MODULE_AUTHOR("Dan Drown <dan-github@drown.org>, Sven Schnelle <svens@bitebene.org>, Jan Engelhardt <jengelh@medozas.de>");
MODULE_DESCRIPTION("Xtables: TCP timestamp option rewrite (SB6183 bug)");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_SB6183");
MODULE_ALIAS("ip6t_SB6183");
