/*
 * Shared library add-on to iptables to add SB6183 target support.
 * Copyright (c) 2007 Sven Schnelle <svens@bitebene.org>
 * Copyright © CC Computer Consultants GmbH, 2007
 * Jan Engelhardt <jengelh@computergmbh.de>
 */
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <netinet/tcp.h>

#include "xt_SB6183.h"

static const struct xt_option_entry sb6183_tg_opts[] = {
	XTOPT_TABLEEND,
};

static void sb6183_tg_help(void)
{
	printf( "SB6183 target options (none)\n");
}

static void sb6183_tg_parse(struct xt_option_call *cb)
{
	struct xt_sb6183_target_info *info = cb->data;

	xtables_option_parse(cb);
}

static void
sb6183_tg_print(const void *ip, const struct xt_entry_target *target,
                     int numeric)
{
}

static void
sb6183_tg_save(const void *ip, const struct xt_entry_target *target)
{
}

static struct xtables_target sb6183_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "SB6183",
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_sb6183_target_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_sb6183_target_info)),
	.help          = sb6183_tg_help,
	.print         = sb6183_tg_print,
	.save          = sb6183_tg_save,
	.x6_parse      = sb6183_tg_parse,
	.x6_options    = sb6183_tg_opts,
};

void _init(void)
{
	xtables_register_target(&sb6183_tg_reg);
}
