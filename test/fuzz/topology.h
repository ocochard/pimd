/*
 * topology - the router a harness fabricates around the parsers
 *
 * Copyright (c) 2026  Olivier Cochard-Labbe <olivier@cochard.me>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * Two interfaces, three neighbors, one host that has sent no Hello, one
 * group and one source, all in host order: every address a harness has to
 * agree with its own MRIB (fuzz/mrib.c) about.  A router this small is
 * still every shape the protocol code asks about -- two links to pick an
 * incoming interface between, two neighbors on one of them so a DR
 * election and an assert have someone to run against, a neighbor on the
 * other so a Join can arrive from somewhere the source is not, and an
 * address on a subnet of ours that never said Hello, which is what RFC
 * 7761 sec. 4.5 has the Join/Prune and Assert paths refuse.
 *
 * Two groups for the same reason there are two links: this router is the RP
 * for one of them and a neighbor is the RP for the other, so both sides of
 * every test of "am I the RP for this" have a group to be asked about.
 */

#ifndef PIMD_FUZZ_TOPOLOGY_H_
#define PIMD_FUZZ_TOPOLOGY_H_

/* Vif 0 is the register vif, PIMREG_VIF, on this router as on any other.
 * Each physical vif is given its own index as its kernel interface index, so
 * that one number is both: find_vif() looks a packet's ifindex up and
 * find_vif_direct() looks its source address up, and a harness that has to
 * name an interface can pass either without the two disagreeing.
 */
#define FUZZ_VIF0		1
#define FUZZ_VIF1		2
#define FUZZ_NUMVIFS		3

#define FUZZ_MASK24		0xffffff00
#define FUZZ_MASK24_LEN		24

#define FUZZ_IF0_NAME		"fz0"
#define FUZZ_IF0_NET		0x0a000100	/* 10.0.1.0/24 */
#define FUZZ_IF0_ADDR		0x0a000101	/* 10.0.1.1, and the RP */
#define FUZZ_NBR0_ADDR		0x0a000102	/* 10.0.1.2, and the next hop */
#define FUZZ_NBR1_ADDR		0x0a000103	/* 10.0.1.3 */
#define FUZZ_STRANGER_ADDR	0x0a000104	/* 10.0.1.4, no Hello of its own */

#define FUZZ_IF1_NAME		"fz1"
#define FUZZ_IF1_NET		0x0a000200	/* 10.0.2.0/24 */
#define FUZZ_IF1_ADDR		0x0a000201	/* 10.0.2.1 */
#define FUZZ_NBR2_ADDR		0x0a000202	/* 10.0.2.2 */

#define FUZZ_GROUP		0xef010101	/* 239.1.1.1, this router is the RP */
#define FUZZ_GROUP2		0xef020304	/* 239.2.3.4, the neighbor is */
#define FUZZ_SOURCE		0x0a000109	/* 10.0.1.9, on the first link */

/* What fuzz/mrib.c answers with, the two numbers an assert compares */
#define FUZZ_METRIC_CONNECTED	1
#define FUZZ_METRIC_REMOTE	1024

#endif /* PIMD_FUZZ_TOPOLOGY_H_ */
