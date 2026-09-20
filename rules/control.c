/* control.c - one instance of every pattern rules/security.cocci looks for
 *
 * This file is never compiled and never linked.  It exists so that
 * rules/run.sh can tell a rule that found nothing from a rule that is
 * broken: every rule in rules/security.cocci has to report at least one
 * line here.  Add the counter-example here in the same commit that adds a
 * rule, and write it so it looks like the code it is meant to catch.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define MAXVIFS   32
#define NO_VIF    ((uint16_t)MAXVIFS)
#define PIM_FOO   0x01

struct uvif { uint32_t uv_lcl_addr; };
extern struct uvif uvifs[MAXVIFS];
extern uint16_t numvifs;
extern char s1[46], s2[46];

char *inet_fmt(uint32_t addr, char *buf, size_t len);
void logit(int severity, int syserr, const char *fmt, ...);
uint16_t find_vif_direct(uint32_t src);

/* Copy and buffer hygiene */
void ctl_copy(char *dst, const char *src, struct uvif *v)
{
	strncpy(dst, src, sizeof(dst));		/* strncpy_unterminated, sizeof_pointer */
	memset(v, 0, sizeof(v));		/* sizeof_pointer */
	strcpy(dst, src);			/* unbounded_copy */
	memset(v, sizeof(*v), 0);		/* memset_swapped */
}

/* Allocation */
struct uvif *ctl_alloc(void)
{
	struct uvif *v;

	v = malloc(sizeof(v));			/* alloc_sizeof_pointer */

	return v;
}

/* An allocation used before it was checked */
int ctl_unchecked_alloc(int n)
{
	struct uvif *v = malloc(sizeof(*v));	/* unchecked_alloc */
	uint32_t *tab;

	tab = calloc(n, sizeof(*tab));
	tab[0] = v->uv_lcl_addr;		/* unchecked_alloc */

	return (int)tab[0];
}

/* Format strings */
void ctl_format(FILE *fp, const char *user)
{
	char buf[64];

	printf(user);				/* fmt_printf */
	fprintf(fp, user);			/* fmt_fprintf */
	snprintf(buf, sizeof(buf), user);	/* fmt_sized */
	logit(0, 0, user);			/* fmt_sized */

	/* The same calls done right: a literal format, the input as an
	 * argument.  Neither of these may be reported.
	 */
	printf("%s", user);
	fprintf(fp, "%s", user);
	snprintf(buf, sizeof(buf), "%s", user);
	logit(0, 0, "%s", buf);
}

/* Integer and conversion hazards */
uint32_t ctl_byteorder(void)
{
	uint32_t wide = 1;
	uint16_t narrow = 2;
	uint16_t small;

	small = ntohl(wide);			/* truncating_store */

	return ntohs(wide) + htonl(narrow) + small;	/* byteorder_wide, byteorder_narrow */
}

/* Expression and control-flow mistakes */
int ctl_expr(int a, int b, int flags)
{
	int x;

	if (x = a)				/* assign_in_cond */
		return 0;
	if (!flags & PIM_FOO)			/* bang_precedence */
		return 1;
	if (flags & PIM_FOO == 0)		/* cmp_precedence */
		return 2;
	if (a > 0 || b > 0 || a > 0)		/* dup_operand */
		return 3;
	if (a == b)				/* dup_elseif */
		return 4;
	else if (a == b)
		return 5;
	if (a < b)				/* same_branches */
		return 6;
	else
		return 6;
	if (a == a)				/* self_compare */
		return 7;
	a = a;					/* self_assign */

	return a;
}

/* pimd's own idioms */
void ctl_idioms(uint32_t src, uint32_t grp)
{
	uint16_t vifi;

	logit(0, 0, "%s -> %s", inet_fmt(src, s1, sizeof(s1)),
	      inet_fmt(grp, s1, sizeof(s1)));	/* inetfmt_alias */
	logit(0, 0, "%s", inet_fmt(src, s1, sizeof(s2)));	/* inetfmt_mismatch */

	vifi = find_vif_direct(src);
	logit(0, 0, "%s", inet_fmt(uvifs[vifi].uv_lcl_addr, s1, sizeof(s1)));	/* unchecked_vif */
}

/* A handler that parses without bounding first */
int receive_pim_control(uint32_t src, uint32_t dst, char *msg, size_t len)
{
	uint8_t type = msg[8];			/* unbounded_handler */

	(void)src; (void)dst; (void)len;

	return type;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
