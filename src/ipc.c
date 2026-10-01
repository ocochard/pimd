/*
 * Copyright (c) 2018-2020  Joachim Wiberg <troglobit@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * IPC API:
 *    - text based for compat with any PIM daemon
 *    - required commands: HELP, SHOW, VERSION
 *
 * Client asks daemon for available commands with HELP (help sep. w/ two spaces)
 * Client can also send VERSION to get daemon version
 * Client can send SHOW to get general status overview
 *
 * Daemon requires commands to be EXACT MATCH, so the client must
 * translate any short-commands to the full command before sending
 * it to the daemon.
 */

#include <poll.h>		/* poll() in ipc_write() */
#include <sys/stat.h>		/* umask() */
#include "defs.h"

#define ENABLED(v) (v ? "Enabled" : "Disabled")

/* A candidacy pimd.conf asked for whose address has not turned up yet is
 * neither: it is configured, it is not speaking, and it starts on its own
 * when the interface it names appears.  See config_resolve_addrs()
 * (src/config.c). */
#define CANDIDACY(on, configured) ((on) ? "Enabled" : (configured) ? "Pending" : "Disabled")

static struct sockaddr_un sun;
static int ipc_socket = -1;
static int detail = 0;
static int json = 0;		/* "pimctl -j", a word check_modifiers() reads */

static int ipc_rows;		/* rows in the table being written	  */
static int ipc_items;		/* tables and values in the reply so far  */

/* Whether this reply is JSON, for the dumps that are not in this file */
int ipc_json(void)
{
	return json;
}

/* The string as JSON: the escapes RFC 8259 sec. 7 requires and no others,
 * with anything below a space written as \u00xx.  A byte above 0x7f goes
 * through as it stands -- what is printed here is addresses, interface
 * names and words of this file's own, none of which leave ASCII. */
static void ipc_json_str(FILE *fp, const char *str)
{
	putc('"', fp);
	for (; str && *str; str++) {
		switch (*str) {
		case '"':  fputs("\\\"", fp); break;
		case '\\': fputs("\\\\", fp); break;
		case '\n': fputs("\\n", fp);  break;
		case '\r': fputs("\\r", fp);  break;
		case '\t': fputs("\\t", fp);  break;
		default:
			if ((unsigned char)*str < 0x20)
				fprintf(fp, "\\u%04x", *str);
			else
				putc(*str, fp);
			break;
		}
	}
	putc('"', fp);
}

static void ipc_json_key(FILE *fp, const char *key)
{
	int sep = 0, first = 1;

	putc('"', fp);
	for (; *key; key++) {
		if (!isalnum((unsigned char)*key)) {
			sep = !first;	/* one underscore, and none leading */
			continue;
		}

		if (sep)
			putc('_', fp);
		putc(tolower((unsigned char)*key), fp);
		sep = 0;
		first = 0;
	}
	putc('"', fp);
}

/*
 * The head of a table: the title pimctl underlines, or in JSON the name of
 * the array its rows go in.  The headings come with the first row, so a
 * table nothing is in prints no header, which is what every one of these
 * did by hand before.
 */
void ipc_table(FILE *fp, const char *title, const char *name)
{
	ipc_rows = 0;

	if (json) {
		fprintf(fp, "%s  \"%s\": [", ipc_items++ ? ",\n" : "", name);
		return;
	}

	fprintf(fp, "%s_\n", title);
}

void ipc_row(FILE *fp, const struct ipc_field *row)
{
	const struct ipc_field *f;
	const char *sep = "";

	if (!json) {
		if (!ipc_rows) {
			for (f = row; f->key; f++)
				fprintf(fp, "%*s  ", f->width, f->key);
			fprintf(fp, "=\n");
		}

		for (f = row; f->key; f++) {
			switch (f->type) {
			case IPC_T_STR:
				fprintf(fp, "%*s  ", f->width, f->str ? f->str : "");
				break;

			case IPC_T_NUM:
				fprintf(fp, "%*lld  ", f->width, f->num);
				break;

			case IPC_T_NONE:
				fprintf(fp, "%*s  ", f->width, "N/A");
				break;
			}
		}
		fprintf(fp, "\n");
		ipc_rows++;

		return;
	}

	fprintf(fp, "%s\n    {", ipc_rows++ ? "," : "");
	for (f = row; f->key; f++, sep = ",") {
		fprintf(fp, "%s ", sep);
		ipc_json_key(fp, f->key);
		fputs(": ", fp);
		if (f->type == IPC_T_NUM)
			fprintf(fp, "%lld", f->num);
		else if (f->type == IPC_T_NONE)
			fputs("null", fp);
		else
			ipc_json_str(fp, f->str ? f->str : "");
	}
	fprintf(fp, " }");
}

void ipc_table_end(FILE *fp)
{
	if (json)
		fprintf(fp, "%s]", ipc_rows ? "\n  " : "");
}

/*
 * The other half of a reply: a single value, "Key : value" in a column of
 * its own where a table would have had rows.  "show status" is all of
 * these, and a section of it is a prefix rather than an object, so that
 * every value of the reply is one key a script can ask for: the "Address"
 * under "Elected BSR" is .elected_bsr_address.
 *
 * The column is one wider than the longest label any of them has, so that
 * every ':' lines up and every one of them has a space in front of it --
 * "Number of Cache MIRRORs" is the long one, and a reader that tells a
 * value from a table row by the " : " in it would have no space there.
 */
#define IPC_KV_COL	24

static const char *ipc_sect;	/* the section the next values are in, or NULL */

static void ipc_section(FILE *fp, const char *title)
{
	ipc_sect = title;

	if (!json && title)
		fprintf(fp, "%s\n", title);
}

static void ipc_kv(FILE *fp, const char *key)
{
	char buf[80];
	int indent;

	if (!json) {
		indent = ipc_sect ? 4 : 0;
		fprintf(fp, "%*s%-*s: ", indent, "", IPC_KV_COL - indent, key);
		return;
	}

	fprintf(fp, "%s  ", ipc_items++ ? ",\n" : "");
	if (ipc_sect) {
		snprintf(buf, sizeof(buf), "%s %s", ipc_sect, key);
		key = buf;
	}
	ipc_json_key(fp, key);
	fputs(": ", fp);
}

/* In JSON the separator of the next value ends this one */
static void ipc_kv_end(FILE *fp)
{
	if (!json)
		putc('\n', fp);
}

/* A NULL value is one this router has not got, as IPC_NA is in a table */
static void ipc_kv_str(FILE *fp, const char *key, const char *val)
{
	ipc_kv(fp, key);
	if (!val)
		fputs(json ? "null" : "N/A", fp);
	else if (json)
		ipc_json_str(fp, val);
	else
		fputs(val, fp);
	ipc_kv_end(fp);
}

static void ipc_kv_num(FILE *fp, const char *key, long long val)
{
	ipc_kv(fp, key);
	fprintf(fp, "%lld", val);
	ipc_kv_end(fp);
}

/* A number of seconds, which every timer here is said in */
static void ipc_kv_secs(FILE *fp, const char *key, long long val)
{
	ipc_kv(fp, key);

	/* Two calls rather than a format chosen at runtime: a format that
	 * is not a literal is the shape rules/security.cocci looks for,
	 * and it is not worth being the one exception to it. */
	if (json)
		fprintf(fp, "%lld", val);
	else
		fprintf(fp, "%lld sec", val);

	ipc_kv_end(fp);
}

/* A number this router may not have, an unelected BSR's priority say */
static void ipc_kv_opt(FILE *fp, const char *key, int have, long long val)
{
	ipc_kv(fp, key);
	if (!have)
		fputs(json ? "null" : "N/A", fp);
	else
		fprintf(fp, "%lld", val);
	ipc_kv_end(fp);
}

/* State against the limit that caps it, two numbers in JSON */
static void ipc_kv_limit(FILE *fp, const char *key, unsigned used, unsigned limit)
{
	char buf[80];

	if (!json) {
		ipc_kv(fp, key);
		fprintf(fp, "%u of %u\n", used, limit);
		return;
	}

	ipc_kv_num(fp, key, used);
	snprintf(buf, sizeof(buf), "%s limit", key);
	ipc_kv_num(fp, buf, limit);
}

/* What a command with no JSON form answers, so that -j is always JSON */
static void ipc_no_json(FILE *fp, const char *cmd)
{
	fprintf(fp, "%s  \"error\": ", ipc_items++ ? ",\n" : "");
	fprintf(fp, "\"%s has no JSON form, it is a text dump\"", cmd);
}

/* How long a reply waits for a client that has stopped reading, in ms.  A
 * dump is written in pieces and this bounds each of them, so a client that
 * went away costs the router this much once rather than for ever. */
#define IPC_WRITE_WAIT		2000

enum {
	IPC_ERR = -1,
	IPC_OK  = 0,
	IPC_HELP,
	IPC_VERSION,
	IPC_STATUS,
	IPC_RESTART,
	IPC_DEBUG,
	IPC_LOGLEVEL,
	IPC_KILL,
	IPC_IGMP,
	IPC_IGMP_GRP,
	IPC_IGMP_IFACE,
	IPC_SUMMARY,
	IPC_PIM,
	IPC_PIM_IFACE,
	IPC_PIM_NEIGH,
	IPC_PIM_ROUTE,
	IPC_PIM_MFC,
	IPC_PIM_RP,
	IPC_PIM_CRP,
	IPC_PIM_DUMP,
	IPC_AUTORP
};

static struct ipcmd {
	int   op;
	char *cmd;
	char *arg;
	char *help;
} cmds[] = {
	{ IPC_DEBUG,      "debug", "[? | none | SYS]", "Debug subystem(s), separate with comma"},
	{ IPC_HELP,       "help", NULL, "This help text" },
	{ IPC_KILL,       "kill", NULL, "Kill running daemon, like SIGTERM"},
	{ IPC_LOGLEVEL,   "log", "[? | none | LEVEL]" , "Set log level: none, err, notice*, info, debug"},
	{ IPC_RESTART,    "restart", NULL, "Restart and reload .conf file, like SIGHUP"},
	{ IPC_VERSION,    "version", NULL, "Show daemon version" },
	{ IPC_STATUS,     "show status", NULL, "Show router status" },
	{ IPC_SUMMARY,    "show summary", NULL, "Show interface summary, PIM and IGMP" },
	{ IPC_IGMP_GRP,   "show igmp groups", NULL, "Show IGMP group memberships" },
	{ IPC_IGMP_IFACE, "show igmp interface", NULL, "Show IGMP interface status" },
	{ IPC_IGMP,       "show igmp", NULL, "Show interfaces and group memberships" },
	{ IPC_PIM_IFACE,  "show interface", NULL, "Show router interface table" },
	{ IPC_PIM_ROUTE,  "show mrt", "[detail]", "Show multicast routing table" },
	{ IPC_PIM_MFC,    "show mfc", NULL, "Show kernel multicast forwarding cache" },
	{ IPC_PIM_NEIGH,  "show neighbor", "[detail]", "Show router neighbor table" },
	{ IPC_PIM_RP,     "show rp", NULL, "Show Rendezvous-Point (RP) set" },
	{ IPC_PIM_CRP,    "show crp", NULL, "Show candidate Rendezvous-Point (CRP) set" },
	{ IPC_AUTORP,     "show autorp", NULL, "Show Auto-RP group-to-RP mappings" },
	{ IPC_PIM,        "show pim", "[detail]", "Show interfaces, neighbors and routes (default)"},
	{ IPC_PIM_DUMP,   "show compat", "[detail]", "Show router status, compat mode" },

	/* Aliases for what users type, hidden from help by a NULL description.
	 * Order matters: ipc_read() takes the first row whose command is a
	 * prefix of what the client sent, so a short command has to come after
	 * every longer one it is a prefix of -- the reason "show igmp groups"
	 * is listed above "show igmp", and "show" last of all. */
	{ IPC_PIM_IFACE,  "show interfaces", NULL, NULL },
	{ IPC_PIM_IFACE,  "show if", NULL, NULL },
	{ IPC_PIM_ROUTE,  "show routes", NULL, NULL },
	{ IPC_IGMP_GRP,   "show groups", NULL, NULL },
	{ IPC_PIM,        "show", NULL, NULL }, /* hidden default */
};

static char *timetostr(time_t t, char *buf, size_t len)
{
	int sec, min, hour, day;
	static char tmp[20];

	if (!buf) {
		buf = tmp;
		len = sizeof(tmp);
	}

	day  = t / 86400;
	t    = t % 86400;
	hour = t / 3600;
	t    = t % 3600;
	min  = t / 60;
	t    = t % 60;
	sec  = t;

	if (day)
		snprintf(buf, len, "%dd%dh%dm%ds", day, hour, min, sec);
	else
		snprintf(buf, len, "%dh%dm%ds", hour, min, sec);

	return buf;
}

static char *chomp(char *str)
{
	char *p;

	if (!str || strlen(str) < 1) {
		errno = EINVAL;
		return NULL;
	}

	/* The bound is not decoration: without it a string of nothing but
	 * newlines walks p off the front of the buffer, writing as it goes.
	 * Nothing reaches this with one -- strip() skips the leading run of
	 * " \t\n" before every call -- and the same function in pimctl.c
	 * carries the same test, so the two say the same thing now. */
	p = str + strlen(str) - 1;
        while (p >= str && *p == '\n')
		*p-- = 0;

	return str;
}

static void strip(char *cmd, size_t len)
{
	char *ptr;

	ptr = cmd + len;
	len = strspn(ptr, " \t\n");
	if (len > 0)
		ptr += len;

	memmove(cmd, ptr, strlen(ptr) + 1);
	chomp(cmd);
}

/*
 * The words that may follow a command: "detail", which every table that has
 * a long form takes, and "json", which "pimctl -j" appends.  Read in any
 * order and left as they were found for the next one, so that "show mrt
 * detail json" and "show mrt json detail" are the same request.
 *
 * A word matches while it is a prefix of the keyword, which is how "detail"
 * has always been read here -- "det" is a word somebody has typed.
 */
static int is_word(const char *cmd, size_t len, const char *word)
{
	return len > 0 && len <= strlen(word) && !strncasecmp(cmd, word, len);
}

static void check_modifiers(char *cmd, size_t len)
{
	strip(cmd, len);		/* the command itself */

	while (*cmd) {
		len = strcspn(cmd, " \t\n");

		if (is_word(cmd, len, "detail"))
			detail = 1;
		else if (is_word(cmd, len, "json"))
			json = 1;
		else
			break;		/* not ours, leave it alone */

		strip(cmd, len);
	}
}

static int ipc_read(int sd, char *cmd, ssize_t len)
{
	ssize_t num;

	/* Keep the size of the buffer and the result of the read apart: one
	 * variable for both means a retry asks read() for len - 1 with len
	 * already -1, and the client decides how much it sends.
	 */
	while ((num = read(sd, cmd, len - 1)) == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			continue;
		default:
			break;
		}
		return IPC_ERR;
	}
	if (num == 0)
		return IPC_OK;

	cmd[num] = 0;
//	logit(LOG_DEBUG, 0, "IPC cmd: '%s'", cmd);

	/* One command's modifiers are not the next one's, whether or not
	 * this one turns out to name a command at all */
	detail = 0;
	json = 0;

	for (size_t i = 0; i < NELEMS(cmds); i++) {
		struct ipcmd *c = &cmds[i];
		size_t clen = strlen(c->cmd);

		if (!strncasecmp(cmd, c->cmd, clen)) {
			check_modifiers(cmd, clen);
			return c->op;
		}
	}

	errno = EBADMSG;
	return IPC_ERR;
}

/*
 * The client socket is a non-blocking SOCK_STREAM one (ipc_init() and the
 * accept() below both set O_NONBLOCK), so a write takes what fits in the
 * socket buffer and says how much that was: a reply longer than the buffer
 * comes back short, and so does one interrupted by a signal after part of
 * it was copied.  Neither means the client has gone -- it means the rest
 * is still to send, which is what this loop does.  Reading a short write
 * as an error truncated whatever reply was long enough to hit it, "show
 * mrt" on a busy router being the one to notice.
 */
static int ipc_write(int sd, char *msg, size_t sz)
{
	size_t off = 0;

//	logit(LOG_DEBUG, 0, "IPC rpl: '%s'", msg);

	while (off < sz) {
		ssize_t len;

		len = write(sd, msg + off, sz - off);
		if (len < 0) {
			struct pollfd pfd = { .fd = sd, .events = POLLOUT };

			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				return IPC_ERR;

			/* A client that has stopped reading answers every
			 * write with EAGAIN, the socket being non-blocking,
			 * and retrying at once is a spin -- in a daemon with
			 * one thread, which is every timer and every packet
			 * of the router waiting on one pimctl.  So wait for
			 * room, and give up on the client rather than on the
			 * router if it never comes. */
			if (poll(&pfd, 1, IPC_WRITE_WAIT) <= 0)
				return IPC_ERR;

			continue;
		}
		if (len == 0)
			return IPC_ERR;

		off += (size_t)len;
	}

	return 0;
}

static int ipc_close(int sd)
{
	return shutdown(sd, SHUT_RDWR) ||
		close(sd);
}

/* The caller owns sd, ipc_handle() closes it once the reply is out. */
static int ipc_send(int sd, char *buf, size_t len, FILE *fp)
{
	while (fgets(buf, len, fp)) {
		if (!ipc_write(sd, buf, strlen(buf)))
			continue;

		logit(LOG_WARNING, errno, "Failed communicating with client");
		return IPC_ERR;
	}

	return 0;
}

static void ipc_show(int sd, int (*cb)(FILE *), char *buf, size_t len)
{
	FILE *fp;

	fp = priv_tempfile();
	if (!fp) {
		logit(LOG_WARNING, errno, "Failed opening temporary file");
		return;
	}

	/* One reply is one JSON document, however many tables it holds */
	ipc_items = 0;
	ipc_sect = NULL;
	if (json)
		fprintf(fp, "{\n");

	if (cb(fp)) {
		fclose(fp);
		return;
	}

	if (json)
		fprintf(fp, "\n}\n");

	rewind(fp);
	ipc_send(sd, buf, len, fp);
	fclose(fp);
}

static int ipc_err(int sd, char *buf, size_t len)
{
	switch (errno) {
	case EBADMSG:
		snprintf(buf, len, "No such command, see 'help' for available commands.");
		break;

	case EINVAL:
		snprintf(buf, len, "Invalid argument.");
		break;

	default:
		snprintf(buf, len, "Unknown error: %s", strerror(errno));
		break;
	}

	return ipc_write(sd, buf, strlen(buf));
}

/* wrap simple functions that don't use >768 bytes for I/O */
static int ipc_wrap(int sd, int (*cb)(char *, size_t), char *buf, size_t len)
{
	if (cb(buf, len))
		return IPC_ERR;

	return ipc_write(sd, buf, strlen(buf));
}

static const char *ifstate(struct uvif *uv)
{
	if (uv->uv_flags & VIFF_DOWN)
		return "Down";

	if (uv->uv_flags & VIFF_DISABLED)
		return "Disabled";

	/* Up, and running IGMP, but with no PIM on the wire */
	if (uv->uv_flags & VIFF_PASSIVE)
		return "Passive";

	return "Up";
}

static size_t nbr_count(struct uvif *uv)
{
	pim_nbr_entry_t *n;
	size_t num = 0;

	for (n = uv->uv_pim_neighbors; n; n = n->next)
		num++;

	return num;
}

static size_t group_count(struct uvif *uv)
{
	struct listaddr *group;
	size_t num = 0;

	for (group = uv->uv_groups; group; group = group->al_next)
		num++;

	return num;
}

/* The DR on this interface, our own address when we are it, 0.0.0.0 when
 * there is no neighbor to elect one with yet. */
static uint32_t dr_addr(struct uvif *uv)
{
	if (uv->uv_flags & VIFF_DR)
		return uv->uv_lcl_addr;

	if (uv->uv_pim_neighbor_dr)
		return uv->uv_pim_neighbor_dr->address;

	return 0;
}

static int igmp_version(struct uvif *uv)
{
	if (uv->uv_flags & VIFF_IGMPV2)
		return 2;

	return 3;
}

/* How many group ranges igmp-accept-groups allows here, zero for an
 * interface where any group may be joined */
static size_t grp_acl_count(struct uvif *uv)
{
	struct vif_acl *acl;
	size_t num = 0;

	for (acl = uv->uv_grp_acl; acl; acl = acl->acl_next)
		num++;

	return num;
}

/* The elected IGMP querier, "Local" when this router won the election */
static char *igmp_querier(struct uvif *uv, char *buf, size_t len)
{
	if (!uv->uv_querier)
		strlcpy(buf, "Local", len);
	else
		inet_fmt(uv->uv_querier->al_addr, buf, len);

	return buf;
}

static int show_neighbor(FILE *fp, struct uvif *uv, pim_nbr_entry_t *n)
{
	char tmp[20] = { 0 }, buf[42];
	time_t now, uptime;

	now = time(NULL);
	uptime = now - n->uptime;
	snprintf(buf, sizeof(buf), "%s/%s",
		 timetostr(uptime, tmp, sizeof(tmp)),
		 timetostr(n->timer, NULL, 0));

	struct ipc_field row[] = {
		IPC_STR("Interface",      -16, uv->uv_name),
		IPC_STR("Address",        -15, inet_fmt(n->address, s1, sizeof(s1))),
		IPC_OPT("Priority",	   10, n->dr_prio_present, n->dr_prio),
		IPC_STR("Mode",		   -9, !(uv->uv_flags & VIFF_DR) &&
					       uv->uv_pim_neighbor_dr == n ? "DR" : ""),
		IPC_STR("Uptime/Expires", -28, buf),
		IPC_END
	};

	ipc_row(fp, row);

	/* Its Address List, RFC 7761 sec. 4.3.4, one address to a row of its
	 * own, said so by the mode: a neighbor keeps one row otherwise. */
	if (detail) {
		for (uint16_t i = 0; i < n->nsecaddrs; i++) {
			struct ipc_field sec[] = {
				IPC_STR("Interface",	  -16, uv->uv_name),
				IPC_STR("Address",	  -15, inet_fmt(n->secaddrs[i], s1, sizeof(s1))),
				IPC_NA ("Priority",	   10),
				IPC_STR("Mode",		   -9, "secondary"),
				IPC_NA ("Uptime/Expires", -28),
				IPC_END
			};

			ipc_row(fp, sec);
		}
	}

	return 0;
}

/* PIM Neighbor Table */
static int show_neighbors(FILE *fp)
{
	pim_nbr_entry_t *n;
	struct uvif *uv;
	vifi_t vifi;

	ipc_table(fp, "PIM Neighbor Table", "neighbor");

	for (vifi = 0; vifi < numvifs; vifi++) {
		uv = &uvifs[vifi];

		for (n = uv->uv_pim_neighbors; n; n = n->next)
			show_neighbor(fp, uv, n);
	}

	ipc_table_end(fp);

	return 0;
}

static void show_interface(FILE *fp, struct uvif *uv)
{
	uint32_t prio = uv->uv_dr_prio;
	int known = 1;

	if (uv->uv_flags & VIFF_REGISTER)
		return;

	/* The DR's priority is this router's own where it is the DR, and
	 * otherwise the neighbor's -- which it has only if that neighbor's
	 * Hello carried the option. */
	if (!(uv->uv_flags & VIFF_DR)) {
		pim_nbr_entry_t *dr = uv->uv_pim_neighbor_dr;

		known = dr && dr->dr_prio_present;
		if (known)
			prio = dr->dr_prio;
	}

	struct ipc_field row[] = {
		IPC_STR("Interface",   -16, uv->uv_name),
		IPC_STR("State",	-8, ifstate(uv)),
		IPC_STR("Address",     -15, inet_fmt(uv->uv_lcl_addr, s1, sizeof(s1))),
		IPC_NUM("Priority",     10, uv->uv_dr_prio),
		IPC_NUM("Hello",	 5, pim_timer_hello_interval),
		IPC_NUM("Nbr",		 3, nbr_count(uv)),
		IPC_STR("DR Address",  -15, inet_fmt(dr_addr(uv), s2, sizeof(s2))),
		IPC_OPT("DR Priority",  11, known, prio),
		IPC_END
	};

	ipc_row(fp, row);
}

/*
 * One line per interface with the PIM and the IGMP view side by side, for
 * the common case of wanting to know whether an interface is doing
 * anything at all.  "show interface" and "show igmp interface" have the
 * per-protocol detail this leaves out.
 */
static int show_summary(FILE *fp)
{
	struct uvif *uv;
	vifi_t vifi;

	ipc_table(fp, "Interface Summary", "summary");

	for (vifi = 0, uv = uvifs; vifi < numvifs; vifi++, uv++) {
		char querier[20];

		/* The register vif has neither neighbors nor memberships */
		if (uv->uv_flags & VIFF_REGISTER)
			continue;

		struct ipc_field row[] = {
			IPC_STR("Interface",  -16, uv->uv_name),
			IPC_STR("State",       -8, ifstate(uv)),
			IPC_STR("Address",    -15, inet_fmt(uv->uv_lcl_addr, s1, sizeof(s1))),
			IPC_NUM("Nbrs",		4, nbr_count(uv)),
			IPC_STR("DR Address", -15, inet_fmt(dr_addr(uv), s2, sizeof(s2))),
			IPC_NUM("IGMP",		4, igmp_version(uv)),
			IPC_STR("Querier",    -15, igmp_querier(uv, querier, sizeof(querier))),
			IPC_NUM("Groups",	6, group_count(uv)),
			IPC_END
		};

		ipc_row(fp, row);
	}

	ipc_table_end(fp);

	return 0;
}

/* PIM Interface Table */
static int show_interfaces(FILE *fp)
{
	vifi_t vifi;

	ipc_table(fp, "PIM Interface Table", "interface");

	for (vifi = 0; vifi < numvifs; vifi++)
		show_interface(fp, &uvifs[vifi]);

	ipc_table_end(fp);

	return 0;
}

/* PIM RP Set Table */
static int show_rp(FILE *fp)
{
	grp_mask_t *grp;

	ipc_table(fp, "PIM Rendez-Vous Point Set Table", "rp");

	for (grp = grp_mask_list; grp; grp = grp->next) {
		struct rp_grp_entry *rp_grp = grp->grp_rp_next;

		while (rp_grp) {
			uint16_t ht = rp_grp->holdtime;
			const char *type;
			char htstr[10];

			/* Where the mapping came from, which used to be read
			 * off the holdtime: a configured RP is the one with
			 * no holdtime, so "static" and "forever" were the
			 * same answer.  With Auto-RP beside the BSR they are
			 * not, and only the entry itself knows. */
			switch (rp_grp->origin) {
			case RP_ORIGIN_STATIC:
				type = "Static";
				break;

			case RP_ORIGIN_AUTORP:
				type = "Auto-RP";
				break;

			default:
				type = "Dynamic";
				break;
			}

			if (ht == PIM_HELLO_HOLDTIME_FOREVER)
				snprintf(htstr, sizeof(htstr), "Forever");
			else
				snprintf(htstr, sizeof(htstr), "%d", ht);

			struct ipc_field row[] = {
				IPC_STR("Group Address", -16, netname(grp->group_addr, grp->group_mask)),
				IPC_STR("RP Address",	 -15, inet_fmt(rp_grp->rp->rpentry->address, s1, sizeof(s1))),
				IPC_NUM("Prio",		   4, rp_grp->priority),
				IPC_STR("Holdtime",	   8, htstr),
				IPC_STR("Type",		  -7, type),
				IPC_END
			};

			ipc_row(fp, row);

			rp_grp = rp_grp->grp_rp_next;
		}
	}

	ipc_table_end(fp);

	return 0;
}

/* PIM Cand-RP Table */
static int show_crp(FILE *fp)
{
	struct cand_rp *rp;

	ipc_table(fp, "PIM Candidate Rendez-Vous Point Table", "crp");

	for (rp = cand_rp_list; rp; rp = rp->next) {
		struct rp_grp_entry *rp_grp = rp->rp_grp_next;
		struct grp_mask *grp = rp_grp->group;
		rpentry_t *entry = rp->rpentry;
		char buf[10];

		if (entry->adv_holdtime == PIM_HELLO_HOLDTIME_FOREVER)
			snprintf(buf, sizeof(buf), "Forever");
		else
			snprintf(buf, sizeof(buf), "%d", entry->adv_holdtime);

		struct ipc_field row[] = {
			IPC_STR("Group Address", -16, netname(grp->group_addr, grp->group_mask)),
			IPC_STR("RP Address",	 -15, inet_fmt(entry->address, s1, sizeof(s1))),
			IPC_NUM("Prio",		   4, rp_grp->priority),
			IPC_STR("Holdtime",	   8, buf),
			IPC_STR("Expires",	  -8, PIM_HELLO_HOLDTIME_FOREVER == rp_grp->holdtime
					       ? "Never"
					       : timetostr(rp_grp->holdtime, NULL, 0)),
			IPC_END
		};

		ipc_row(fp, row);
	}

	ipc_table_end(fp);

	if (!json)
		putc('\n', fp);
	ipc_kv_str(fp, "Current BSR address", inet_fmt(curr_bsr_address, s1, sizeof(s1)));

	return 0;
}

/* The MRTF_* of one entry as the words "show mrt" has always printed */
static const char *route_flags(mrtentry_t *r, char *buf, size_t len)
{
	static const struct {
		uint32_t    flag;
		const char *name;
	} flags[] = {
		{ MRTF_SPT,	    "SPT"      },
		{ MRTF_KAT,	    "KAT"      },
		{ MRTF_WC,	    "WC"       },
		{ MRTF_RP,	    "RP"       },
		{ MRTF_REGISTER,    "REG"      },
		{ MRTF_IIF_REGISTER,"IIF_REG"  },
		{ MRTF_NULL_OIF,    "NULL_OIF" },
		{ MRTF_KERNEL_CACHE,"CACHE"    },
		{ MRTF_ASSERTED,    "ASSERTED" },
		{ MRTF_REG_SUPP,    "REG_SUPP" },
		{ MRTF_SG,	    "SG"       },
	};

	buf[0] = 0;
	for (size_t i = 0; i < NELEMS(flags); i++) {
		if (!(r->flags & flags[i].flag))
			continue;

		if (buf[0])
			strlcat(buf, " ", len);
		strlcat(buf, flags[i].name, len);
	}

	return buf;
}

/*
 * The long form of one routing entry, below the row it belongs to: the
 * per-interface maps and the timers, which are a block rather than a
 * table and have no JSON form.
 */
static void dump_route(FILE *fp, mrtentry_t *r)
{
	char asserted_oifs[MAXVIFS+1];
	char assert_states[MAXVIFS+1];
	char incoming_iif[MAXVIFS+1];
	char joined_oifs[MAXVIFS+1];
	char pruned_oifs[MAXVIFS+1];
	char rpt_oifs[MAXVIFS+1];
	char leaves_oifs[MAXVIFS+1];
	char oifs[MAXVIFS+1];
	vifi_t vifi;

	for (vifi = 0; vifi < numvifs; vifi++) {
		oifs[vifi] =
			PIMD_VIFM_ISSET(vifi, r->oifs) ? 'o' : '.';
		joined_oifs[vifi] =
			PIMD_VIFM_ISSET(vifi, r->joined_oifs) ? 'j' : '.';
		pruned_oifs[vifi] =
			PIMD_VIFM_ISSET(vifi, r->pruned_oifs) ? 'p' : '.';
		/* The downstream (S,G,rpt) machine of RFC 7761 sec. 4.5.3:
		 * 'p' in Prune, 'P' in Prune-Pending, which still forwards */
		rpt_oifs[vifi] =
			PIMD_VIFM_ISSET(vifi, r->rpt_pruned_oifs) ? 'p'
			: (PIMD_VIFM_ISSET(vifi, r->rpt_pp_oifs) ? 'P' : '.');
		leaves_oifs[vifi] =
			PIMD_VIFM_ISSET(vifi, r->leaves) ? 'l' : '.';
		asserted_oifs[vifi] =
			PIMD_VIFM_ISSET(vifi, r->asserted_oifs) ? 'a' : '.';
		/* The Assert state machine of RFC 7761 sec. 4.6.1: 'W' where
		 * we won the election, 'L' where we lost it.  Not the same
		 * question as the line above, which is the olist the loss
		 * leaves behind. */
		assert_states[vifi] = assert_winner_is_me(r, vifi) ? 'W'
			: (assert_lost_on(r, vifi) ? 'L' : '.');
		incoming_iif[vifi] = '.';
	}
	oifs[vifi]		= 0x0;	/* End of string */
	joined_oifs[vifi]	= 0x0;
	pruned_oifs[vifi]	= 0x0;
	rpt_oifs[vifi]		= 0x0;
	leaves_oifs[vifi]	= 0x0;
	asserted_oifs[vifi] = 0x0;
	assert_states[vifi] = 0x0;
	incoming_iif[vifi]	= 0x0;
	incoming_iif[r->incoming] = 'I';

	if (!detail || json)
		return;

	fprintf(fp, "Joined   oifs: %-20s\n", joined_oifs);
	fprintf(fp, "Pruned   oifs: %-20s\n", pruned_oifs);
	if (r->flags & MRTF_SG)
		fprintf(fp, "RptPrune oifs: %-20s\n", rpt_oifs);
	fprintf(fp, "Leaves   oifs: %-20s\n", leaves_oifs);
	fprintf(fp, "Asserted oifs: %-20s\n", asserted_oifs);
	fprintf(fp, "Assert state : %-20s\n", assert_states);
	fprintf(fp, "Outgoing oifs: %-20s\n", oifs);
	fprintf(fp, "Incoming     : %-20s\n", incoming_iif);

	fprintf(fp, "\nTIMERS       :  Entry    JP    RS  VIFS:");
	for (vifi = 0; vifi < numvifs; vifi++)
		fprintf(fp, "  %d", vifi);
	fprintf(fp, "\n                %5d  %4d  %4d       ",
		r->entry_timer, timer_secs_left(r->jp_expires), r->rs_timer);
	for (vifi = 0; vifi < numvifs; vifi++)
		fprintf(fp, " %2d", r->vif_timers[vifi]);
	fprintf(fp, "\nASSERT TIMERS:                        ");
	for (vifi = 0; vifi < numvifs; vifi++)
		fprintf(fp, " %2d", timer_secs_left(r->asserts[vifi].expires));
	fprintf(fp, "\n");
}

/* PIM Multicast Routing Table */
static int show_pim_mrt(FILE *fp)
{
	u_int number_of_cache_mirrors = 0;
	u_int number_of_groups = 0;
	char flags[80];
	kernel_cache_t *kc;
	grpentry_t *g;
	mrtentry_t *r;

	ipc_table(fp, "Multicast Routing Table", "mrt");

	/* TODO: remove the dummy 0.0.0.0 group (first in the chain) */
	for (g = grplist->next; g; g = g->next) {
		number_of_groups++;

		r = g->grp_route;
		if (r) {
			if (r->flags & MRTF_KERNEL_CACHE) {
				for (kc = r->kernel_cache; kc; kc = kc->next)
					number_of_cache_mirrors++;
			}

			struct ipc_field row[] = {
				IPC_STR("Source",     -15, "ANY"),
				IPC_STR("Group",      -15, inet_fmt(g->group, s1, sizeof(s1))),
				IPC_STR("RP Address", -15, IN_PIM_SSM_RANGE(g->group)
					? "SSM"
					: (g->active_rp_grp
					   ? inet_fmt(g->rpaddr, s2, sizeof(s2))
					   : "NULL")),
				IPC_STR("Flags",       -5, route_flags(r, flags, sizeof(flags))),
				IPC_END
			};

			ipc_row(fp, row);
			dump_route(fp, r);
		}

		for (r = g->mrtlink; r; r = r->grpnext) {
			if (r->flags & MRTF_KERNEL_CACHE)
				number_of_cache_mirrors++;

			struct ipc_field row[] = {
				IPC_STR("Source",     -15, inet_fmt(r->source->address, s1, sizeof(s1))),
				IPC_STR("Group",      -15, inet_fmt(g->group, s2, sizeof(s2))),
				IPC_STR("RP Address", -15, IN_PIM_SSM_RANGE(g->group)
					? "SSM"
					: (g->active_rp_grp
					   ? inet_fmt(g->rpaddr, s3, sizeof(s3))
					   : "NULL")),
				IPC_STR("Flags",       -5, route_flags(r, flags, sizeof(flags))),
				IPC_END
			};

			ipc_row(fp, row);
			dump_route(fp, r);
		}
	}

	ipc_table_end(fp);

	if (!json)
		putc('\n', fp);
	ipc_kv_num(fp, "Number of Groups", number_of_groups);
	ipc_kv_num(fp, "Number of Cache MIRRORs", number_of_cache_mirrors);

	return 0;
}

/*
 * One line per (S,G) the kernel has in its MFC on behalf of this routing
 * entry.  A (*,G) or an (S,G) on the shared tree mirrors every active
 * source in its kernel_cache list, so walking that list is what gives the
 * kernel's view rather than the daemon's.  Counters are read into a local
 * struct on purpose: check_spt_threshold() (src/route.c) compares the
 * stored ones against the previous read to measure a datarate, and a
 * "pimctl show mfc" must not perturb that.
 */
static u_int dump_mfc(FILE *fp, mrtentry_t *r)
{
	char oifs[MAXVIFS * (IFNAMSIZ + 1)];
	struct sg_count cnt = { 0 };	/* the row reads it either way */
	kernel_cache_t *kc;
	u_int num = 0;
	vifi_t vifi;

	if (!r || !(r->flags & MRTF_KERNEL_CACHE))
		return 0;

	oifs[0] = 0;
	for (vifi = 0; vifi < numvifs; vifi++) {
		/* k_chg_mfc() (src/kern.c) clears the iif before handing the
		 * list to the kernel, RFC 7761 4.2, so a vif that is both must
		 * not be listed here either. */
		if (vifi == r->incoming || !PIMD_VIFM_ISSET(vifi, r->oifs))
			continue;

		if (oifs[0])
			strlcat(oifs, ",", sizeof(oifs));
		strlcat(oifs, uvifs[vifi].uv_name, sizeof(oifs));
	}
	if (!oifs[0])
		strlcpy(oifs, "---", sizeof(oifs));

	for (kc = r->kernel_cache; kc; kc = kc->next) {
		int have;

		num++;
		have = !k_get_sg_cnt(udp_socket, kc->source, kc->group, &cnt);

		struct ipc_field row[] = {
			IPC_STR("Source", -15, inet_fmt(kc->source, s1, sizeof(s1))),
			IPC_STR("Group",  -15, inet_fmt(kc->group, s2, sizeof(s2))),
			IPC_STR("Iif",	  -15, r->incoming < numvifs ? uvifs[r->incoming].uv_name : "---"),
			IPC_OPT("Packets", 10, have, cnt.pktcnt),
			IPC_OPT("Bytes",   10, have, cnt.bytecnt),
			IPC_OPT("WrongIf",  9, have, cnt.wrong_if),
			IPC_STR("Oifs",	   -4, oifs),
			IPC_END
		};

		ipc_row(fp, row);
	}

	return num;
}

/* Kernel Multicast Forwarding Cache (MFC) */
static int show_mfc(FILE *fp)
{
	u_int number_of_entries = 0;
	grpentry_t *g;
	mrtentry_t *r;

	ipc_table(fp, "Kernel Multicast Forwarding Cache", "mfc");

	/* TODO: remove the dummy 0.0.0.0 group (first in the chain) */
	for (g = grplist->next; g; g = g->next) {
		number_of_entries += dump_mfc(fp, g->grp_route);

		for (r = g->mrtlink; r; r = r->grpnext)
			number_of_entries += dump_mfc(fp, r);
	}

	ipc_table_end(fp);

	if (!json)
		putc('\n', fp);
	ipc_kv_num(fp, "Number of MFC entries", number_of_entries);

	return 0;
}

static int show_pim(FILE *fp)
{
	return  show_interfaces (fp) ||
		show_neighbors  (fp) ||
		show_pim_mrt    (fp) ||
		show_crp        (fp) ||
		show_rp         (fp);
}

static int show_status(FILE *fp)
{
	char buf[120];
	int len;

	if (!json)
		fprintf(fp, "PIM Daemon Status=\n");

	MASK_TO_MASKLEN(curr_bsr_hash_mask, len);

	ipc_section(fp, "Elected BSR");
	ipc_kv_str(fp, "Address", inet_fmt(curr_bsr_address, s1, sizeof(s1)));
	ipc_kv_str(fp, "Expiry Time", !pim_bootstrap_timer ? NULL : timetostr(pim_bootstrap_timer, NULL, 0));
	ipc_kv_opt(fp, "Priority", curr_bsr_priority, curr_bsr_priority);
	ipc_kv_num(fp, "Hash Mask Length", len);

	ipc_section(fp, "Candidate BSR");
	ipc_kv_str(fp, "State", CANDIDACY(cand_bsr_flag, cand_bsr_configured));
	ipc_kv_str(fp, "Address", inet_fmt(my_bsr_address, s1, sizeof(s1)));
	ipc_kv_opt(fp, "Priority", my_bsr_priority, my_bsr_priority);

	ipc_section(fp, "Candidate RP");
	ipc_kv_str(fp, "State", CANDIDACY(cand_rp_flag, cand_rp_configured));
	ipc_kv_str(fp, "Address", inet_fmt(my_cand_rp_address, s1, sizeof(s1)));
	ipc_kv_num(fp, "Priority", my_cand_rp_priority);
	ipc_kv_secs(fp, "Holdtime", my_cand_rp_holdtime);

	ipc_section(fp, NULL);

	/* Which of routesock.c and netlink.c was built in.  On Linux there is
	 * only ever one answer, but a FreeBSD pimd can be either, and nothing
	 * else about a running router says which: both answer the same
	 * lookups. */
	ipc_kv_str(fp, "RPF Backend", rpf_backend);

	/* Where the metric preference of an Assert comes from, which is a
	 * question about this router's own Asserts that nothing else
	 * answers: "rib" is only an answer where the backend above can name
	 * the routing protocol, and a route it cannot name still carries the
	 * interface's `distance`. */
	ipc_kv_str(fp, "Assert preference", assert_pref_from_rib ? "rib" : "configured");

	/* Whether the half that parses the wire is the one holding root, and
	 * what keeps it in.  Nothing else about a running router says so, and
	 * "separated" that quietly stopped being true is exactly the failure
	 * worth being able to see. */
	if (priv_enabled())
		snprintf(buf, sizeof(buf), "%s, sandbox %s, chroot %s",
			 priv_user(), priv_sandbox(), priv_chroot_dir());
	else
		snprintf(buf, sizeof(buf), "none, running as root");
	ipc_kv_str(fp, "Privilege separation", buf);

	ipc_kv_secs(fp, "Join/Prune Interval", PIM_JOIN_PRUNE_PERIOD);
	ipc_kv_secs(fp, "Hello Interval", pim_timer_hello_interval);
	ipc_kv_secs(fp, "Hello Holdtime", pim_timer_hello_holdtime);
	ipc_kv_secs(fp, "IGMP query interval", igmp_query_interval);
	ipc_kv_secs(fp, "IGMP querier timeout", igmp_querier_timeout);
	ipc_kv_limit(fp, "RPT Prune entries", rpt_prune_entries, rpt_prune_limit);
	ipc_kv_num(fp, "Route ageing usec", route_ageing_usec);
	ipc_kv_num(fp, "Route ageing peak", route_ageing_peak_usec);
	ipc_kv_limit(fp, "Local (S,G) entries", local_sg_entries, local_sg_limit);
	ipc_kv_limit(fp, "Register (S,G) state", register_sg_entries, register_sg_limit);
	ipc_kv_limit(fp, "Auto-RP mappings", autorp_entries, autorp_limit);
	ipc_kv_limit(fp, "RP set group ranges", rp_set_entries, rp_set_limit);
	dump_cand_rp_prefixes(fp);
	dump_ssm_ranges(fp);
	dump_reg_acl(fp);
	dump_crp_acl(fp);
	dump_anycast_rp(fp);
	ipc_kv_str(fp, "SPT Threshold", spt_threshold.mode == SPT_INF ? "Disabled" : "Enabled");
	if (spt_threshold.mode != SPT_INF) {
		if (spt_threshold.mode == SPT_RATE) {
			ipc_kv_str(fp, "SPT Mode", "rate");
			ipc_kv_num(fp, "SPT Bytes (kbps)", spt_threshold.bytes / 1000);
		} else {
			ipc_kv_str(fp, "SPT Mode", "packets");
			ipc_kv_num(fp, "SPT Packets", spt_threshold.packets);
		}
		ipc_kv_secs(fp, "SPT Interval", spt_threshold.interval);
	}

	return 0;
}

static int show_igmp_groups(FILE *fp)
{
	struct listaddr *group, *source;
	struct uvif *uv;
	vifi_t vifi;

	ipc_table(fp, "IGMP Group Membership Table", "igmp_group");

	for (vifi = 0, uv = uvifs; vifi < numvifs; vifi++, uv++) {
		for (group = uv->uv_groups; group; group = group->al_next) {
			/*
			 * One row per source, or one saying ANY where the
			 * membership names none, each with the timer it
			 * expires on.  The version is the group's
			 * compatibility mode, not the interface's: one
			 * older report puts the group back a version
			 * (RFC 3376 sec. 7.3.2) and a timer of its own
			 * brings it forward again, which is state nothing
			 * else here could show.
			 */
			source = group->al_sources;
			do {
				struct ipc_field row[] = {
					IPC_STR("Interface",	 -16, uv->uv_name),
					IPC_STR("Group",	 -15, inet_fmt(group->al_addr, s1, sizeof(s1))),
					IPC_STR("Source",	 -15, source ? inet_fmt(source->al_addr, s2, sizeof(s2)) : "ANY"),
					IPC_STR("Last Reported", -15, inet_fmt(group->al_reporter, s3, sizeof(s3))),
					IPC_NUM("Timeout",	   7, source ? source->al_timer : group->al_timer),
					IPC_NUM("Version",	   7, group->al_pv),
					IPC_END
				};

				ipc_row(fp, row);
				if (source)
					source = source->al_next;
			} while (source);
		}
	}

	ipc_table_end(fp);

	return 0;
}

static int show_igmp_iface(FILE *fp)
{
	struct uvif *uv;
	vifi_t vifi;

	ipc_table(fp, "IGMP Interface Table", "igmp_interface");

	for (vifi = 0, uv = uvifs; vifi < numvifs; vifi++, uv++) {
		/* The register_vif is never used for IGMP messages */
		if (uv->uv_flags & VIFF_REGISTER)
			continue;

		/* Only a querier elsewhere on the LAN times out; this
		 * router being the querier itself, nothing does. */
		struct ipc_field row[] = {
			IPC_STR("Interface", -16, uv->uv_name),
			IPC_STR("State",      -8, ifstate(uv)),
			IPC_STR("Querier",   -15, igmp_querier(uv, s1, sizeof(s1))),
			IPC_OPT("Timeout",     7, uv->uv_querier,
				uv->uv_querier ? igmp_querier_timeout - uv->uv_querier->al_timer : 0),
			IPC_NUM("Version",     7, igmp_version(uv)),
			IPC_NUM("Groups",      6, group_count(uv)),
			/* The ranges a host here may join, "N/A" where that
			 * is every group, which is the default */
			IPC_OPT("Accept",      6, grp_acl_count(uv), grp_acl_count(uv)),
			IPC_END
		};

		ipc_row(fp, row);
	}

	ipc_table_end(fp);

	return 0;
}

static int show_igmp(FILE *fp)
{
	int rc = 0;

	rc += show_igmp_iface(fp);
	rc += show_igmp_groups(fp);

	return rc;
}

/* What Auto-RP has said, which the RP table above cannot show: a denied
 * prefix has no RP to put in a row, and nothing else says which agent a
 * mapping came from or when it stops being believed. */
static int show_autorp(FILE *fp)
{
	return dump_autorp(fp, detail);
}

static int show_dump(FILE *fp)
{
	/* A frozen format from before pimctl, prose and tables in equal
	 * measure: there is nothing to declare, so -j says so rather than
	 * wrapping a text dump in braces and calling it JSON. */
	if (json) {
		ipc_no_json(fp, "show compat");
		return 0;
	}

	dump_vifs(fp, detail);
	dump_ssm(fp, detail);
	dump_pim_mrt(fp, detail);
	dump_rp_set(fp, detail);

	return 0;
}

static int show_version(FILE *fp)
{
	char buf[120];

	if (!json) {
		fputs(versionstring, fp);
		return 0;
	}

	/* The banner is one line with a newline of its own */
	strlcpy(buf, versionstring, sizeof(buf));
	buf[strcspn(buf, "\n")] = 0;
	ipc_kv_str(fp, "Version", buf);

	return 0;
}

static int ipc_debug(char *buf, size_t len)
{
	if (!strcmp(buf, "?"))
		return debug_list(DEBUG_ALL, buf, len);

	if (strlen(buf)) {
		int rc = debug_parse(buf);

		if ((int)DEBUG_PARSE_FAIL == rc) {
			errno = EINVAL;
			return 1;
		}

		/* Activate debugging of new subsystems */
		debug = rc;
	}

	/* Return list of activated subsystems */
	if (debug)
		debug_list(debug, buf, len);
	else
		snprintf(buf, len, "none");

	return 0;
}

static int ipc_loglevel(char *buf, size_t len)
{
	int rc;

	if (!strcmp(buf, "?"))
		return log_list(buf, len);

	if (!strlen(buf)) {
		strlcpy(buf, log_lvl2str(loglevel), len);
		return 0;
	}

	rc = log_str2lvl(buf);
	if (-1 == rc) {
		errno = EINVAL;
		return 1;
	}

	logit(LOG_NOTICE, 0, "Setting new log level %s", log_lvl2str(rc));
	loglevel = rc;

	return 0;
}

static void ipc_help(int sd, char *buf, size_t len)
{
	FILE *fp;

	fp = priv_tempfile();
	if (!fp) {
		(void)snprintf(buf, len, "Cannot create tempfile: %s", strerror(errno));
		/* Through ipc_write(), which sends all of it: snprintf()
		 * answers with the length it wanted rather than the one it
		 * wrote, so the count this used to hand write() was past
		 * the end of the buffer whenever the message was truncated. */
		if (ipc_write(sd, buf, strlen(buf)))
			logit(LOG_INFO, errno, "Client closed connection");
		return;
	}

	for (size_t i = 0; i < NELEMS(cmds); i++) {
		struct ipcmd *c = &cmds[i];
		char tmp[50];

		snprintf(tmp, sizeof(tmp), "%s%s%s", c->cmd, c->arg ? " " : "", c->arg ?: "");
		fprintf(fp, "%s\t%s\n", tmp, c->help ? c->help : "");
	}
	rewind(fp);

	while (fgets(buf, len, fp)) {
		if (!ipc_write(sd, buf, strlen(buf)))
			continue;

		logit(LOG_WARNING, errno, "Failed communicating with client");
	}

	fclose(fp);
}

/* Declared in defs.h: the event loop calls this through the registration
 * below, and test/fuzz/fuzz_ipc.c calls it directly.
 */
void ipc_handle(int sd)
{
	char cmd[768] = { 0 };
	int client;
	int rc = 0;

	client = accept(sd, NULL, NULL);
	if (client < 0)
		return;

	switch (ipc_read(client, cmd, sizeof(cmd))) {
	case IPC_HELP:
		ipc_help(client, cmd, sizeof(cmd));
		break;

	case IPC_DEBUG:
		rc = ipc_wrap(client, ipc_debug, cmd, sizeof(cmd));
		break;

	case IPC_LOGLEVEL:
		rc = ipc_wrap(client, ipc_loglevel, cmd, sizeof(cmd));
		break;

	case IPC_KILL:
		rc = ipc_wrap(client, daemon_kill, cmd, sizeof(cmd));
		break;

	case IPC_RESTART:
		rc = ipc_wrap(client, daemon_restart, cmd, sizeof(cmd));
		break;

	case IPC_VERSION:
		ipc_show(client, show_version, cmd, sizeof(cmd));
		break;

	case IPC_IGMP_GRP:
		ipc_show(client, show_igmp_groups, cmd, sizeof(cmd));
		break;

	case IPC_IGMP_IFACE:
		ipc_show(client, show_igmp_iface, cmd, sizeof(cmd));
		break;

	case IPC_IGMP:
		ipc_show(client, show_igmp, cmd, sizeof(cmd));
		break;

	case IPC_PIM_IFACE:
		ipc_show(client, show_interfaces, cmd, sizeof(cmd));
		break;

	case IPC_SUMMARY:
		ipc_show(client, show_summary, cmd, sizeof(cmd));
		break;

	case IPC_PIM_NEIGH:
		ipc_show(client, show_neighbors, cmd, sizeof(cmd));
		break;

	case IPC_PIM_ROUTE:
		ipc_show(client, show_pim_mrt, cmd, sizeof(cmd));
		break;

	case IPC_PIM_MFC:
		ipc_show(client, show_mfc, cmd, sizeof(cmd));
		break;

	case IPC_PIM_RP:
		ipc_show(client, show_rp, cmd, sizeof(cmd));
		break;

	case IPC_PIM_CRP:
		ipc_show(client, show_crp, cmd, sizeof(cmd));
		break;

	case IPC_AUTORP:
		ipc_show(client, show_autorp, cmd, sizeof(cmd));
		break;

	case IPC_PIM:
		ipc_show(client, show_pim, cmd, sizeof(cmd));
		break;

	case IPC_STATUS:
		ipc_show(client, show_status, cmd, sizeof(cmd));
		break;

	case IPC_PIM_DUMP:
		ipc_show(client, show_dump, cmd, sizeof(cmd));
		break;

	case IPC_OK:
		/* client ping, ignore */
		break;

	case IPC_ERR:
		logit(LOG_WARNING, errno, "Failed reading command from client");
		rc = IPC_ERR;
		break;

	default:
		logit(LOG_WARNING, 0, "Invalid IPC command: %s", cmd);
		break;
	}

	if (rc == IPC_ERR)
		ipc_err(client, cmd, sizeof(cmd));

	ipc_close(client);
}


void ipc_init(char *sockfile)
{
	socklen_t len;
	mode_t mask;
	int sd;

	/* Under separation the parent has already created, bound and
	 * listened on this: the path is in /var/run, which the sandbox puts
	 * out of reach, and the node has to be owned by root for the same
	 * reason the mode below is 0700. */
	if (priv_enabled()) {
		sd = priv_ipc_socket();
		if (sd < 0) {
			logit(LOG_WARNING, errno, "Failed binding IPC socket, client disabled");
			return;
		}

		(void)fcntl(sd, F_SETFL, fcntl(sd, F_GETFL) | O_NONBLOCK);
		goto bound;
	}

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd < 0) {
		logit(LOG_ERR, errno, "Failed creating IPC socket");
		return;
	}

	/* Portable SOCK_NONBLOCK replacement, ignore any error.  O_NONBLOCK
	 * is a file status flag, so it belongs to F_SETFL; setting it with
	 * F_SETFD wrote it to the descriptor flags, where the only bit that
	 * means anything is FD_CLOEXEC, and left the socket blocking.
	 */
	(void)fcntl(sd, F_SETFL, fcntl(sd, F_GETFL) | O_NONBLOCK);

#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sun.sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sun.sun_family = AF_UNIX;
	if (sockfile)
		strlcpy(sun.sun_path, sockfile, sizeof(sun.sun_path));
	else
		snprintf(sun.sun_path, sizeof(sun.sun_path), _PATH_PIMD_SOCK, ident);

	unlink(sun.sun_path);
	logit(LOG_DEBUG, 0, "Binding IPC socket to %s", sun.sun_path);

	/* Connecting to a UNIX socket needs write permission on it, and the
	 * commands it takes are the ones that reconfigure this daemon, so
	 * say who may rather than leaving it to whatever umask pimd was
	 * started with.  The mode has to be in place before bind() creates
	 * the node, since there is no unprivileged window afterwards to
	 * fix it in.
	 */
	mask = umask(0077);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	if (bind(sd, (struct sockaddr *)&sun, len) < 0 || listen(sd, 1)) {
		umask(mask);
		logit(LOG_WARNING, errno, "Failed binding IPC socket, client disabled");
		close(sd);
		return;
	}
	umask(mask);

  bound:
	if (register_input_handler(sd, ipc_handle) < 0)
		logit(LOG_ERR, 0, "Failed registering IPC handler");

	ipc_socket = sd;
}

void ipc_exit(void)
{
	if (ipc_socket > -1)
		close(ipc_socket);

	if (priv_enabled())
		priv_ipc_close();
	else
		unlink(sun.sun_path);

	ipc_socket = -1;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
