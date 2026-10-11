/*
 * Copyright (c) 1998-2001
 * University of Southern California/Information Sciences Institute.
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
 *  $Id: debug.c,v 1.22 2001/11/28 00:13:50 pavlin Exp $
 */
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */

#define SYSLOG_NAMES
#include "defs.h"

#include <stdarg.h>
#include <stdio.h>



static struct debugname {
    char	*name;
    uint32_t	 level;
    size_t	 nchars;
} debugnames[] = {
    {	"all",		    DEBUG_ALL,		  2	    },
    {	"3",		    DEBUG_ALL,		  1	    },	 /* compat. */
    {	"asserts",	    DEBUG_PIM_ASSERT,	  5	    },
    {	"pim-asserts",	    DEBUG_PIM_ASSERT,	  5	    },
    {	"pim_asserts",	    DEBUG_PIM_ASSERT,	  5	    },
    {	"bsr",		    DEBUG_PIM_BOOTSTRAP,  1	    },
    {	"bootstrap",	    DEBUG_PIM_BOOTSTRAP,  1	    },
    {	"pim_bsr",	    DEBUG_PIM_BOOTSTRAP,  5	    },
    {	"pim-bsr",	    DEBUG_PIM_BOOTSTRAP,  5	    },
    {	"pim-bootstrap",    DEBUG_PIM_BOOTSTRAP,  5	    },
    {	"pim_bootstrap",    DEBUG_PIM_BOOTSTRAP,  5	    },
    {	"crp",		    DEBUG_PIM_CAND_RP,	  2	    },
    {	"pim_cand_rp",	    DEBUG_PIM_CAND_RP,	  5	    },
    {	"pim-cand-rp",	    DEBUG_PIM_CAND_RP,	  5	    },
    {	"pim_c_rp",	    DEBUG_PIM_CAND_RP,	  5	    },
    {	"pim_rp",	    DEBUG_PIM_CAND_RP,	  6	    },
    {	"rp",		    DEBUG_PIM_CAND_RP,	  2	    },
    {	"detail",	    DEBUG_PIM_DETAIL,	  5	    },
    {	"pim_detail",	    DEBUG_PIM_DETAIL,	  5	    },
    {	"igmp",		    DEBUG_IGMP,		  1	    },
    {	"interfaces",	    DEBUG_IF,		  2	    },
    {	"vifs",		    DEBUG_IF,		  1	    },
    {	"jp",		    DEBUG_PIM_JOIN_PRUNE, 5	    },
    {	"join-prune",	    DEBUG_PIM_JOIN_PRUNE, 5	    },
    {	"pim-join-prune",   DEBUG_PIM_JOIN_PRUNE, 5	    },
    {	"pim_join_prune",   DEBUG_PIM_JOIN_PRUNE, 5	    },
    {	"pim_jp",	    DEBUG_PIM_JOIN_PRUNE, 5	    },
    {	"pim_j_p",	    DEBUG_PIM_JOIN_PRUNE, 5	    },
    {	"kernel",	    DEBUG_KERN,		  2	    },
    {	"mfc",		    DEBUG_MFC,		  2	    },
    {	"k_cache",	    DEBUG_MFC,		  2	    },
    {	"k_mfc",	    DEBUG_MFC,		  2	    },
    {	"cache",	    DEBUG_MFC,		  1	    },
    {	"mrt",		    DEBUG_MRT,		  1	    },
    {	"routes",	    DEBUG_MRT,		  1	    },
    {	"routing",	    DEBUG_MRT,		  1	    },
    {	"neighbors",	    DEBUG_PIM_HELLO,	  5	    },
    {	"peers",	    DEBUG_PIM_HELLO,	  5	    },
    {	"hello",	    DEBUG_PIM_HELLO,	  5	    },
    {	"pim_hello",	    DEBUG_PIM_HELLO,	  5	    },
    {	"pim-hello",	    DEBUG_PIM_HELLO,	  5	    },
    {	"pim_neighbors",    DEBUG_PIM_HELLO,	  5	    },
    {	"pim-neighbors",    DEBUG_PIM_HELLO,	  5	    },
    {	"pim_peers",	    DEBUG_PIM_HELLO,	  5	    },
    {	"pim-peers",	    DEBUG_PIM_HELLO,	  5	    },
    {	"packets",	    DEBUG_PKT,		  2	    },
    {	"pkt",		    DEBUG_PKT,		  2	    },
    {	"pim",		    DEBUG_PIM,		  1	    },
    {	"registers",	    DEBUG_PIM_REGISTER,	  2	    },
    {	"pim_register",	    DEBUG_PIM_REGISTER,	  5	    },
    {	"pim-register",	    DEBUG_PIM_REGISTER,	  5	    },
    {	"rpf",		    DEBUG_RPF,		  3	    },
    {	"timeout",	    DEBUG_TIMEOUT,	  2	    },
    {	"callout",	    DEBUG_TIMEOUT,	  3	    },
    {	"timers",	    DEBUG_TIMER,	  1	    },
    {	"traceroute",	    DEBUG_TRACE,	  2	    },
    {	"trace",	    DEBUG_TRACE,	  2	    },
    {	"mtrace",	    DEBUG_TRACE,	  2	    },
};

int log_nmsgs = 0;
int loglevel = LOG_NOTICE;
unsigned long debug = 0x00000000;        /* If (long) is smaller than
					  * 4 bytes, then we are in
					  * trouble.
					  */
static int log_syslog = 0;


char *packet_kind(int proto, int type, int code)
{
    static char unknown[60];

    switch (proto) {
	case IPPROTO_IGMP:
	    switch (type) {
		case IGMP_MEMBERSHIP_QUERY:     return "IGMP Membership Query    ";
		case IGMP_V1_MEMBERSHIP_REPORT: return "IGMP v1 Membership Report";
		case IGMP_V2_MEMBERSHIP_REPORT: return "IGMP v2 Membership Report";
		case IGMP_V3_MEMBERSHIP_REPORT: return "IGMP v3 Membership Report";
		case IGMP_V2_LEAVE_GROUP:       return "IGMP Leave message       ";
		case IGMP_DVMRP:
		    switch (code) {
			case DVMRP_PROBE:          return "DVMRP Neighbor Probe     ";
			case DVMRP_REPORT:         return "DVMRP Route Report       ";
			case DVMRP_ASK_NEIGHBORS:  return "DVMRP Neighbor Request   ";
			case DVMRP_NEIGHBORS:      return "DVMRP Neighbor List      ";
			case DVMRP_ASK_NEIGHBORS2: return "DVMRP Neighbor request 2 ";
			case DVMRP_NEIGHBORS2:     return "DVMRP Neighbor list 2    ";
			case DVMRP_PRUNE:          return "DVMRP Prune message      ";
			case DVMRP_GRAFT:          return "DVMRP Graft message      ";
			case DVMRP_GRAFT_ACK:      return "DVMRP Graft message ack  ";
			case DVMRP_INFO_REQUEST:   return "DVMRP Info Request       ";
			case DVMRP_INFO_REPLY:     return "DVMRP Info Reply         ";
			default:
			    snprintf(unknown, sizeof(unknown), "UNKNOWN DVMRP message code = %3d ", code);
			    return unknown;
		    }

		case IGMP_PIM:
		    /* The old style (PIM v1) encapsulation of PIM messages
		     * inside IGMP messages.
		     */
		    /* PIM v1 is not implemented but we just inform that a message
		     *	has arrived.
		     */
		    switch (code) {
			case PIM_V1_QUERY:         return "PIM v1 Router-Query      ";
			case PIM_V1_REGISTER:      return "PIM v1 Register          ";
			case PIM_V1_REGISTER_STOP: return "PIM v1 Register-Stop     ";
			case PIM_V1_JOIN_PRUNE:    return "PIM v1 Join/Prune        ";
			case PIM_V1_RP_REACHABILITY:
			    return "PIM v1 RP-Reachability   ";

			case PIM_V1_ASSERT:        return "PIM v1 Assert            ";
			case PIM_V1_GRAFT:         return "PIM v1 Graft             ";
			case PIM_V1_GRAFT_ACK:     return "PIM v1 Graft_Ack         ";
			default:
			    snprintf(unknown, sizeof(unknown), "UNKNOWN PIM v1 message type =%3d ", code);
			    return unknown;
		    }

		case IGMP_MTRACE:              return "IGMP trace query         ";
		case IGMP_MTRACE_RESP:         return "IGMP trace reply         ";
		default:
		    snprintf(unknown, sizeof (unknown), "UNKNOWN IGMP message: type = 0x%02x, code = 0x%02x ", type, code);
		    return unknown;
	    }

	case IPPROTO_PIM:    /* PIM v2 */
	    switch (type) {
		case PIM_V2_HELLO:             return "PIM v2 Hello             ";
		case PIM_V2_REGISTER:          return "PIM v2 Register          ";
		case PIM_V2_REGISTER_STOP:     return "PIM v2 Register_Stop     ";
		case PIM_V2_JOIN_PRUNE:        return "PIM v2 Join/Prune        ";
		case PIM_V2_BOOTSTRAP:         return "PIM v2 Bootstrap         ";
		case PIM_V2_ASSERT:            return "PIM v2 Assert            ";
		case PIM_V2_GRAFT:             return "PIM-DM v2 Graft          ";
		case PIM_V2_GRAFT_ACK:         return "PIM-DM v2 Graft_Ack      ";
		case PIM_V2_CAND_RP_ADV:       return "PIM v2 Cand. RP Adv.     ";
		default:
		    snprintf(unknown, sizeof(unknown), "UNKNOWN PIM v2 message type =%3d ", type);
		    return unknown;
	    }

	default:
	    snprintf(unknown, sizeof(unknown), "UNKNOWN proto =%3d               ", proto);
	    return unknown;
    }
}


/*
 * Used for debugging particular type of messages.
 */
int debug_kind(int proto, int type, int code)
{
    switch (proto) {
	case IPPROTO_IGMP:
	    switch (type) {
		case IGMP_MEMBERSHIP_QUERY:        return DEBUG_IGMP;
		case IGMP_V1_MEMBERSHIP_REPORT:    return DEBUG_IGMP;
		case IGMP_V2_MEMBERSHIP_REPORT:    return DEBUG_IGMP;
		case IGMP_V3_MEMBERSHIP_REPORT:    return DEBUG_IGMP;
		case IGMP_V2_LEAVE_GROUP:          return DEBUG_IGMP;
		case IGMP_DVMRP:
		    switch (code) {
			case DVMRP_PROBE:              return DEBUG_DVMRP_PEER;
			case DVMRP_REPORT:             return DEBUG_DVMRP_ROUTE;
			case DVMRP_ASK_NEIGHBORS:      return 0;
			case DVMRP_NEIGHBORS:          return 0;
			case DVMRP_ASK_NEIGHBORS2:     return 0;
			case DVMRP_NEIGHBORS2:         return 0;
			case DVMRP_PRUNE:              return DEBUG_DVMRP_PRUNE;
			case DVMRP_GRAFT:              return DEBUG_DVMRP_PRUNE;
			case DVMRP_GRAFT_ACK:          return DEBUG_DVMRP_PRUNE;
			case DVMRP_INFO_REQUEST:       return 0;
			case DVMRP_INFO_REPLY:         return 0;
			default:                       return 0;
		    }
		    break;

		case IGMP_PIM:
		    /* PIM v1 is not implemented */
		    switch (code) {
			case PIM_V1_QUERY:             return DEBUG_PIM;
			case PIM_V1_REGISTER:          return DEBUG_PIM;
			case PIM_V1_REGISTER_STOP:     return DEBUG_PIM;
			case PIM_V1_JOIN_PRUNE:        return DEBUG_PIM;
			case PIM_V1_RP_REACHABILITY:   return DEBUG_PIM;
			case PIM_V1_ASSERT:            return DEBUG_PIM;
			case PIM_V1_GRAFT:             return DEBUG_PIM;
			case PIM_V1_GRAFT_ACK:         return DEBUG_PIM;
			default:                       return DEBUG_PIM;
		    }
		    break;

		case IGMP_MTRACE:                  return DEBUG_TRACE;
		case IGMP_MTRACE_RESP:             return DEBUG_TRACE;
		default:                           return DEBUG_IGMP;
	    }

	case IPPROTO_PIM:       /* PIM v2 */
	    /* TODO: modify? */
	    switch (type) {
		case PIM_V2_HELLO:             return DEBUG_PIM;
		case PIM_V2_REGISTER:          return DEBUG_PIM_REGISTER;
		case PIM_V2_REGISTER_STOP:     return DEBUG_PIM_REGISTER;
		case PIM_V2_JOIN_PRUNE:        return DEBUG_PIM;
		case PIM_V2_BOOTSTRAP:         return DEBUG_PIM_BOOTSTRAP;
		case PIM_V2_ASSERT:            return DEBUG_PIM;
		case PIM_V2_GRAFT:             return DEBUG_PIM;
		case PIM_V2_GRAFT_ACK:         return DEBUG_PIM;
		case PIM_V2_CAND_RP_ADV:       return DEBUG_PIM_CAND_RP;
		default:                       return DEBUG_PIM;
	    }
	    break;

	default:                               return 0;
    }

    return 0;
}

/*
 * Two questions, one function, and the mask says which: DEBUG_ALL is the
 * usage text and `pimctl debug ?` asking what subsystems there are, any
 * other mask is somebody asking which of them are on.
 */
int debug_list(int mask, char *buf, size_t len)
{
    struct debugname *d;
    uint32_t last = 0;
    size_t i;
    int pass;

    memset(buf, 0, len);

    /* What there is: one name per subsystem, in the order of the table.
     * DEBUG_TIMEOUT is not part of DEBUG_ALL, so it is not listed here
     * either, and is asked for by name. */
    if ((uint32_t)mask == DEBUG_ALL) {
	for (i = 0, d = debugnames; i < NELEMS(debugnames); i++, d++) {
	    if (!(mask & d->level))
		continue;

	    if (last == d->level)
		continue;
	    last = d->level;

	    if (*buf)
		strlcat(buf, ", ", len);
	    strlcat(buf, d->name, len);
	}

	return 0;
    }

    /*
     * What is on.  A row answers only when every bit it names is set: the
     * first row of the table is "all", which carries DEBUG_ALL and so
     * shares a bit with every mask there is, and matching on that made it
     * the answer to anything -- `pimctl debug pim_jp` replied "all", and so
     * did the startup line of a daemon started with -d anything.
     *
     * Rows carrying several bits go first, so that "pim" is the answer for
     * the nine subsystems it stands for rather than the nine answering one
     * at a time, and a row takes its bits out of the mask as it prints, so
     * that the same subsystem under another name is not printed twice.
     */
    for (pass = 0; pass < 2; pass++) {
	for (i = 0, d = debugnames; i < NELEMS(debugnames); i++, d++) {
	    int several = (d->level & (d->level - 1)) != 0;

	    /* Pass 0 is the rows carrying several bits, pass 1 the rest */
	    if (several != (pass == 0))
		continue;

	    if (((uint32_t)mask & d->level) != d->level)
		continue;
	    mask &= ~d->level;

	    if (*buf)
		strlcat(buf, ", ", len);
	    strlcat(buf, d->name, len);
	}
    }

    return 0;
}

int debug_parse(char *arg)
{
    struct debugname *d;
    size_t i, len;
    char *next = NULL;
    int sys = 0;

    if (!arg || !strlen(arg) || strstr(arg, "none"))
	return sys;

    while (arg) {
	int no = 0;

	next = strchr(arg, ',');
	if (next)
	    *next++ = '\0';
	/* disable log level if flag preceded by '-' */
	if (arg[0] == '-') {
	    arg++;
	    no = 1;
	}

	len = strlen(arg);
	for (i = 0, d = debugnames; i < NELEMS(debugnames); i++, d++) {
	    if (len >= d->nchars && strncmp(d->name, arg, len) == 0)
		break;
	}

	if (i == NELEMS(debugnames))
	    return DEBUG_PARSE_FAIL;

	if (no)
	    sys &= ~d->level;
	else
	    sys |= d->level;
	arg = next;
    }

    return sys;
}

/*
 * Some messages are more important than others.  This routine
 * determines the logging level at which to log a send error (often
 * "No route to host").  This is important when there is asymmetric
 * reachability and someone is trying to, i.e., mrinfo me periodically.
 */
int log_level(int proto, int type, int code)
{
    switch (proto) {
	case IPPROTO_IGMP:
	    switch (type) {
		case IGMP_MTRACE_RESP:
		    return LOG_INFO;

		case IGMP_DVMRP:
		    switch (code) {
			case DVMRP_NEIGHBORS:
			case DVMRP_NEIGHBORS2:
			    return LOG_INFO;
		    }
		    return LOG_WARNING;

		case IGMP_PIM:
		    /* PIM v1 */
		    switch (code) {
			default:
			    return LOG_INFO;
		    }
		    return LOG_WARNING;

		default:
		    return LOG_WARNING;
	    }

	case IPPROTO_PIM:
	    /* PIM v2 */
	    switch (type) {
		default:
		    return LOG_INFO;
	    }
	    return LOG_WARNING;

	default:
	    return LOG_WARNING;
    }
    return LOG_WARNING;
}

void log_init(int do_syslog)
{
    int log_opts = LOG_PID;

    log_syslog = do_syslog;

#ifdef LOG_DAEMON
    openlog(ident, log_opts, LOG_DAEMON);
    setlogmask(LOG_UPTO(loglevel));
#else
    openlog(ident, log_opts);
#endif
}

int log_str2lvl(char *level)
{
    int i;

    for (i = 0; prioritynames[i].c_name; i++) {
	size_t len = MIN(strlen(prioritynames[i].c_name), strlen(level));

	if (!strncasecmp(prioritynames[i].c_name, level, len))
	    return prioritynames[i].c_val;
    }

    return atoi(level);
}

const char *log_lvl2str(int val)
{
    int i;

    for (i = 0; prioritynames[i].c_name; i++) {
	if (prioritynames[i].c_val == val)
	    return prioritynames[i].c_name;
    }

    return "unknown";
}

int log_list(char *buf, size_t len)
{
    int i;

    memset(buf, 0, len);
    for (i = 0; prioritynames[i].c_name; i++) {
	if (i > 0)
	    strlcat(buf, ", ", len);
	strlcat(buf, prioritynames[i].c_name, len);
    }

    return 0;
}

/*
 * Log errors and other messages to the system log daemon and to stderr,
 * according to the severity of the message and the current debug level.
 * For errors of severity LOG_ERR or worse, terminate the program.
 */
/*
 * Put one rendered line where the log goes: stderr with a timestamp in the
 * foreground, the system log daemon otherwise.
 *
 * Split out of logit() because under privilege separation this runs in the
 * *privileged* half, on lines the unprivileged one sends over.  One
 * process then stamps every line, which is not a nicety: the unprivileged
 * half is chroot'ed, so /etc/localtime is not there for it to read, and
 * glibc retries that open on every localtime() call rather than giving up
 * once -- which under the seccomp filter, where open is not on the
 * allowlist, is a SIGSYS on the first line logged after the sandbox goes
 * up.  The daemon died there with nothing in its own log to say why.
 */
void log_emit(int severity, int syserr, const char *msg)
{
    struct timeval now;
    struct tm *thyme;
    time_t lt;

    /* pimd running in foreground */
    if (!log_syslog) {
	gettimeofday(&now, NULL);
	lt = now.tv_sec;
	thyme = localtime(&lt);

//	if (!debug)
	    fprintf(stderr, "%s: ", ident);

	/* localtime() answers NULL for a time it cannot break down, and
	 * losing the message is the one thing this function may not do:
	 * print it without the timestamp rather than dereference that. */
	if (thyme)
	    fprintf(stderr, "%02d:%02d:%02d.%03ld %s", thyme->tm_hour, thyme->tm_min,
		    thyme->tm_sec, (long int)(now.tv_usec / 1000), msg);
	else
	    fprintf(stderr, "%s", msg);

	if (syserr)
	    fprintf(stderr, ": %s", strerror(syserr));

	fprintf(stderr, "\n");
	return;
    }

    if (syserr)
	syslog(severity, "%s: %s", msg, strerror(syserr));
    else
	syslog(severity, "%s", msg);
}

/*
 * One rendered line to wherever the log is, past every filter: the
 * privileged half when there is one, this process when there is not.
 *
 * Separate from log_emit() because the two are not the same side under
 * privilege separation, and separate from logit() because resetlogging()
 * (src/main.c) has to be able to say that the rate limiter has shut the
 * log up -- a message the limiter would otherwise be the first to drop.
 */
void log_line(int severity, int syserr, const char *msg)
{
    if (priv_enabled())
	priv_log(severity, syserr, msg);
    else
	log_emit(severity, syserr, msg);
}

/*
 * Log errors and other messages to the system log daemon and to stderr,
 * according to the severity of the message and the current debug level.
 * For errors of severity LOG_ERR or worse, terminate the program.
 */
void logit(int severity, int syserr, const char *format, ...)
{
    va_list ap;
    char msg[211];

    va_start(ap, format);
    vsnprintf(msg, sizeof(msg), format, ap);
    va_end(ap);

    /*
     * Filtered on this side whichever half we are, and for the same reason
     * the rate limiter below is counted here: "pimctl loglevel" changes
     * loglevel in the unprivileged half and resetlogging() runs its timer
     * there, so a privileged half deciding either would be working from
     * the values it was forked with.
     */
    if (!log_syslog) {
	if (!debug && severity > loglevel)
	    goto done;
    } else {
	/*
	 * Always log things that are worse than warnings, no matter what
	 * the log_nmsgs rate limiter says.
	 *
	 * Only count things at the defined loglevel or worse in the rate
	 * limiter and exclude debugging (since if you put daemon.debug in
	 * syslog.conf you probably actually want to log the debugging
	 * messages so they shouldn't be rate-limited)
	 */
	if (severity >= LOG_WARNING && log_nmsgs >= LOG_MAX_MSGS)
	    goto done;

	if ((severity <= loglevel) && (severity != LOG_DEBUG))
	    log_nmsgs++;
    }

    /* The unprivileged half reaches neither /var/run/log, which syslog(3)
     * connects to by path, nor /etc/localtime -- hand the line to the
     * privileged half, which has both. */
    log_line(severity, syserr, msg);

  done:
#ifdef CONTINUE_ON_ERROR
    return;			/* A label wants a statement after it, and
				 * with CONTINUE_ON_ERROR the exit below is
				 * not compiled in */
#else
    if (severity <= LOG_ERR)
	exit(-1);		/* Exit status: 255 */
#endif
}


/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
