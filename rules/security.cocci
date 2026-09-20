/* security.cocci - static bug patterns for pimd, for Coccinelle's spatch(1)
 *
 * The checklist of doc/security-review-prompt.md, in the part of it a
 * machine can decide, plus the four rules CLAUDE.md asks for at the point
 * of writing and a handful that are about this tree in particular rather
 * than about C.  Run it with rules/run.sh; the tree is clean, so anything
 * it prints is a regression.
 *
 * Every rule here fires on rules/control.c, which collects one instance of
 * each pattern.  Keep it that way: a rule that matches nothing is
 * indistinguishable from a rule that is broken, and the control file is
 * what tells the two apart.
 *
 * Usage:
 *	spatch --very-quiet --sp-file rules/security.cocci --dir src
 *
 * One --dir per run: spatch(1) honours only the last one on its command
 * line and silently drops any earlier one, which is why rules/run.sh walks
 * src/ and lib/ one at a time.
 *
 * No alternation in an identifier's =~ constraint.  spatch(1) borrows its
 * regular expressions from whatever it was built against, and `spatch
 * --version' says which: PCRE on FreeBSD, Str on Debian and Ubuntu, where
 * `(' `|' `)' are ordinary characters and "^(memcpy|memmove)$" matches the
 * name "(memcpy|memmove)" -- nothing, silently, which is exactly what a
 * clean run looks like.  Eight rules here were dead that way on Ubuntu.
 * The names a rule cares about are listed below and tested in its script
 * instead; what =~ still does is anchored prefixes and character classes,
 * which both engines read the same.
 */

@initialize:python@
@@

copy_sized = ("memcpy", "memmove", "memset", "memcmp", "bcopy", "bzero",
	      "strlcpy", "strlcat", "strncpy", "strncat", "snprintf",
	      "read", "write", "recv", "recvfrom", "send", "sendto")
copy_unbounded = ("strcpy", "strcat", "sprintf", "vsprintf", "gets", "alloca")
allocators = ("malloc", "calloc", "realloc", "strdup", "strndup")
printf_like = ("printf", "vprintf")
fprintf_like = ("fprintf", "dprintf", "vfprintf", "syslog")
inet_fmt_like = ("inet_fmt", "inet_fmts", "inet_name")
vif_lookups = ("find_vif", "find_vif_direct", "find_vif_direct_local",
	       "find_vif_name", "local_address", "get_iif")

// --------------------------------------------------------------------
// Copy and buffer hygiene -- CWE-120/121/787, SEI CERT STR31-C
// --------------------------------------------------------------------

// strncpy() bounded by the destination's own sizeof leaves the result
// unterminated on truncation.  lib/ has strlcpy(); use it.
//
@strncpy_unterminated@
expression dst, src;
position p;
@@
strncpy@p(dst, src, sizeof(dst))

@script:python@
p << strncpy_unterminated.p;
@@
print("%s:%s: [strncpy_unterminated] strncpy() bounded by sizeof(dst) may leave it unterminated, use strlcpy()"
      % (p[0].file, p[0].line))

# sizeof(pointer) as a length: the size of the pointer, not of what it
# points at.  Catches memcpy(p, q, sizeof(p)) and memset(p, 0, sizeof(p)).
#
@sizeof_pointer@
identifier f;
type T;
T *ptr;
position p;
@@
f@p(..., sizeof(ptr), ...)

@script:python@
p << sizeof_pointer.p;
f << sizeof_pointer.f;
@@
if f in copy_sized:
    print("%s:%s: [sizeof_pointer] %s() sized with sizeof(pointer), not sizeof(*pointer)"
          % (p[0].file, p[0].line, f))

# Unbounded copy primitives.  Use the lib/ wrappers instead.
@unbounded_copy@
identifier f;
position p;
@@
f@p(...)

@script:python@
p << unbounded_copy.p;
f << unbounded_copy.f;
@@
if f in copy_unbounded:
    print("%s:%s: [unbounded_copy] %s() is unbounded, use the lib/ wrapper (strlcpy/strlcat/snprintf)"
          % (p[0].file, p[0].line, f))

# memset(p, sizeof(x), 0): the length and the fill swapped.
@memset_swapped@
expression p1, sz;
position p;
@@
memset@p(p1, sizeof(sz), ...)

@script:python@
p << memset_swapped.p;
@@
print("%s:%s: [memset_swapped] memset() fill and length look swapped" % (p[0].file, p[0].line))

# --------------------------------------------------------------------
# Allocation -- CWE-131/761, SEI CERT MEM35-C
# --------------------------------------------------------------------

# x = malloc(sizeof(x)) allocates a pointer's worth, not an object's.
@alloc_sizeof_pointer@
type T;
T *x;
position p;
@@
(
x = malloc@p(sizeof(x))
|
x = malloc@p(sizeof(T *))
|
x = calloc@p(..., sizeof(x))
|
x = realloc@p(..., sizeof(x))
)

@script:python@
p << alloc_sizeof_pointer.p;
@@
print("%s:%s: [alloc_sizeof_pointer] allocation sized with sizeof(pointer), not sizeof(*pointer)"
      % (p[0].file, p[0].line))

# An allocation dereferenced before anything asked whether it succeeded.
#
@unchecked_alloc exists@
identifier f;
identifier x;
identifier fld;
type T;
expression E;
position p;
@@
(
T x = f(...);
|
x = f(...);
)
... when != \(x == NULL\|x != NULL\|!x\)
    when != x = ...
(
* x@p->fld
|
* *x@p
|
* x@p[E]
)

@script:python@
p << unchecked_alloc.p;
f << unchecked_alloc.f;
@@
if f in allocators:
    print("%s:%s: [unchecked_alloc] allocation dereferenced with no NULL test"
          % (p[0].file, p[0].line))

# --------------------------------------------------------------------
# Format strings -- CWE-134
# --------------------------------------------------------------------
#
# A format string that is not a literal lets whoever supplies it read the
# stack with %x and write memory with %n.  gcc and clang find these with
# -Wformat-security, which is not in pimd_CFLAGS (src/Makefile.am has
# -W -Wall -Wextra -Wno-unused), so nothing else in the build looks.
#
# An identifier can never bind to a string literal, so spelling the format
# argument as one is what separates printf(buf) from printf("%s", buf).
#
@fmt_printf@
identifier f;
identifier fmt;
position p;
@@
f@p(fmt)

@script:python@
p << fmt_printf.p;
f << fmt_printf.f;
@@
if f in printf_like:
    print("%s:%s: [fmt_printf] %s() format string is not a literal"
          % (p[0].file, p[0].line, f))

@fmt_fprintf@
identifier f;
identifier fmt;
expression E;
position p;
@@
f@p(E, fmt)

@script:python@
p << fmt_fprintf.p;
f << fmt_fprintf.f;
@@
if f in fprintf_like:
    print("%s:%s: [fmt_fprintf] %s() format string is not a literal"
          % (p[0].file, p[0].line, f))

@fmt_sized@
identifier fmt;
expression E1, E2;
position p;
@@
(
* snprintf@p(E1, E2, fmt)
|
* logit@p(E1, E2, fmt)
)

@script:python@
p << fmt_sized.p;
@@
print("%s:%s: [fmt_sized] format string is not a literal"
      % (p[0].file, p[0].line))

# --------------------------------------------------------------------
# Integer and conversion hazards -- CWE-190/197/681
# --------------------------------------------------------------------

# Byte-order conversion applied to an object of the wrong width: the
# 16-bit form on a 32-bit value silently keeps half of it.
#
@byteorder_wide@
typedef uint32_t;
uint32_t E;
position p;
@@
(
ntohs@p(E)
|
htons@p(E)
)

@script:python@
p << byteorder_wide.p;
@@
print("%s:%s: [byteorder_wide] 16-bit byte-order conversion applied to a 32-bit object"
      % (p[0].file, p[0].line))

@byteorder_narrow@
typedef uint16_t;
typedef uint8_t;
{uint16_t, uint8_t, unsigned short, unsigned char} E;
position p;
@@
(
ntohl@p(E)
|
htonl@p(E)
)

@script:python@
p << byteorder_narrow.p;
@@
print("%s:%s: [byteorder_narrow] 32-bit byte-order conversion applied to a narrower object"
      % (p[0].file, p[0].line))

# A 32-bit network value stored in a 16- or 8-bit variable.
@truncating_store@
typedef uint16_t;
typedef uint8_t;
{uint16_t, uint8_t, unsigned short, unsigned char} v;
expression E;
position p;
@@
(
v@p = ntohl(E)
|
v@p = htonl(E)
)

@script:python@
p << truncating_store.p;
@@
print("%s:%s: [truncating_store] 32-bit value truncated into a narrower variable"
      % (p[0].file, p[0].line))

# --------------------------------------------------------------------
# Expression and control-flow mistakes -- CWE-480/481/570/571
# --------------------------------------------------------------------

# if (x = y): assignment where a comparison was meant.
@assign_in_cond@
identifier x;
expression E;
statement S;
position p;
@@
if@p (x = E) S

@script:python@
p << assign_in_cond.p;
@@
print("%s:%s: [assign_in_cond] assignment inside an if() condition" % (p[0].file, p[0].line))

# !x & y and !x | y: the negation binds tighter than the bit operator,
# which is almost never what was written.
#
@bang_precedence@
expression E1, E2;
position p;
@@
(
!E1@p & E2
|
!E1@p | E2
)

@script:python@
p << bang_precedence.p;
@@
print("%s:%s: [bang_precedence] ! binds tighter than the bit operator here, parenthesise"
      % (p[0].file, p[0].line))

# x & FLAG == V: == binds tighter than & and |.
@cmp_precedence@
expression E1, E2, E3;
position p;
@@
(
E1 & E2@p == E3
|
E1 & E2@p != E3
|
E1 | E2@p == E3
|
E1 | E2@p != E3
)

@script:python@
p << cmp_precedence.p;
@@
print("%s:%s: [cmp_precedence] == binds tighter than & and |, parenthesise the mask test"
      % (p[0].file, p[0].line))

# The same sub-expression on both sides of && or ||.
@dup_operand@
expression E;
position p;
@@
(
E@p || ... || E
|
E@p && ... && E
)

@script:python@
p << dup_operand.p;
@@
print("%s:%s: [dup_operand] the same sub-expression appears twice in this condition"
      % (p[0].file, p[0].line))

# if (E) S else if (E) S2: the second arm is dead.
@dup_elseif@
expression E;
statement S1, S2;
position p;
@@
if@p (E) S1 else if (E) S2

@script:python@
p << dup_elseif.p;
@@
print("%s:%s: [dup_elseif] duplicated condition, the else-if arm is dead"
      % (p[0].file, p[0].line))

# if (E) S else S: both arms identical.
@same_branches@
expression E;
statement S;
position p;
@@
if@p (E) S else S

@script:python@
p << same_branches.p;
@@
print("%s:%s: [same_branches] both arms of this if() are identical" % (p[0].file, p[0].line))

# E op E: a comparison of something with itself.
@self_compare@
expression E;
position p;
@@
(
E@p == E
|
E@p != E
|
E@p < E
|
E@p > E
)

@script:python@
p << self_compare.p;
@@
print("%s:%s: [self_compare] expression compared with itself" % (p[0].file, p[0].line))

# x = x: a self-assignment, usually a typo for a neighbouring field.
@self_assign@
identifier x;
position p;
@@
x@p = x;

@script:python@
p << self_assign.p;
@@
print("%s:%s: [self_assign] self-assignment" % (p[0].file, p[0].line))

# --------------------------------------------------------------------
# pimd's own idioms
# --------------------------------------------------------------------

# inet_fmt() and friends format into a caller-supplied static buffer, and
# s1..s4 in inet.c are the ones every log line uses.  Two of them in one
# call sharing a buffer print the same address twice: the second call has
# overwritten the first before printf() reads either.
#
@inetfmt_alias@
identifier buf =~ "^s[1-4]$";
identifier other =~ "^s[1-4]$";
identifier f;
identifier g;
identifier h;
expression a, b;
position p;
@@
h(..., f(a, buf, ...), ..., g(b, other, ...), ...)@p

@script:python@
p << inetfmt_alias.p;
buf << inetfmt_alias.buf;
other << inetfmt_alias.other;
f << inetfmt_alias.f;
g << inetfmt_alias.g;
@@
if buf == other and f in inet_fmt_like and g in inet_fmt_like:
    print("%s:%s: [inetfmt_alias] static buffer %s formatted twice in one call, both read back the same"
          % (p[0].file, p[0].line, buf))

# inet_fmt(x, s1, sizeof(s2)): the length of a different buffer.
@inetfmt_mismatch@
identifier buf =~ "^s[1-4]$";
identifier other =~ "^s[1-4]$";
identifier f;
expression a;
position p;
@@
f@p(a, buf, sizeof(other))

@script:python@
p << inetfmt_mismatch.p;
buf << inetfmt_mismatch.buf;
other << inetfmt_mismatch.other;
f << inetfmt_mismatch.f;
@@
if buf != other and f in inet_fmt_like:
    print("%s:%s: [inetfmt_mismatch] buffer %s sized with sizeof(%s)"
          % (p[0].file, p[0].line, buf, other))

# "Bound before parsing": a PIM message handler that never compares its
# len argument against anything.  PIM_JOIN_PRUNE_MINLEN,
# PIM_BOOTSTRAP_MINLEN, PIM_CAND_RP_ADV_MINLEN and PIM_ASSERT_MINLEN are
# what this is asking for.  receive_pim_assert() once parsed 26 bytes out
# of a message pim.c guarantees only 4 of.
#
@unbounded_handler exists@
identifier f =~ "^receive_pim_";
identifier msg, len;
type T;
position p;
@@
T f@p(..., char *msg, size_t len) {
... when != \(len < ...\|len <= ...\|len > ...\|len >= ...\|len == ...\|len != ...\)
}

@script:python@
p << unbounded_handler.p;
f << unbounded_handler.f;
@@
print("%s:%s: [unbounded_handler] %s() never bounds-checks its len argument"
      % (p[0].file, p[0].line, f))

# NO_VIF is MAXVIFS, one past the end of uvifs[].  An index that came out
# of a lookup is checked against it before it subscripts anything.
#
@unchecked_vif exists@
identifier v;
expression numvifs;
identifier f;
position p;
@@
v = f(...);
... when != \(v == NO_VIF\|v != NO_VIF\|v < numvifs\|v >= numvifs\|v = ...\)
* uvifs[v]@p

@script:python@
p << unchecked_vif.p;
f << unchecked_vif.f;
@@
if f in vif_lookups:
    print("%s:%s: [unchecked_vif] uvifs[] subscripted with a lookup result that was not tested against NO_VIF"
          % (p[0].file, p[0].line))
