check-log4j
===========

This tool will try to determine if the host it is
running on is likely vulnerable to the latest reason
that [the internet is on
fire](https://istheinternetonfire.com): the [log4j
RCE](https://logging.apache.org/log4j/2.x/security.html)
[CVE‐2021‐44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228).

This is different from other tools that attempt to
verify whether a specific service is vulnerable by
triggering the exploit and e.g., tracking pingbacks on
a DNS canary token.  That approach tells you whether a
_service_ is vulnerable, but it doesn't even tell you
which _specific systems_: the payload may have been
proxied on to another system and from there logged via
`log4j` on yet another one.  So inspection of the
service does not tell you that that specific host is
vulnerable.

On the other hand, host owners may not know whether
they have a vulnerable version of `log4j` on their
system: The `log4j` package may be pulled in as a
dependency by various packages, or included inside a
Java application jar.

The `check-log4j` tool attempts to give host owners a
tool to determine likely vulnerability by looking at
running java processes and inside of any common Java
archive files found.

Please see the [manual
page](./doc/check-log4j.1.txt) for full
details.

Installation
============

To install the command and manual page somewhere
convenient, run `make install`; the Makefile defaults
to '/usr/local' but you can change the PREFIX:

```
$ make PREFIX=~ install
```

FAQ
===

## Dude, this is a shell script. You suck. Why isn't this written in $MyFavoriteLanguage?

`check-log4j` is intended to run on any Unix-like
system without depending on any particular language
runtime.  It's not pretty, but hey.

## Why does it say "Possibly vulnerable"?

Actual vulnerability depends on runtime configuration.
`check-log4j` basically checks whether
`JndiLookup.class` found in any archive files.  If so,
the system becomes suspect.  If `check-log4j` can
determine that this might be a `log4j-2.16.x` version,
it will remain silent, but otherwise, it simply
doesn't know whether that class might be used or
just sits there as an unused dependency or what.

## This doesn't work on my system, explodes in some way, or doesn't correctly detect a vulnerable host!

I'm sorry.  Please let me know about this via email or
a GitHub issue or, better yet, a pull request with a
fix.


Documentation
=============

```
NAME
     check-log4j -- try to determine if a host is vulnerable to log4j
     CVE-2021-44228

SYNOPSIS
     check-log4j [-fhv] [-j jar] [-p path] [-s skip]

DESCRIPTION
     The check-log4j tool attempts to determine whether the host it is exe-
     cuted on is vulnerable to the logj4 RCE vulnerability identified as
     CVE-2021-4428.

     Since this vulnerability is in a specific Java class that may be inside
     nested Java archive files, check-log4j may be somewhat intrusive to run
     and should be executed with care and consideration of the system's load.
     Please see DETAILS for more information.

OPTIONS
     The following options are supported by check-log4j:

     -f	      Attempt to apply mitigations for the vulnerability.  (This
	      requires super-user privileges.)

     -h	      Print a short help message and exit.

     -j jar   Check only this archive, nothing else.  Can be specified multi-
	      ple times for multiple JAR (or other zip formatted archive)
	      files.

     -p path  Limit filesystem traversal to this directory.  Can be specified
	      multiple times.  If not specified, check-log4j will default to
	      '/'.

     -s skip  Skip the given checks.  Valid arguments are 'files', 'packages',
	      and 'processes'.

     -v	      Be verbose.  Can be specified multiple times.

DETAILS
     CVE-2021-4428 describes a possible remote code execution (RCE) vulnera-
     bility in the popular log4j framework.  Simply causing the vulnerable
     system to log a specifically crafted message can the attacker gain com-
     mand execution and information disclosure capabilities.  This vulnerabil-
     ity relies on an insecure default setting applying to the Java Naming and
     Directory Interface (JNDI).

     Specifically, a system that contains the JndiLookup.class may enable the
     attack path in question.

     To determine whether a host is vulnerable, the check-log4j tool will per-
     form the following checks:
     o	 check for the existence of likely vulnerable packages
     o	 check for the existence of java processes using the 'JndiLookup'
	 class

     The discovery process may include running find(1), lsof(1), or rpm(1);
     please use the -s flag to skip any checks that might have a negative
     impact on your host.

     The output of the command attempts to be human readable and provide suf-
     ficient information to judge whether the host requires attention.

EXAMPLES
     Sample invocation on a non-vulnerable host:

	   $ check-log4j
	   No obvious indicators of vulnerability found.
	   $

     Sample invocation only looking at processes

	   $ ./check-log4j.sh -s files -s packages -v -v
	   => Running all checks...
	   ==> Skipping package check.
	   ==> Looking for jars...
	   ==> Skipping files check.
	   ==> Checking all found jars...
	   check-log4j.sh 1.0 localhost: Possibly vulnerable jar 'BOOT-INF/lib/log4j-core-2.14.1.jar' (inside of /home/jans/log4shell-vulnerable-app-0.0.1-SNAPSHOT.jar) used by process 15569.

	   $

     Sample invocation searching only /var and /usr/local/lib and skipping
     package and process checks:

	   $ check-log4j -p /var -p /usr/local/lib -s packages -s processes
	   Possibly vulnerable jar '/usr/local/lib/jars/log4j-core-2.15.0.jar'.
	   Possibly vulnerable jar '/usr/local/lib/jars/log4j-core-2.15.jar'.
	   Possibly vulnerable jar '/usr/local/lib/jars/log4j-core-2.jar'.
	   Possibly vulnerable jar '/usr/local/lib/jars/log4j-core.jar'.

	   $

     Note version comparisons are only done for packages, which is why the
     above output incudes files ending in a seemingly non-vulnerable version.

EXIT STATUS
     check-log4j will return 0 if the host was found not to be vulnerable and
     greater than 0 otherwise.

SEE ALSO
     find(1), lsof(1), rpm(1)

HISTORY
     check-log4j was originally written by Jan Schaumann <jans@yahooinc.com>
     in December 2021.

BUGS
     Please file bugs and feature requests by emailing the author.
```
