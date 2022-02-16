/* $OpenBSD: scp.c,v 1.214 2021/04/03 06:18:40 djm Exp $ */
/*
 * scp - secure remote copy.  This is basically patched BSD rcp which
 * uses ssh to do the data transfer (instead of using rcmd).
 *
 * NOTE: This version should NOT be suid root.  (This uses ssh to
 * do the transfer and ssh has the necessary privileges.)
 *
 * 1995 Timo Rinne <tri@iki.fi>, Tatu Ylonen <ylo@cs.hut.fi>
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1999 Aaron Campbell.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Parts from:
 *
 * Copyright (c) 1983, 1990, 1992, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "includes.h"

#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_POLL_H
#include <poll.h>
#else
# ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
# endif
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <sys/wait.h>
#include <sys/uio.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif
#include <limits.h>
#include <locale.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "openbsd-compat/glob.h"
#if defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#include <vis.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "atomicio.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "progressmeter.h"
#include "utf8.h"

extern char *__progname;

#define COPY_BUFLEN	16384

int do_cmd(char *host, char *remuser, int port, char *cmd, int *fdin, int *fdout);
int do_cmd2(char *host, char *remuser, int port, char *cmd, int fdin, int fdout);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
struct bwlimit bwlimit;

/* Name of current file being transferred. */
char *curfile;

/* This is set to non-zero to enable verbose mode. */
int verbose_mode = 0;

/* This is set to zero if the progressmeter is not desired. */
int showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
int throughlocal = 0;

/* Non-standard port to use for the ssh connection or -1. */
int sshport = -1;

/* This is the program to execute for the secured connection. ("ssh" or -S) */
char *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;

static void
killchild(int signo)
{
	if (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		waitpid(do_cmd_pid, NULL, 0);
	}

	if (signo)
		_exit(1);
	exit(1);
}

static void
suspchild(int signo)
{
	int status;

	if (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo);
		while (waitpid(do_cmd_pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
		kill(getpid(), SIGSTOP);
	}
}

static int
do_local_cmd(arglist *a)
{
	u_int i;
	int status;
	pid_t pid;

	if (a->num == 0)
		fatal("do_local_cmd: no arguments");

	if (verbose_mode) {
		fprintf(stderr, "Executing:");
		for (i = 0; i < a->num; i++)
			fmprintf(stderr, " %s", a->list[i]);
		fprintf(stderr, "\n");
	}
#ifdef WINDOWS
	/* flatten the cmd into a long space separated string and execute using system(cmd) api */
	{
		char* cmd;
		size_t cmdlen = 0;
		for (i = 0; i < a->num; i++)
			cmdlen += strlen(a->list[i]) + 1;

		cmd = xmalloc(cmdlen);
		cmd[0] = '\0';
		for (i = 0; i < a->num; i++) {
			char *path = a->list[i];
			if (is_bash_test_env()) {
				char resolved[PATH_MAX] = { 0, };
				convertToForwardslash(path);

				if(bash_to_win_path(path, resolved, _countof(resolved)))
					convertToBackslash(resolved);

				strcat(cmd, " ");
				strcat(cmd, resolved);
			} else {
				if (i != 0)
					strcat_s(cmd, cmdlen, " ");
				strcat_s(cmd, cmdlen, a->list[i]);
			}
		}

		wchar_t *cmd_w = utf8_to_utf16(cmd);
		if (cmd_w) {
			if (_wsystem(cmd_w))
				return -1;

			free(cmd_w);
			return 0;
		} else {
			error("%s out of memory", __func__);
			return -1;
		}
	}

#else /* !WINDOWS */
	if ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	if (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (-1);

	return (0);
#endif /* !WINDOWS */
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

int
do_cmd(char *host, char *remuser, int port, char *cmd, int *fdin, int *fdout)
{
	int pin[2], pout[2], reserved[2];

	if (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	if (port == -1)
		port = sshport;

	/*
	 * Reserve two descriptors so that the real pipes won't get
	 * descriptors 0 and 1 because that will screw up dup2 below.
	 */
	if (pipe(reserved) == -1)
		fatal("pipe: %s", strerror(errno));

	/* Create a socket pair for communicating with ssh. */
	if (pipe(pin) == -1)
		fatal("pipe: %s", strerror(errno));
	if (pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
	fcntl(pout[0], F_SETFD, FD_CLOEXEC);
	fcntl(pout[1], F_SETFD, FD_CLOEXEC);
	fcntl(pin[0], F_SETFD, FD_CLOEXEC);
	fcntl(pin[1], F_SETFD, FD_CLOEXEC);

	/* Free the reserved descriptors. */
	close(reserved[0]);
	close(reserved[1]);

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
#ifdef FORK_NOT_SUPPORTED
	replacearg(&args, 0, "%s", ssh_program);		
	if (port != -1) {
		addargs(&args, "-p");
		addargs(&args, "%d", port);
	}
	if (remuser != NULL) {
		addargs(&args, "-l");
		addargs(&args, "%s", remuser);
	}
	addargs(&args, "--");
	addargs(&args, "%s", host);
	addargs(&args, "%s", cmd);

	{
		posix_spawn_file_actions_t actions;
		do_cmd_pid = -1;

		if (posix_spawn_file_actions_init(&actions) != 0 ||
		    posix_spawn_file_actions_adddup2(&actions, pin[0], STDIN_FILENO) != 0 ||
		    posix_spawn_file_actions_adddup2(&actions, pout[1], STDOUT_FILENO) != 0 )
			fatal("posix_spawn initialization failed");
		else if (posix_spawn(&do_cmd_pid, args.list[0], &actions, NULL, args.list, NULL) != 0) 
			fatal("posix_spawn: %s", strerror(errno));
			
			posix_spawn_file_actions_destroy(&actions);
	}

#else 
	do_cmd_pid = fork();
	if (do_cmd_pid == 0) {
		/* Child. */
		close(pin[1]);
		close(pout[0]);
		dup2(pin[0], 0);
		dup2(pout[1], 1);
		close(pin[0]);
		close(pout[1]);

		replacearg(&args, 0, "%s", ssh_program);
		if (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		if (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(ssh_program, args.list);
		perror(ssh_program);
		exit(1);
	} else if (do_cmd_pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
#endif 
	/* Parent.  Close the other side, and return the local side. */
	close(pin[0]);
	*fdout = pin[1];
	close(pout[1]);
	*fdin = pout[0];
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);
	return 0;
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
int
do_cmd2(char *host, char *remuser, int port, char *cmd, int fdin, int fdout)
{
	pid_t pid;
	int status;

	if (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	if (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
#ifdef FORK_NOT_SUPPORTED
	/* generate command line and spawn_child */	
	replacearg(&args, 0, "%s", ssh_program);	
	if (port != -1) {
		addargs(&args, "-p");
		addargs(&args, "%d", port);
	}
	if (remuser != NULL) {
		addargs(&args, "-l");
		addargs(&args, "%s", remuser);
	}
	addargs(&args, "--");
	addargs(&args, "%s", host);
	addargs(&args, "%s", cmd);

	{
		posix_spawn_file_actions_t actions;
		pid = -1;

		if (posix_spawn_file_actions_init(&actions) != 0 ||
		    posix_spawn_file_actions_adddup2(&actions, fdin, STDIN_FILENO) != 0 ||
		    posix_spawn_file_actions_adddup2(&actions, fdout, STDOUT_FILENO) != 0 ) 
			fatal("posix_spawn initialization failed");
		else if (posix_spawn(&pid, args.list[0], &actions, NULL, args.list, NULL) != 0) 
			fatal("posix_spawn: %s", strerror(errno));

		posix_spawn_file_actions_destroy(&actions);
	}		
#else 
	pid = fork();
	if (pid == 0) {
		dup2(fdin, 0);
		dup2(fdout, 1);

		replacearg(&args, 0, "%s", ssh_program);
		if (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		if (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		addargs(&args, "-oBatchMode=yes");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(ssh_program, args.list);
		perror(ssh_program);
		exit(1);
	} else if (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
#endif
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	return 0;
}

typedef struct {
	size_t cnt;
	char *buf;
} BUF;

BUF *allocbuf(BUF *, int, int);
void lostconn(int);
int okname(char *);
void run_err(const char *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int note_err(const char *,...)
    __attribute__((__format__ (printf, 1, 2)));
void verifydir(char *);

struct passwd *pwd;
uid_t userid;
int errs, remin, remout;
int Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
char cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

int response(void);
void rsource(char *, struct stat *);
void sink(int, char *[], const char *);
void source(int, char *[]);
void tolocal(int, char *[]);
void toremote(int, char *[]);
void usage(void);

int
main(int argc, char **argv)
{
	int ch, fflag, tflag, status, n;
	char **newargv;
	const char *errstr;
	extern char *optarg;
	extern int optind;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	seed_rng();

	msetlocale();

	/* Copy argv, because we modify it */
	newargv = xcalloc(MAXIMUM(argc + 1, 1), sizeof(*newargv));
#ifdef WINDOWS	
	{
		/* 
		 * Wildcards are not expanded by shell on Windows; expand them
		 * Convert '\\' to '/' in path portion to support both Windows and Unix style paths
		 */
		char *p, *argdup;
		int i = 0;		
		glob_t g;
		int expandargc = 0;
		memset(&g, 0, sizeof(g));
		for (n = 0; n < argc; n++) {
			argdup = xstrdup(argv[n]);
			if (p = colon(argdup))
				convertToForwardslash(p);
			else
				convertToForwardslash(argdup);
			if (glob(argdup, GLOB_NOCHECK | GLOB_NOESCAPE, NULL, &g)) {
				if (expandargc > argc)
					newargv = xreallocarray(newargv, expandargc + 1, sizeof(*newargv));
				newargv[expandargc++] = xstrdup(argdup);
			} else {
				int count = g.gl_matchc > 1 ? g.gl_matchc : 1;
				if (expandargc + count > argc - 1)
					newargv = xreallocarray(newargv, expandargc + count, sizeof(*newargv));
				for (i = 0; i < count; i++)
					newargv[expandargc++] = xstrdup(g.gl_pathv[i]);
			}
			free(argdup);
			globfree(&g);
		}
		argc = expandargc;		
	}
#else  /* !WINDOWS */
	for (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
#endif /* !WINDOWS */
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	memset(&args, '\0', sizeof(args));
	memset(&remote_remote_args, '\0', sizeof(remote_remote_args));
	args.list = remote_remote_args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");

	fflag = Tflag = tflag = 0;
	while ((ch = getopt(argc, argv,
	    "12346ABCTdfpqrtvF:J:P:S:c:i:l:o:")) != -1) {
		switch (ch) {
		/* User-visible flags. */
		case '1':
			fatal("SSH protocol v.1 is no longer supported");
			break;
		case '2':
			/* Ignored */
			break;
		case 'A':
		case '4':
		case '6':
		case 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			break;
		case '3':
			throughlocal = 1;
			break;
		case 'o':
		case 'c':
		case 'i':
		case 'F':
		case 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			break;
		case 'P':
			sshport = a2port(optarg);
			if (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			break;
		case 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			break;
		case 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			if (errstr != NULL)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			break;
		case 'p':
			pflag = 1;
			break;
		case 'r':
			iamrecursive = 1;
			break;
		case 'S':
			ssh_program = xstrdup(optarg);
			break;
		case 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			verbose_mode = 1;
			break;
		case 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			break;

		/* Server options. */
		case 'd':
			targetshouldbedirectory = 1;
			break;
		case 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			break;
		case 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_BINARY);
#endif
			break;
		case 'T':
			Tflag = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	if ((pwd = getpwuid(userid = getuid())) == NULL)
		fatal("unknown user %u", (u_int) userid);

	if (!isatty(STDOUT_FILENO))
		showprogress = 0;

	if (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} else {
		if (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;	

	if (fflag) {
		/* Follow "protocol", send data. */
		(void) response();
		source(argc, argv);
		exit(errs != 0);
	}
	if (tflag) {
		/* Receive data. */
		sink(argc, argv, NULL);
		exit(errs != 0);
	}
	if (argc < 2)
		usage();
	if (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(void) snprintf(cmd, sizeof cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(void) ssh_signal(SIGPIPE, lostconn);

	if (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv);
	else {
		if (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	if (do_cmd_pid != -1 && errs == 0) {
		if (remin != -1)
		    (void) close(remin);
		if (remout != -1)
		    (void) close(remout);
		if (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		else {
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
static int
scpio(void *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	if (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	return 0;
}

static int
do_times(int fd, int verb, const struct stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	char buf[(20 + 7 + 2) * 2 + 2];

	(void)snprintf(buf, sizeof(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	if (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(void) atomicio(vwrite, fd, buf, strlen(buf));
	return (response());
}

static int
parse_scp_uri(const char *uri, char **userp, char **hostp, int *portp,
    char **pathp)
{
	int r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	if (r == 0 && *pathp == NULL)
		*pathp = xstrdup(".");
	return r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
static int
append(char *cp, char ***ap, size_t *np)
{
	char **tmp;

	if ((tmp = reallocarray(*ap, *np + 1, sizeof(*tmp))) == NULL)
		return -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	return 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
static int
find_brace(const char *pattern, int *startp, int *endp)
{
	int i;
	int in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	for (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		switch (pattern[i]) {
		case '\\':
			/* skip next character */
			if (pattern[i + 1] != '\0')
				i++;
			break;
		case '[':
			in_bracket = 1;
			break;
		case ']':
			in_bracket = 0;
			break;
		case '{':
			if (in_bracket)
				break;
			if (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				break;
			}
			if (*startp == -1)
				*startp = i;
			brace_level++;
			break;
		case '}':
			if (in_bracket)
				break;
			if (*startp < 0) {
				/* Unbalanced brace */
				return -1;
			}
			if (--brace_level <= 0)
				*endp = i;
			break;
		}
	}
	/* unbalanced brackets/braces */
	if (*endp < 0 && (*startp >= 0 || in_bracket))
		return -1;
	return 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
static int
emit_expansion(const char *pattern, int brace_start, int brace_end,
    int sel_start, int sel_end, char ***patternsp, size_t *npatternsp)
{
	char *cp;
	int o = 0, tail_len = strlen(pattern + brace_end + 1);

	if ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == NULL)
		return -1;

	/* Pattern before initial brace */
	if (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	if (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	if (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	if (append(cp, patternsp, npatternsp) != 0) {
		free(cp);
		return -1;
	}
	return 0;
}

/*
 * Expand the first encountered brace in pattern, appending the expanded
 * patterns it yielded to the *patternsp array.
 *
 * Returns 0 on success or -1 on allocation failure.
 *
 * Signals whether expansion was performed via *expanded and whether
 * pattern was invalid via *invalid.
 */
static int
brace_expand_one(const char *pattern, char ***patternsp, size_t *npatternsp,
    int *expanded, int *invalid)
{
	int i;
	int in_bracket, brace_start, brace_end, brace_level;
	int sel_start, sel_end;

	*invalid = *expanded = 0;

	if (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		return 0;
	} else if (brace_start == -1)
		return 0;

	in_bracket = brace_level = 0;
	for (i = sel_start = brace_start + 1; i < brace_end; i++) {
		switch (pattern[i]) {
		case '{':
			if (in_bracket)
				break;
			brace_level++;
			break;
		case '}':
			if (in_bracket)
				break;
			brace_level--;
			break;
		case '[':
			in_bracket = 1;
			break;
		case ']':
			in_bracket = 0;
			break;
		case '\\':
			if (i < brace_end - 1)
				i++; /* skip */
			break;
		}
		if (pattern[i] == ',' || i == brace_end - 1) {
			if (in_bracket || brace_level > 0)
				continue;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			if (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				return -1;
			/* move on to the next selection */
			sel_start = i + 1;
			continue;
		}
	}
	if (in_bracket || brace_level > 0) {
		*invalid = 1;
		return 0;
	}
	/* success */
	*expanded = 1;
	return 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
static int
brace_expand(const char *pattern, char ***patternsp, size_t *npatternsp)
{
	char *cp, *cp2, **active = NULL, **done = NULL;
	size_t i, nactive = 0, ndone = 0;
	int ret = -1, invalid = 0, expanded = 0;

	*patternsp = NULL;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	if ((cp = strdup(pattern)) == NULL)
		return -1;
	if (append(cp, &active, &nactive) != 0) {
		free(cp);
		return -1;
	}
	while (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		if (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			free(cp);
			goto fail;
		}
		if (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		if (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			free(cp);
			continue;
		}
		/*
		 * Pattern did not expand; append the finename component to
		 * the completed list
		 */
		if ((cp2 = strrchr(cp, '/')) != NULL)
			*cp2++ = '\0';
		else
			cp2 = cp;
		if (append(xstrdup(cp2), &done, &ndone) != 0) {
			free(cp);
			goto fail;
		}
		free(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = NULL;
	ndone = 0;
	ret = 0;
 fail:
	for (i = 0; i < nactive; i++)
		free(active[i]);
	free(active);
	for (i = 0; i < ndone; i++)
		free(done[i]);
	free(done);
	return ret;
}

void
toremote(int argc, char **argv)
{
	char *suser = NULL, *host = NULL, *src = NULL;
	char *bp, *tuser, *thost, *targ;
	int sport = -1, tport = -1;
	arglist alist;
	int i, r;
	u_int j;

	memset(&alist, '\0', sizeof(alist));
	alist.list = NULL;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	if (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		goto out;
	}
	if (r != 0) {
		if (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			goto out;
		}
	}
	if (tuser != NULL && !okname(tuser)) {
		++errs;
		goto out;
	}

	/* Parse source files */
	for (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		if (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		if (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		if (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		if (host && throughlocal) {	/* extended remote to remote */
			xasprintf(&bp, "%s -f %s%s", cmd,
			    *src == '-' ? "-- " : "", src);
			if (do_cmd(host, suser, sport, bp, &remin, &remout) < 0)
				exit(1);
			free(bp);
			xasprintf(&bp, "%s -t %s%s", cmd,
			    *targ == '-' ? "-- " : "", targ);
			if (do_cmd2(thost, tuser, tport, bp, remin, remout) < 0)
				exit(1);
			free(bp);
			(void) close(remin);
			(void) close(remout);
			remin = remout = -1;
		} else if (host) {	/* standard remote to remote */
			if (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts without the -3 option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			for (j = 0; j < remote_remote_args.num; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			if (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			if (suser) {
				addargs(&alist, "-l");
				addargs(&alist, "%s", suser);
			}
			addargs(&alist, "--");
			addargs(&alist, "%s", host);
			addargs(&alist, "%s", cmd);
			addargs(&alist, "%s", src);
			addargs(&alist, "%s%s%s:%s",
			    tuser ? tuser : "", tuser ? "@" : "",
			    thost, targ);
			if (do_local_cmd(&alist) != 0)
				errs = 1;
		} else {	/* local to remote */
			if (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				if (do_cmd(thost, tuser, tport, bp, &remin,
				    &remout) < 0)
					exit(1);
				if (response() < 0)
					exit(1);
				free(bp);
			}
			source(1, argv + i);
		}
	}
out:
	free(tuser);
	free(thost);
	free(targ);
	free(suser);
	free(host);
	free(src);
}

void
tolocal(int argc, char **argv)
{
	char *bp, *host = NULL, *src = NULL, *suser = NULL;
	arglist alist;
	int i, r, sport = -1;

	memset(&alist, '\0', sizeof(alist));
	alist.list = NULL;

	for (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		if (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		if (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		if (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		if (!host) {	/* Local to local. */
			freeargs(&alist);
#ifdef WINDOWS
#define _PATH_XCOPY "xcopy"
#define _PATH_COPY "copy"
			/* local to local on windows - need to use local native copy command */
			struct stat stb;
			int exists;
			char *last;

			exists = stat(argv[i], &stb) == 0;
			/* convert '/' to '\\' 	*/
			convertToBackslash(argv[i]);
			convertToBackslash(argv[argc - 1]);
			if (exists && (S_ISDIR(stb.st_mode))) {
				addargs(&alist, "%s", _PATH_XCOPY);
				if (iamrecursive)
					addargs(&alist, "/S /E /H");
				if (pflag)
					addargs(&alist, "/K /X");
				addargs(&alist, "/Y /F /I");
				addargs(&alist, "%s", argv[i]);

				/* This logic is added to align with UNIX behavior.
				 * If the argv[argc-1] exists then append direcorty name from argv[i]
				 */
				if (0 == stat(argv[argc - 1], &stb) && (S_ISDIR(stb.st_mode))) {
					if ((last = strrchr(argv[i], '\\')) == NULL)
						last = argv[i];
					else
						++last;

					addargs(&alist, "%s%s%s", argv[argc - 1],
						strcmp(argv[argc - 1], "\\") ? "\\" : "", last);
				} else {
					addargs(&alist, "%s", argv[argc - 1]);
				}
			} else {
				addargs(&alist, "%s", _PATH_COPY);
				addargs(&alist, "/Y");				
				addargs(&alist, "%s", argv[i]);
				addargs(&alist, "%s", argv[argc - 1]);
			}			
#else  /* !WINDOWS */
			addargs(&alist, "%s", _PATH_CP);
			if (iamrecursive)
				addargs(&alist, "-r");
			if (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
#endif /* !WINDOWS */
			if (do_local_cmd(&alist))
				++errs;
			continue;
		}
		/* Remote to local. */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		if (do_cmd(host, suser, sport, bp, &remin, &remout) < 0) {
			free(bp);
			++errs;
			continue;
		}
		free(bp);
		sink(1, argv + argc - 1, src);
		(void) close(remin);
		remin = remout = -1;
	}
	free(suser);
	free(host);
	free(src);
}

void
source(int argc, char **argv)
{
	struct stat stb;
	static BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	int fd = -1, haderr, indx;
#ifdef WINDOWS
	/* PATH_MAX is too large on Windows.*/
	/* Allocate memory dynamically for encname and buf to avoid stack overflow on recursive calls.*/
	char *last, *name, *buf = NULL, *encname = NULL;
	size_t encname_len, buf_len, tmp_len;
#else
	char *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
#endif
	int len;
	

	for (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		while (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		if ((fd = open(name, O_RDONLY|O_NONBLOCK, 0)) == -1)
			goto syserr;

		if (strchr(name, '\n') != NULL) {
#ifdef WINDOWS
			if (!encname) {
				encname_len = ((2 * len) < MAX_PATH) ? 2 * len : MAX_PATH;
				encname = xmalloc(encname_len);
			}
			while ((tmp_len = strnvis(encname, name, encname_len, VIS_NL)) >= encname_len) {
				if (tmp_len >= MAX_PATH)
					break;
				encname = xreallocarray(encname, tmp_len + 1, sizeof(char));
				encname_len = tmp_len + 1;
			}
#else
			strnvis(encname, name, sizeof(encname), VIS_NL);
#endif
			name = encname;
		}
		if (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			goto next;
		}
		if (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			goto next;
		}
		unset_nonblock(fd);
		switch (stb.st_mode & S_IFMT) {
		case S_IFREG:
			break;
		case S_IFDIR:
			if (iamrecursive) {
				rsource(name, &stb);
				goto next;
			}
			/* FALLTHROUGH */
		default:
			run_err("%s: not a regular file", name);
			goto next;
		}
		if ((last = strrchr(name, '/')) == NULL)
			last = name;
		else
			++last;
		curfile = last;
		if (pflag) {
			if (do_times(remout, verbose_mode, &stb) < 0)
				goto next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
#ifdef WINDOWS
		buf_len = ((strlen(last) + 20) < MAX_PATH) ? strlen(last) + 20 : MAX_PATH;
		buf = xmalloc(buf_len);
		while ((tmp_len = snprintf(buf, buf_len, "C%04o %lld %s\n",
		      (u_int) (stb.st_mode & FILEMODEMASK),
			  (long long)stb.st_size, last)) >= buf_len) {
			if (tmp_len >= MAX_PATH)
				break;
			buf = xreallocarray(buf, tmp_len + 1, sizeof(char));
			buf_len = tmp_len + 1;
		}
#else
		snprintf(buf, sizeof buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
#endif
		if (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(void) atomicio(vwrite, remout, buf, strlen(buf));
		if (response() < 0)
			goto next;
		if ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == NULL) {
next:			if (fd != -1) {
				(void) close(fd);
				fd = -1;
			}
			continue;
		}
		if (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		for (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			if (!haderr) {
				if ((nr = atomicio(read, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			if (haderr) {
				(void)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				continue;
			}
			if (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		if (fd != -1) {
			if (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		if (!haderr)
			(void) atomicio(vwrite, remout, "", 1);
		else
			run_err("%s: %s", name, strerror(haderr));
		(void) response();
		if (showprogress)
			stop_progress_meter();
	}
#ifdef WINDOWS
	if (encname)
		free(encname);
	if (buf)
		free(buf);
#endif
}

void
rsource(char *name, struct stat *statp)
{
	DIR *dirp;
	struct dirent *dp;
#ifndef WINDOWS
	char *last, *vect[1], path[PATH_MAX];
#else
	/* PATH_MAX is too large on Windows.*/
	/* Allocate memory dynamically for path to avoid stack overflow on recursive calls.*/
	char *last, *vect[1], *path;
	size_t path_len = 260, len;

	path = xmalloc(path_len);
#endif

	if (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		return;
	}
	last = strrchr(name, '/');
	if (last == NULL)
		last = name;
	else
		last++;
	if (pflag) {
		if (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			return;
		}
	}
#ifdef WINDOWS
	while ((len = snprintf(path, path_len, "D%04o %d %.1024s\n",
		  (u_int)(statp->st_mode & FILEMODEMASK), 0, last)) >= path_len) {
		if (len >= MAX_PATH)
			break;
		path = xreallocarray(path, len + 1, sizeof(char));
		path_len = len + 1;
	}
#else
	(void) snprintf(path, sizeof path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
#endif
	if (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(void) atomicio(vwrite, remout, path, strlen(path));
	if (response() < 0) {
		closedir(dirp);
		return;
	}
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_ino == 0)
			continue;
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
#ifdef WINDOWS
		if (strlen(name) + 1 + strlen(dp->d_name) >= PATH_MAX - 1) {
#else 
		if (strlen(name) + 1 + strlen(dp->d_name) >= sizeof(path) - 1) {
#endif
			run_err("%s/%s: name too long", name, dp->d_name);
			continue;
		}
#ifdef WINDOWS
		while ((len = snprintf(path, path_len, "%s/%s", name, dp->d_name)) >= path_len) {
			path = xreallocarray(path, len + 1, sizeof(char));
			path_len = len + 1;
		}
#else
		(void) snprintf(path, sizeof path, "%s/%s", name, dp->d_name);
#endif
		vect[0] = path;
		source(1, vect);
	}
#ifdef WINDOWS
	if (path)
		free(path);
#endif
	(void) closedir(dirp);
	(void) atomicio(vwrite, remout, "E\n", 2);
	(void) response();
}

#define TYPE_OVERFLOW(type, val) \
	((sizeof(type) == 4 && (val) > INT32_MAX) || \
	 (sizeof(type) == 8 && (val) > INT64_MAX) || \
	 (sizeof(type) != 4 && sizeof(type) != 8))

void
sink(int argc, char **argv, const char *src)
{
	static BUF buffer;
	struct stat stb;
	BUF *bp;
	off_t i;
	size_t j, count;
	int amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	int setimes, targisdir, wrerr;
	char ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	char **patterns = NULL;
	size_t n, npatterns = 0;
	struct timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

	if (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	if (!pflag)
		(void) umask(mask);
	if (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	if (targetshouldbedirectory)
		verifydir(targ);

	(void) atomicio(vwrite, remout, "", 1);
	if (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	if (src != NULL && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		if (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	for (first = 1;; first = 0) {
		cp = buf;
		if (atomicio(read, remin, cp, 1) != 1)
			goto done;
		if (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			if (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				SCREWUP("lost connection");
			*cp++ = ch;
		} while (cp < &buf[sizeof(buf) - 1] && ch != '\n');
		*cp = 0;
		if (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		if (buf[0] == '\01' || buf[0] == '\02') {
			if (iamremote == 0) {
				(void) snmprintf(visbuf, sizeof(visbuf),
				    NULL, "%s", buf + 1);
				(void) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			if (buf[0] == '\02')
				exit(1);
			++errs;
			continue;
		}
		if (buf[0] == 'E') {
			(void) atomicio(vwrite, remout, "", 1);
			goto done;
		}
		if (ch == '\n')
			*--cp = 0;

		cp = buf;
		if (*cp == 'T') {
			setimes++;
			cp++;
			if (!isdigit((unsigned char)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			if (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			if (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			if (!isdigit((unsigned char)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			if (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			if (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(void) atomicio(vwrite, remout, "", 1);
			continue;
		}
		if (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			if (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		for (++cp; cp < buf + 5; cp++) {
			if (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		if (!pflag)
			mode &= ~mask;
		if (*cp++ != ' ')
			SCREWUP("mode not delimited");

		if (!isdigit((unsigned char)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		if (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		if (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		if (*cp == '\0' || strchr(cp, '/') != NULL ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		if (npatterns > 0) {
			for (n = 0; n < npatterns; n++) {
				if (fnmatch(patterns[n], cp, 0) == 0)
					break;
			}
			if (n >= npatterns)
				SCREWUP("filename does not match request");
		}
		if (targisdir) {
			static char *namebuf;
			static size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			if (need > cursize) {
				free(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(void) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} else
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		if (buf[0] == 'D') {
			int mod_flag = pflag;
			if (!iamrecursive)
				SCREWUP("received directory without -r");
			if (exists) {
				if (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					goto bad;
				}
				if (pflag)
					(void) chmod(np, mode);
			} else {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				if (mkdir(np, mode | S_IRWXU) == -1)
					goto bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			if (setimes) {
				setimes = 0;
				(void) utimes(vect[0], tv);
			}
			if (mod_flag)
				(void) chmod(vect[0], mode);
			free(vect[0]);
			continue;
		}
		omode = mode;
		mode |= S_IWUSR;
#ifdef WINDOWS
		// In windows, we would like to inherit the parent folder permissions by setting mode to USHRT_MAX.
		if ((ofd = open(np, O_WRONLY|O_CREAT, USHRT_MAX)) == -1) {
#else
		if ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
#endif // WINDOWS
bad:			run_err("%s: %s", np, strerror(errno));
			continue;
		}
		(void) atomicio(vwrite, remout, "", 1);
		if ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == NULL) {
			(void) close(ofd);
			continue;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desyncronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		if (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		for (count = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = atomicio6(read, remin, cp, amt,
				    scpio, &statbytes);
				if (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} while (amt > 0);

			if (count == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				if (!wrerr) {
					if (atomicio(vwrite, ofd, bp->buf,
					    count) != count) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				count = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		if (count != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, count) != count) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		if (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		if (pflag) {
			if (exists || omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode)) {
#else /* HAVE_FCHMOD */
				if (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} else {
			if (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode & ~mask)) {
#else /* HAVE_FCHMOD */
				if (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		if (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(void) response();
		if (showprogress)
			stop_progress_meter();
		if (setimes && !wrerr) {
			setimes = 0;
			if (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		if (note_err(NULL) == 0)
			(void) atomicio(vwrite, remout, "", 1);
	}
done:
	for (n = 0; n < npatterns; n++)
		free(patterns[n]);
	free(patterns);
	return;
screwup:
	for (n = 0; n < npatterns; n++)
		free(patterns[n]);
	free(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

int
response(void)
{
	char ch, *cp, resp, rbuf[2048], visbuf[2048];

	if (atomicio(read, remin, &resp, sizeof(resp)) != sizeof(resp))
		lostconn(0);

	cp = rbuf;
	switch (resp) {
	case 0:		/* ok */
		return (0);
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	case 1:		/* error, followed by error msg */
	case 2:		/* fatal error, "" */
		do {
			if (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				lostconn(0);
			*cp++ = ch;
		} while (cp < &rbuf[sizeof(rbuf) - 1] && ch != '\n');

		if (!iamremote) {
			cp[-1] = '\0';
			(void) snmprintf(visbuf, sizeof(visbuf),
			    NULL, "%s\n", rbuf);
			(void) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		if (resp == 1)
			return (-1);
		exit(1);
	}
	/* NOTREACHED */
}

void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: scp [-346ABCpqrTv] [-c cipher] [-F ssh_config] [-i identity_file]\n"
	    "            [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "            [-S program] source ... target\n");
	exit(1);
}

void
run_err(const char *fmt,...)
{
	static FILE *fp;
	va_list ap;

	++errs;
	if (fp != NULL || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(void) fprintf(fp, "%c", 0x01);
		(void) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(void) vfprintf(fp, fmt, ap);
		va_end(ap);
		(void) fprintf(fp, "\n");
		(void) fflush(fp);
	}

	if (!iamremote) {
		va_start(ap, fmt);
		vfmprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}

/*
 * Notes a sink error for sending at the end of a file transfer. Returns 0 if
 * no error has been noted or -1 otherwise. Use note_err(NULL) to flush
 * any active error at the end of the transfer.
 */
int
note_err(const char *fmt, ...)
{
	static char *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	if (fmt == NULL) {
		if (emsg == NULL)
			return 0;
		run_err("%s", emsg);
		free(emsg);
		emsg = NULL;
		return -1;
	}

	errs++;
	/* Prefer first-noted error */
	if (emsg != NULL)
		return -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, NULL, fmt, ap);
	va_end(ap);
	return -1;
}

void
verifydir(char *cp)
{
	struct stat stb;

	if (!stat(cp, &stb)) {
		if (S_ISDIR(stb.st_mode))
			return;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

int
okname(char *cp0)
{
	int c;
	char *cp;

	cp = cp0;
	do {
		c = (int)*cp;
		if (c & 0200)
			goto bad;
		if (!isalpha(c) && !isdigit((unsigned char)c)) {
			switch (c) {
			case '\'':
			case '"':
			case '`':
			case ' ':
			case '#':
				goto bad;
			default:
				break;
			}
		}
	} while (*++cp);
	return (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	return (0);
}

BUF *
allocbuf(BUF *bp, int fd, int blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	struct stat stb;

	if (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		return (0);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	if (size == 0)
		size = blksize;
#else /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	if (bp->cnt >= size)
		return (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	return (bp);
}

void
lostconn(int signo)
{
	if (!iamremote)
		(void)write(STDERR_FILENO, "lost connection\n", 16);
	if (signo)
		_exit(1);
	else
		exit(1);
}
