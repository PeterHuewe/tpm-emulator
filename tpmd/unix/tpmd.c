/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id: tpmd.c 463 2011-06-08 14:25:04Z mast $
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include <grp.h>
#include "config.h"
#include "tpm/tpm_emulator.h"

#define TPM_COMMAND_TIMEOUT 30

static volatile int stopflag = 0;
static int is_daemon = 0;
static int opt_debug = 0;
static int opt_foreground = 0;
static const char default_socket_name[] = TPM_SOCKET_NAME;
static const char *opt_socket_name = default_socket_name;
static const char default_dev_name[] = "/dev/tpm_emul";
static const char *opt_dev_name = default_dev_name;
static uid_t opt_uid = 0;
static gid_t opt_gid = 0;
static int tpm_startup = 2;
static uint32_t tpm_config = 0;
extern const char *tpm_storage_file;

void my_log(int priority, const char *fmt, ...)
{
    va_list ap, bp;
    va_start(ap, fmt);
    va_copy(bp, ap);
    switch (priority) {
      case TPM_LOG_DEBUG:
        vsyslog(LOG_DEBUG, fmt, ap);
        break;
      case TPM_LOG_ERROR:
        vsyslog(LOG_ERR, fmt, ap);
        break;
      case TPM_LOG_INFO:
      default:
        vsyslog(LOG_INFO, fmt, ap);
        break;
    }
    va_end(ap);
    if (!is_daemon && (priority != TPM_LOG_DEBUG || opt_debug)) {
        vprintf(fmt, bp);
    }
    va_end(bp);
}

static void print_usage(char *name)
{
    printf("usage: %s [-d] [-f] [-s storage file] [-u unix socket name] "
           "[-o user name] [-g group name] [-h] [startup mode]\n", name);
    printf("  d : enable debug mode\n");
    printf("  f : forces the application to run in the foreground\n");
    printf("  s : storage file to use (default: %s)\n", tpm_storage_file);
    printf("  u : unix socket name to use (default: %s)\n", default_socket_name);
    printf("  U : don't use unix socket\n");
    printf("  e : emulation device to use (default: %s)\n", default_dev_name);
    printf("  E : don't use emulation device\n");
    printf("  o : effective user the application should run as\n");
    printf("  g : effective group the application should run as\n");
    printf("  h : print this help message\n");
    printf("  startup mode : must be 'clear', "
           "'save' (default) or 'deactivated\n");
}

static void parse_options(int argc, char **argv)
{
    int c, set_dev = 0;
    struct passwd *pwd;
    struct group *grp;
    opt_uid = getuid();
    opt_gid = getgid();
    info("parsing options");
    while ((c = getopt (argc, argv, "dfs:u:Ue:Eo:g:c:h")) != -1) {
        debug("handling option '-%c'", c);
        switch (c) {
            case 'd':
                opt_debug = 1;
                setlogmask(setlogmask(0) | LOG_MASK(LOG_DEBUG));
                debug("debug mode enabled");
                break;
            case 'f':
                debug("application is forced to run in foreground");
                opt_foreground = 1;
                break;
            case 's':
                tpm_storage_file = optarg;
                debug("using storage file '%s'", tpm_storage_file);
                break;
            case 'u':
                opt_socket_name = optarg;
                debug("using unix socket '%s'", opt_socket_name);
                break;
            case 'U':
		opt_socket_name = NULL;
		break;
            case 'e':
                opt_dev_name = optarg;
		set_dev = 1;
                debug("using emulation device '%s'", opt_dev_name);
		break;
            case 'E':
		opt_dev_name = NULL;
		set_dev = 0;
		break;
            case 'o':
                pwd  = getpwnam(optarg);
                if (pwd == NULL) {
                    error("invalid user name '%s'\n", optarg);
                    exit(EXIT_FAILURE);
                }
                opt_uid = pwd->pw_uid;
                break;
            case 'g':
                grp  = getgrnam(optarg);
                if (grp == NULL) {
                    error("invalid group name '%s'\n", optarg);
                    exit(EXIT_FAILURE);
                }
                opt_gid = grp->gr_gid;
                break;
            case 'c':
                tpm_config = strtol(optarg, NULL, 0);
                debug("tpm_config = %04x", tpm_config);
                break;
            case '?':
                error("unknown option '-%c'", optopt);
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            case 'h':
            default:
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    if (set_dev == 0 && access(opt_dev_name, F_OK) < 0)
	opt_dev_name = NULL;
    if (!opt_socket_name && !opt_dev_name) {
            error("both socket and emulator device are unavailable\n");
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
    }

    if (optind < argc) {
        debug("startup mode = '%s'", argv[optind]);
        if (!strcmp(argv[optind], "clear")) {
            tpm_startup = 1;
        } else if (!strcmp(argv[optind], "save")) {
            tpm_startup = 2;
        } else if (!strcmp(argv[optind], "deactivated")) {
            tpm_startup = 3;
        } else {
            error("invalid startup mode '%s'; must be 'clear', "
                  "'save' (default) or 'deactivated", argv[optind]);
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        }
    } else {
        /* if no startup mode is given assume save if a configuration
           file is available, clear otherwise */
        int fh = open(tpm_storage_file, O_RDONLY);
        if (fh < 0) {
            tpm_startup = 1;
            info("no startup mode was specified; asuming 'clear'");
        } else {
            tpm_startup = 2;
            close(fh);
        }
    }
}

static void switch_uid_gid(void)
{
    if (opt_gid != getgid()) {
        info("switching effective group ID to %d", opt_gid);  
        if (setgid(opt_gid) == -1) {
            error("switching effective group ID to %d failed: %s", opt_gid, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    if (opt_uid != getuid()) {
        info("switching effective user ID to %d", opt_uid);
        if (setuid(opt_uid) == -1) {
            error("switching effective user ID to %d failed: %s", opt_uid, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
}

static void signal_handler(int sig)
{
    info("signal received: %d", sig);
    if (sig == SIGTERM || sig == SIGQUIT || sig == SIGINT) stopflag = 1;
}

static void init_signal_handler(void)
{
    info("installing signal handlers");
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        error("signal(SIGTERM) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (signal(SIGQUIT, signal_handler) == SIG_ERR) {
        error("signal(SIGQUIT) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        error("signal(SIGINT) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (signal(SIGPIPE, signal_handler) == SIG_ERR) {
        error("signal(SIGPIPE) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void daemonize(void)
{
    pid_t sid, pid, fd;
    info("daemonizing process");
    pid = fork();
    if (pid < 0) {
        error("fork() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0) exit(EXIT_SUCCESS);
    pid = getpid();
    sid = setsid();
    if (sid < 0) {
        error("setsid() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (chdir("/") < 0) {
        error("chdir() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        error("open(/dev/null) failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    is_daemon = 1;
    info("process was successfully daemonized: pid=%d sid=%d", pid, sid);
}

static int mkdirs(const char *path)
{
    char *copy = strdup(path);
    char *p = strchr(copy + 1, '/');
    while (p != NULL) {
        *p = '\0';
        if ((mkdir(copy, 0755) == -1) && (errno != EEXIST)) {
            free(copy);
            return errno;
        }
        *p = '/';
        p = strchr(p + 1, '/');
    }
    free(copy);
    return 0;
}

static int init_socket(const char *name)
{
    int sock;
    struct sockaddr_un addr;
    info("initializing socket %s", name);
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        error("socket(AF_UNIX) failed: %s", strerror(errno));
        return -1;
    }
    mkdirs(name);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, name, sizeof(addr.sun_path));
    umask(0177);
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        error("bind(%s) failed: %s", addr.sun_path, strerror(errno));
        close(sock);
        return -1;
    }
    listen(sock, 1);
    return sock;
}

static int init_device(const char *name)
{
    int devfd, flags;

    info("initializing device %s", name);
    devfd = open(name, O_RDWR);
    if (devfd < 0) {
        error("open(%s) failed: %s", name, strerror(errno));
        return -1;
    }

    flags = fcntl(devfd, F_GETFL);
    if (flags == -1) {
        error("fcntl(%s, F_GETFL) failed: %s", name, strerror(errno));
        return -1;
    }
    if (fcntl(devfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        error("fcntl(%s, F_SETFL) failed: %s", name, strerror(errno));
        return -1;
    }

    return devfd;
}

static int handle_emuldev_command(int devfd)
{
    ssize_t in_len;
    uint32_t out_len;
    uint8_t in[TPM_CMD_BUF_SIZE], *out;
    int res;

    debug("waiting for commands...");
    in_len = read(devfd, in, sizeof(in));
    debug("received %d bytes", in_len);
    if (in_len <= 0)
	return errno == -EAGAIN ? 0 : in_len;
	
    out = NULL;
    res = tpm_handle_command(in, in_len, &out, &out_len);
    if (res < 0) {
	error("tpm_handle_command() failed");
	if (ioctl(devfd, 0, 0) < 0)
	    return -1;
    } else {
	debug("sending %d bytes", out_len);
	res = write(devfd, out, out_len);
	if (res < 0) {
	    error("write(%d) failed: %s", out_len, strerror(errno));
	    if (errno != ECANCELED)
		return -1;
	}
    }
    tpm_free(out);
    return 0;
}

static void main_loop(void)
{
    int sock = -1, devfd = -1, fh, res, npoll;
    int32_t in_len;
    uint32_t out_len;
    uint8_t in[TPM_CMD_BUF_SIZE], *out;
    struct sockaddr_un addr;
    socklen_t addr_len;
    struct pollfd poll_table[2];

    info("staring main loop");
    /* open UNIX socket */
    if (opt_socket_name) {
	sock = init_socket(opt_socket_name);
	if (sock < 0) exit(EXIT_FAILURE);
    }

    if (opt_dev_name) {
	devfd = init_device(opt_dev_name);
	if (devfd < 0)
	    exit(EXIT_FAILURE);
    }

    /* init tpm emulator */
    debug("initializing TPM emulator");
    if (tpm_emulator_init(tpm_startup, tpm_config) != 0) {
        error("tpm_emulator_init() failed");
        close(sock);
        unlink(opt_socket_name);
        exit(EXIT_FAILURE);
    }

    /* start command processing */
    while (!stopflag) {
        /* wait for incomming connections */
        debug("waiting for connections...");
	npoll = 0;
	if (sock != -1) {
	    poll_table[npoll].fd = sock;
	    poll_table[npoll].events = POLLIN;
	    poll_table[npoll++].revents = 0;
	}
	if (devfd != -1) {
	    poll_table[npoll].fd = devfd;
	    poll_table[npoll].events = POLLIN | POLLERR;
	    poll_table[npoll++].revents = 0;
	}
	res = poll(poll_table, npoll, -1);
        if (res < 0) {
            error("poll(sock,dev) failed: %s", strerror(errno));
            break;
        }

	if (devfd != -1 && poll_table[npoll - 1].revents) {
	    /* if POLLERR was set, let read() handle it */
	    if (handle_emuldev_command(devfd) < 0)
		break;
	}
	if (sock == -1 || !poll_table[0].revents)
	    continue;

	/* Beyond this point, npoll will always be 1 if the emulator device is
	 * not open and 2 if it is, so we can just fill in the second slot of
	 * the poll table unconditionally and rely on passing npoll to poll().
	 */

        addr_len = sizeof(addr);
        fh = accept(sock, (struct sockaddr*)&addr, &addr_len);
        if (fh < 0) {
            error("accept() failed: %s", strerror(errno));
            continue;
        }
        /* receive and handle commands */
        in_len = 0;
        do {
            debug("waiting for commands...");
	    poll_table[0].fd = fh;
	    poll_table[0].events = POLLIN;
	    poll_table[0].revents = 0;
	    poll_table[1].fd = devfd;
	    poll_table[1].events = POLLIN | POLLERR;
	    poll_table[1].revents = 0;

	    res = poll(poll_table, npoll, TPM_COMMAND_TIMEOUT);
            if (res < 0) {
                error("poll(fh) failed: %s", strerror(errno));
                close(fh);
                break;
            } else if (res == 0) {
#ifdef TPMD_DISCONNECT_IDLE_CLIENTS	    
                info("connection closed due to inactivity");
                close(fh);
                break;
#else		
                continue;
#endif		
            }

	    if (poll_table[1].revents) {
		/* if POLLERR was set, let read() handle it */
		if (handle_emuldev_command(devfd) < 0)
		    break;
	    }
	    if (!poll_table[0].revents)
		continue;

            in_len = read(fh, in, sizeof(in));
            if (in_len > 0) {
                debug("received %d bytes", in_len);
                out = NULL;
                res = tpm_handle_command(in, in_len, &out, &out_len);
                if (res < 0) {
                    error("tpm_handle_command() failed");
                } else {
                    debug("sending %d bytes", out_len);
                    uint32_t len = 0;
                    while (len < out_len) {
                        res = write(fh, &out[len], out_len - len);
                        if (res < 0) {
                            error("write(%d) failed: %s", 
                                  out_len - len, strerror(errno));
                            break;
                        }
                        len += res;
                    }
                    tpm_free(out);
                }
            }
        } while (in_len > 0);
        close(fh);
    }
    /* shutdown tpm emulator */
    tpm_emulator_shutdown();
    /* close socket */
    close(sock);
    unlink(opt_socket_name);
    info("main loop stopped");
}

int main(int argc, char **argv)
{
    openlog(argv[0], 0, LOG_DAEMON);
    setlogmask(~LOG_MASK(LOG_DEBUG));
    syslog(LOG_INFO, "--- separator ---\n");
    tpm_log = my_log;
    info("starting TPM Emulator daemon (1.2.%d.%d-%d)",
         VERSION_MAJOR, VERSION_MINOR, VERSION_BUILD);
    parse_options(argc, argv);
    /* switch uid/gid if required */
    switch_uid_gid();
    /* init signal handlers */
    init_signal_handler();
    /* unless requested otherwiese, fork and daemonize process */
    if (!opt_foreground) daemonize();
    /* start main processing loop */
    main_loop();
    info("stopping TPM Emulator daemon");
    closelog();
    return EXIT_SUCCESS;
}
