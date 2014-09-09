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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
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
static const char *opt_socket_name = TPM_SOCKET_NAME;
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
    printf("  u : unix socket name to use (default: %s)\n", opt_socket_name);
    printf("  o : effective user the application should run as\n");
    printf("  g : effective group the application should run as\n");
    printf("  h : print this help message\n");
    printf("  startup mode : must be 'clear', "
           "'save' (default) or 'deactivated\n");
}

static void parse_options(int argc, char **argv)
{
    char c;
    struct passwd *pwd;
    struct group *grp;
    opt_uid = getuid();
    opt_gid = getgid();
    info("parsing options");
    while ((c = getopt (argc, argv, "dfs:u:o:g:c:h")) != -1) {
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
    pid_t sid, pid;
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
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
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

static void main_loop(void)
{
    int sock, fh, res;
    int32_t in_len;
    uint32_t out_len;
    uint8_t in[TPM_CMD_BUF_SIZE], *out;
    struct sockaddr_un addr;
    socklen_t addr_len;
    fd_set rfds;
    struct timeval tv;

    info("staring main loop");
    /* open UNIX socket */
    sock = init_socket(opt_socket_name);
    if (sock < 0) exit(EXIT_FAILURE);
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
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        res = select(sock + 1, &rfds, NULL, NULL, &tv);
        if (res < 0) {
            error("select(sock) failed: %s", strerror(errno));
            break;
        } else if (res == 0) {
            continue;
        }
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
            FD_ZERO(&rfds);
            FD_SET(fh, &rfds);
            tv.tv_sec = TPM_COMMAND_TIMEOUT;
            tv.tv_usec = 0;
            res = select(fh + 1, &rfds, NULL, NULL, &tv);
            if (res < 0) {
                error("select(fh) failed: %s", strerror(errno));
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
