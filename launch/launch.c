/* swc: launch/launch.c
 *
 * Copyright (c) 2013, 2014, 2016 Michael Forney
 *
 * Based in part upon weston-launch.c from weston which is:
 *
 *     Copyright © 2012 Benjamin Franzke
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#ifdef __NetBSD__
#include <dev/wscons/wsconsio.h>
#include <dev/wscons/wsdisplay_usl_io.h>
extern char **environ;
#define TTY_MAJOR	(47)
#define WSKBD_MAJOR	(48)
#define WSMOUSE_MAJOR	(49)
#define	DRM_MAJOR	(180)
#else
#include <linux/input.h>
#include <linux/kd.h>
#include <linux/major.h>
#include <linux/vt.h>
#ifndef DRM_MAJOR
#define DRM_MAJOR 226
#endif
#endif

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <xf86drm.h>

#define ARRAY_LENGTH(array) (sizeof(array) / sizeof(array)[0])

static bool nflag;
static int sigfd[2], sock[2];
static int input_fds[128], num_input_fds;
static int drm_fds[16], num_drm_fds;
static int tty_fd;
static bool active;

static struct {
	bool altered;
	int vt;
	long kb_mode;
	long console_mode;
} original_vt_state;

static void cleanup(void);

static noreturn void usage(const char *name)
{
	fprintf(stderr, "usage: %s [-n] [-t tty] [--] server [args...]\n", name);
	exit(2);
}

static noreturn void __attribute__((format(printf, 1, 2)))
die(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	if (format[0] && format[strlen(format) - 1] == ':')
		fprintf(stderr, " %s", strerror(errno));
	fputc('\n', stderr);

	cleanup();
	exit(EXIT_FAILURE);
}

static void
start_devices(void)
{
	int i;

	for (i = 0; i < num_drm_fds; ++i) {
		if (drmSetMaster(drm_fds[i]) < 0)
			die("failed to set DRM master");
	}
}

static void
stop_devices(bool fatal)
{
	int i;

	for (i = 0; i < num_drm_fds; ++i) {
		if (drmDropMaster(drm_fds[i]) < 0 && fatal)
			die("drmDropMaster:");
	}
	for (i = 0; i < num_input_fds; ++i) {
#ifdef EVIOCREVOKE
		if (ioctl(input_fds[i], EVIOCREVOKE, 0) < 0 && errno != ENODEV && fatal)
			die("ioctl EVIOCREVOKE:");
#endif
		close(input_fds[i]);
	}
	num_input_fds = 0;
}

static void
cleanup(void)
{
	/* Cleanup VT */
	ioctl(tty_fd, KDSETMODE, original_vt_state.console_mode);
	ioctl(tty_fd, KDSKBMODE, original_vt_state.kb_mode);

	/* Stop devices before switching the VT to make sure we have released the DRM
	 * device before the next session tries to claim it. */
	stop_devices(false);

	int dispmode = WSDISPLAYIO_MODE_EMUL;
	ioctl(tty_fd, WSDISPLAYIO_SMODE, &dispmode);

	kill(0, SIGTERM);
}

static void
activate(void)
{
	struct swc_launch_event event = {.type = SWC_LAUNCH_EVENT_ACTIVATE};

	start_devices();
	send(sock[0], &event, sizeof(event), 0);
	active = true;
}

static void
deactivate(void)
{
	struct swc_launch_event event = {.type = SWC_LAUNCH_EVENT_DEACTIVATE};

	send(sock[0], &event, sizeof(event), 0);
	stop_devices(true);
	active = false;
}

static void
handle_signal(int sig)
{
	write(sigfd[1], (char[]){sig}, 1);
}

static void
handle_socket_data(int socket)
{
	struct swc_launch_request request;
	struct swc_launch_event response;
	char path[PATH_MAX];
	struct iovec request_iov[2] = {
		{.iov_base = &request, .iov_len = sizeof(request)},
		{.iov_base = path, .iov_len = sizeof(path)},
	};
	struct iovec response_iov[1] = {
		{.iov_base = &response, .iov_len = sizeof(response)},
	};
	int fd = -1;
	struct stat st;
	ssize_t size;

	size = receive_fd(socket, &fd, request_iov, 2);
	if (size == -1 || size == 0 || size < sizeof(request))
		return;
	size -= sizeof(request);

	response.type = SWC_LAUNCH_EVENT_RESPONSE;
	response.serial = request.serial;

	switch (request.type) {
	case SWC_LAUNCH_REQUEST_OPEN_DEVICE:
		if (size == 0 || path[size - 1] != '\0') {
			fprintf(stderr, "path is not NULL terminated\n");
			goto fail;
		}

		if (stat(path, &st) == -1) {
			fprintf(stderr, "stat %s: %s\n", path, strerror(errno));
			goto fail;
		}

		switch (major(st.st_rdev)) {
#ifdef INPUT_MAJOR
		case INPUT_MAJOR:
#else
		case WSKBD_MAJOR:
		case WSMOUSE_MAJOR:
#endif
			if (!active)
				goto fail;
			if (num_input_fds == ARRAY_LENGTH(input_fds)) {
				fprintf(stderr, "too many input devices opened\n");
				goto fail;
			}
			break;
		case DRM_MAJOR:
			if (num_drm_fds == ARRAY_LENGTH(drm_fds)) {
				fprintf(stderr, "too many DRM devices opened\n");
				goto fail;
			}
			break;
		default:
			fprintf(stderr, "device is not an input device\n");
			goto fail;
		}

		fd = open(path, request.flags);

		if (fd == -1) {
			fprintf(stderr, "open %s: %s\n", path, strerror(errno));
			goto fail;
		}

		switch (major(st.st_rdev)) {
#ifdef INPUT_MAJOR
		case INPUT_MAJOR:
#else
		case WSKBD_MAJOR:
		case WSMOUSE_MAJOR:
#endif
			input_fds[num_input_fds++] = fd;
			break;
		case DRM_MAJOR:
			drm_fds[num_drm_fds++] = fd;
			break;
		}

		break;
	case SWC_LAUNCH_REQUEST_ACTIVATE_VT:
		if (!active)
			goto fail;

		if (ioctl(tty_fd, VT_ACTIVATE, request.vt) == -1)
			fprintf(stderr, "failed to activate VT %d: %s\n", request.vt, strerror(errno));
		break;
	default:
		fprintf(stderr, "unknown request %u\n", request.type);
		goto fail;
	}

	response.success = true;
	goto done;

fail:
	response.success = false;
	fd = -1;
done:
	send_fd(socket, fd, response_iov, 1);
}

static void
find_vt(char *vt, size_t size)
{
	char *vtnr;
	int tty0_fd, vt_num;

	/* If we are running from an existing X or wayland session, always open a new
	 * VT instead of using the current one. */
	if (getenv("DISPLAY") || getenv("WAYLAND_DISPLAY") || !(vtnr = getenv("XDG_VTNR"))) {
		tty0_fd = open("/dev/ttyE0", O_RDWR);
		if (tty0_fd == -1)
			die("open /dev/ttyE0:");
		if (ioctl(tty0_fd, VT_OPENQRY, &vt_num) != 0)
			die("VT open query failed:");
		close(tty0_fd);
		if (snprintf(vt, size, "/dev/ttyE%d", vt_num) >= size)
			die("VT number is too large");
	} else {
		if (snprintf(vt, size, "/dev/ttyE%s", vtnr) >= size)
			die("XDG_VTNR is too long");
	}
}

static int
open_tty(const char *tty_name)
{
	char *stdin_tty;
	int fd;

	/* Check if we are already running on the desired VT */
	if ((stdin_tty = ttyname(STDIN_FILENO)) && strcmp(tty_name, stdin_tty) == 0)
		return STDIN_FILENO;

	fd = open(tty_name, O_RDWR | O_NOCTTY);
	if (fd < 0)
		die("open %s:", tty_name);

	return fd;
}

static void
setup_tty(int fd)
{
	struct stat st;
	int vt;

	if (fstat(fd, &st) == -1)
		die("failed to stat TTY fd:");
	vt = minor(st.st_rdev);
	if (major(st.st_rdev) != TTY_MAJOR || vt == 0)
		die("not a valid VT");

	int dispmode = WSDISPLAYIO_MODE_MAPPED;
	if (ioctl(fd, WSDISPLAYIO_SMODE, &dispmode) < 0)
		die("Failed to set wsdisplay mode");
}

static void
run(int fd) {
	struct pollfd fds[] = {
		{.fd = fd, .events = POLLIN},
		{.fd = sigfd[0], .events = POLLIN},
	};
	int status;
	char sig;

	for (;;) {
		if (poll(fds, ARRAY_LENGTH(fds), -1) < 0) {
			if (errno == EINTR)
				continue;
			die("poll:");
		}
		if (fds[0].revents)
			handle_socket_data(fd);
		if (fds[1].revents) {
			if (read(sigfd[0], &sig, 1) <= 0)
				continue;
			switch (sig) {
			case SIGCHLD:
				wait(&status);
				cleanup();
				exit(WEXITSTATUS(status));
			case SIGUSR1:
				deactivate();
				ioctl(tty_fd, VT_RELDISP, 1);
				break;
			case SIGUSR2:
				ioctl(tty_fd, VT_RELDISP, VT_ACKACQ);
				activate();
				break;
			}
		}
	}
}

int
main(int argc, char *argv[])
{
	int option;
	char *vt = NULL, buf[64];
	struct sigaction action = {
		.sa_handler = handle_signal,
		.sa_flags = SA_RESTART,
	};
	sigset_t set;
	pid_t pid;
	posix_spawnattr_t attr;

	while ((option = getopt(argc, argv, "nt:")) != -1) {
		switch (option) {
		case 'n':
			nflag = true;
			break;
		case 't':
			vt = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (argc - optind < 1)
		usage(argv[0]);

	if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sock) == -1)
		die("socketpair:");
	if (fcntl(sock[0], F_SETFD, FD_CLOEXEC) == -1)
		die("failed set CLOEXEC on socket:");

	if (pipe2(sigfd, O_CLOEXEC) == -1)
		die("pipe:");
	if (sigaction(SIGCHLD, &action, NULL) == -1)
		die("sigaction SIGCHLD:");
	if (sigaction(SIGUSR1, &action, NULL) == -1)
		die("sigaction SIGUSR1:");
	if (sigaction(SIGUSR2, &action, NULL) == -1)
		die("sigaction SIGUSR2:");

	sigfillset(&set);
	sigdelset(&set, SIGCHLD);
	sigdelset(&set, SIGUSR1);
	sigdelset(&set, SIGUSR2);
	sigprocmask(SIG_SETMASK, &set, NULL);

	if (!vt) {
		find_vt(buf, sizeof(buf));
		vt = buf;
	}

	fprintf(stderr, "running on %s\n", vt);
	tty_fd = open_tty(vt);
	setup_tty(tty_fd);

	sprintf(buf, "%d", sock[1]);
	setenv(SWC_LAUNCH_SOCKET_ENV, buf, 1);

	if ((errno = posix_spawnattr_init(&attr)))
		die("posix_spawnattr_init:");
	if ((errno = posix_spawnattr_setflags(&attr, POSIX_SPAWN_RESETIDS|POSIX_SPAWN_SETSIGMASK)))
		die("posix_spawnattr_setflags:");
	sigemptyset(&set);
	if ((errno = posix_spawnattr_setsigmask(&attr, &set)))
		die("posix_spawnattr_setsigmask:");
	if ((errno = posix_spawnp(&pid, argv[optind], NULL, &attr, argv + optind, environ)))
		die("posix_spawnp %s:", argv[optind]);
	posix_spawnattr_destroy(&attr);

	close(sock[1]);
	run(sock[0]);

	return EXIT_SUCCESS;
}
