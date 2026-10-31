/*
 * appsbx syscall guard: a deliberately tiny seccomp user-notification broker.
 * It changes only uname(2), sysinfo(2), and sched_getaffinity(2), including
 * direct syscall users. It does not change the scheduler's real CPU set.
 * The library is injected into the sandbox payload, never the bwrap launcher.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_seccomp
#define __NR_seccomp 317
#endif

struct guard_config {
  char hostname[65];
  char release[65];
  char version[65];
  char machine[65];
  unsigned long ram_bytes;
  unsigned int cpu_count;
};

static struct guard_config config;

static void copy_field(char *destination, size_t size, const char *value) {
  if (value == NULL) value = "";
  snprintf(destination, size, "%s", value);
}

static int write_target(pid_t pid, unsigned long address, const void *source, size_t length) {
  struct iovec local = { .iov_base = (void *)source, .iov_len = length };
  struct iovec remote = { .iov_base = (void *)address, .iov_len = length };
  ssize_t result = syscall(SYS_process_vm_writev, pid, &local, 1, &remote, 1, 0);
  return result == (ssize_t)length ? 0 : -1;
}

static void reply(int listener, struct seccomp_notif *request, long value, int error) {
  struct seccomp_notif_resp response;
  memset(&response, 0, sizeof(response));
  response.id = request->id;
  response.val = value;
  response.error = error ? -error : 0;
  (void)ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response);
}

static void handle_uname(int listener, struct seccomp_notif *request) {
  struct utsname result;
  memset(&result, 0, sizeof(result));
  copy_field(result.sysname, sizeof(result.sysname), "Linux");
  copy_field(result.nodename, sizeof(result.nodename), config.hostname);
  copy_field(result.release, sizeof(result.release), config.release);
  copy_field(result.version, sizeof(result.version), config.version);
  copy_field(result.machine, sizeof(result.machine), config.machine);
#ifdef _GNU_SOURCE
  copy_field(result.domainname, sizeof(result.domainname), "appsbx.local");
#endif
  if (write_target(request->pid, request->data.args[0], &result, sizeof(result)) != 0)
    reply(listener, request, 0, errno ? errno : EFAULT);
  else
    reply(listener, request, 0, 0);
}

static void handle_sysinfo(int listener, struct seccomp_notif *request) {
  struct sysinfo result;
  memset(&result, 0, sizeof(result));
  result.uptime = 0;
  result.totalram = config.ram_bytes;
  result.freeram = config.ram_bytes / 2;
  result.sharedram = 0;
  result.bufferram = 0;
  result.totalswap = 0;
  result.freeswap = 0;
  result.procs = 1;
  result.totalhigh = 0;
  result.freehigh = 0;
  result.mem_unit = 1;
  if (write_target(request->pid, request->data.args[0], &result, sizeof(result)) != 0)
    reply(listener, request, 0, errno ? errno : EFAULT);
  else
    reply(listener, request, 0, 0);
}

static void handle_sched_getaffinity(int listener, struct seccomp_notif *request) {
  const size_t size = (size_t)request->data.args[1];
  if (size == 0 || request->data.args[2] == 0 || size < (config.cpu_count + 7u) / 8u) {
    reply(listener, request, 0, EINVAL);
    return;
  }
  unsigned char *mask = calloc(1, size);
  if (mask == NULL) {
    reply(listener, request, 0, ENOMEM);
    return;
  }
  const unsigned int exposed = config.cpu_count < size * 8 ? config.cpu_count : (unsigned int)(size * 8);
  for (unsigned int cpu = 0; cpu < exposed; ++cpu)
    mask[cpu / 8] |= (unsigned char)(1u << (cpu % 8));
  if (write_target(request->pid, request->data.args[2], mask, size) != 0)
    reply(listener, request, 0, errno ? errno : EFAULT);
  /* The raw Linux syscall returns the kernel mask size; libc normalizes it
   * to zero. Returning the requested size keeps direct-syscall callers and
   * libc's sched_getaffinity wrapper compatible. */
  else
    reply(listener, request, (long)size, 0);
  free(mask);
}

static void broker(int listener, pid_t parent) {
  (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
  if (getppid() != parent) _exit(0);
  struct seccomp_notif_sizes sizes;
  if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) _exit(125);
  struct seccomp_notif *request = calloc(1, sizes.seccomp_notif);
  if (request == NULL) _exit(125);
  for (;;) {
    memset(request, 0, sizes.seccomp_notif);
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
      if (errno == EINTR) continue;
      _exit(0);
    }
    if (request->data.nr == __NR_uname) handle_uname(listener, request);
    else if (request->data.nr == __NR_sysinfo) handle_sysinfo(listener, request);
    else if (request->data.nr == __NR_sched_getaffinity) handle_sched_getaffinity(listener, request);
    else reply(listener, request, 0, ENOSYS);
  }
}

static int install_guard(void) {
#if !defined(__x86_64__)
  errno = ENOTSUP; return -1;
#else
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sysinfo, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sched_getaffinity, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = { .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])), .filter = filter };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
  int listener = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
  if (listener < 0) return -1;
  pid_t child = fork();
  if (child < 0) { close(listener); return -1; }
  if (child == 0) broker(listener, getppid());
  if (prctl(PR_SET_PTRACER, child, 0, 0, 0) != 0) { close(listener); return -1; }
  close(listener);
  return 0;
#endif
}

__attribute__((constructor)) static void appsbx_guard_init(void) {
  if (getenv("APPSBX_SYSCALL_GUARD_ACTIVE") != NULL) return;
  const char *hostname = getenv("APPSBX_UNAME_NODENAME");
  const char *ram = getenv("APPSBX_SYSINFO_TOTALRAM");
  const char *cpu_count = getenv("APPSBX_CPU_COUNT");
  if (hostname == NULL || ram == NULL || cpu_count == NULL) return;
  copy_field(config.hostname, sizeof(config.hostname), hostname);
  copy_field(config.release, sizeof(config.release), getenv("APPSBX_UNAME_RELEASE"));
  copy_field(config.version, sizeof(config.version), getenv("APPSBX_UNAME_VERSION"));
  copy_field(config.machine, sizeof(config.machine), getenv("APPSBX_UNAME_MACHINE"));
  char *end = NULL;
  unsigned long long parsed = strtoull(ram, &end, 10);
  if (end == ram || *end != '\0' || parsed == 0 || parsed > ~0UL) { write(2, "appsbx syscall guard: invalid configuration\n", 43); _exit(125); }
  config.ram_bytes = (unsigned long)parsed;
  end = NULL;
  unsigned long parsed_cpus = strtoul(cpu_count, &end, 10);
  if (end == cpu_count || *end != '\0' || parsed_cpus == 0 || parsed_cpus > 256) {
    write(2, "appsbx syscall guard: invalid CPU configuration\n", 47); _exit(125);
  }
  config.cpu_count = (unsigned int)parsed_cpus;
  if (setenv("APPSBX_SYSCALL_GUARD_ACTIVE", "1", 1) != 0 || install_guard() != 0) {
    write(2, "appsbx syscall guard: unavailable\n", 34); _exit(125);
  }
}
