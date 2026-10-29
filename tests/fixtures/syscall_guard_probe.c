#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--child") == 0) {
    pid_t child = fork();
    if (child < 0) return 3;
    if (child == 0) { execl(argv[0], argv[0], NULL); _exit(127); }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return 4;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 5;
  }
  struct utsname libc_uname, direct_uname;
  struct sysinfo libc_sysinfo, direct_sysinfo;
  if (uname(&libc_uname) || syscall(SYS_uname, &direct_uname) ||
      sysinfo(&libc_sysinfo) || syscall(SYS_sysinfo, &direct_sysinfo)) return 2;
  printf("%s|%s|%s|%s|%lu|%lu\n", libc_uname.nodename, direct_uname.nodename,
         libc_uname.release, direct_uname.release, libc_sysinfo.totalram,
         direct_sysinfo.totalram);
  return 0;
}
