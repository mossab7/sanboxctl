#define _GNU_SOURCE
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <unistd.h>

int main(void) {
  char hostname[256]; struct utsname uts; struct sysinfo info; struct ifaddrs *interfaces = NULL;
  gethostname(hostname, sizeof(hostname)); uname(&uts); sysinfo(&info); getifaddrs(&interfaces);
  int fd = open("/etc/machine-id", O_RDONLY); if (fd >= 0) { char ignored[16]; read(fd, ignored, sizeof(ignored)); close(fd); }
  fd = open("/proc/cpuinfo", O_RDONLY); if (fd >= 0) close(fd);
  fd = open("/sys/class/dmi/id/product_name", O_RDONLY); if (fd >= 0) close(fd);
  if (interfaces) freeifaddrs(interfaces);
  puts("fixture complete (host values intentionally not printed)");
  return 0;
}
