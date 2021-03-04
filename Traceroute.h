#ifndef MYPING_TRACEROUTE_H
#define MYPING_TRACEROUTE_H

#include <cstring>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstdarg>
#include <ctime>
#include <string>
#include <algorithm>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <unistd.h>
#include <net/if.h>
#include <syslog.h>

#define BUFSIZE 2048

#endif
