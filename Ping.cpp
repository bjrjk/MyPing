// Warning: this program must be run in root privilege!

#include "Ping.h"
#include "ArgParser.h"
#include "Err.h"

struct proto {
  void (*fproc)(char *, ssize_t, struct timeval *);
  void (*fsend)(void);
  struct sockaddr *sasend;  // sockaddr for send,
  struct sockaddr *sarecv;  // sockaddr for receive
  socklen_t salen;    // length of sockaddr
  int icmpproto;  // IPPROTO_xxx value for ICMP
};

static void eventLoop();
static void SIGALRM_HANDLER(int);
static addrinfo* host_service(const char *host, const char *serv, int family, int socktype);
static char* sock_to_ip_presentation(const struct sockaddr *sa, socklen_t salen); // Warning: Non-reentrant
static char* sock2ip(const struct sockaddr *sa, socklen_t salen);

static const int datalen = 128; // Bytes of data following ICMP header
static std::string host; // Destination of ICMP packet
static pid_t pid; // Process ID for current MyPing program
static char sendbuf[BUFSIZE], recvbuf[BUFSIZE]; // Buffer for ICMP packets
static int verbose;
static int sockfd; // File descriptor for socket
static int packetCount; // ICMP packet counter

proto* pr;
proto proto_v4 = {recv_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP};
proto proto_v6 = {recv_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6};


int main(int argc, char **argv) {
  // Parse arguments
  auto args = argParse_ping(argc, argv);
  host = args["a"]; //Get hostname from arguments
  if(args["v"] == "1")
    verbose++;
  // Get process ID
  pid = getpid();
  // Register SIGALRM signal handler
  signal(SIGALRM, SIGALRM_HANDLER);
  // Resolve a hostname to a socket addrinfo struct
  addrinfo *ai = host_service(host.c_str(), NULL, 0, 0);
  // Print prompt
  printf("ping %s (%s): %d data bytes\n", ai->ai_canonname, sock2ip(ai->ai_addr, ai->ai_addrlen), datalen);

  // Initialize according to protocol
  if (ai->ai_family == AF_INET)
    pr = &proto_v4;
  else if (ai->ai_family == AF_INET6) {
    pr = &proto_v6;
    if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr)))
      errorQuit("Can't ping IPv4-mapped IPv6 address\n");
  } else
    errorQuit("Unknown address family %d\n", ai->ai_family);

  pr->sasend = ai->ai_addr;
  pr->sarecv = (sockaddr *) (calloc(1, ai->ai_addrlen));
  pr->salen = ai->ai_addrlen;

  eventLoop();

  return 0;
}

// Receive ICMPv4 packet
void recv_v4(char *ptr, ssize_t len, struct timeval *tvrecv) {
  int hlen1, icmplen;
  double rtt;
  struct ip *ip;
  struct icmp *icmp;
  struct timeval *tvsend;

  ip = (struct ip *) ptr;    /* start of IP header */
  hlen1 = ip->ip_hl << 2;    /* length of IP header */

  icmp = (struct icmp *) (ptr + hlen1);  /* start of ICMP header */
  if ((icmplen = len - hlen1) < 8)
    errorQuit("icmplen (%d) < 8", icmplen);

  if (icmp->icmp_type == ICMP_ECHOREPLY) {
    if (icmp->icmp_id != pid)
      return;      /* not a response to our ECHO_REQUEST */
    if (icmplen < 16)
      errorQuit("icmplen (%d) < 16", icmplen);

    tvsend = (struct timeval *) icmp->icmp_data;
    tv_sub(tvrecv, tvsend);
    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
           icmplen, sock2ip(pr->sarecv, pr->salen),
           icmp->icmp_seq, ip->ip_ttl, rtt);

  } else if (verbose) {
    printf("  %d bytes from %s: type = %d, code = %d\n",
           icmplen, sock2ip(pr->sarecv, pr->salen),
           icmp->icmp_type, icmp->icmp_code);
  }
}

// Receive ICMPv6 packet
void recv_v6(char *ptr, ssize_t len, struct timeval *tvrecv) {
  int hlen1, icmp6len;
  double rtt;
  struct ip6_hdr *ip6;
  struct icmp6_hdr *icmp6;
  struct timeval *tvsend;

  /*
   Outgoing packets automatically have an IPv6 header prepended to them (based on the
   destination address).  Incoming packets on the socket are received with the IPv6 header and
   any extension headers removed.

   Refer to:
   https://stackoverflow.com/questions/13250115/get-icmpv6-header-from-ipv6-packet
   http://manpages.ubuntu.com/manpages/hirsute/en/man4/icmp6.4freebsd.html
   */

  icmp6 = (struct icmp6_hdr *) (ptr);
  icmp6len = len;

  if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
    if (icmp6->icmp6_id != pid)
      return;      /* not a response to our ECHO_REQUEST */
    if (icmp6len < 16)
      errorQuit("icmp6len (%d) < 16", icmp6len);

    tvsend = (struct timeval *) (icmp6 + 1);
    tv_sub(tvrecv, tvsend);
    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    printf("%d bytes from %s: seq=%u, hlim=%d, rtt=%.3f ms\n",
           icmp6len, sock2ip(pr->sarecv, pr->salen),
           icmp6->icmp6_seq, ip6->ip6_hlim, rtt);

  } else if (verbose) {
    printf("  %d bytes from %s: type = %d, code = %d\n",
           icmp6len, sock2ip(pr->sarecv, pr->salen),
           icmp6->icmp6_type, icmp6->icmp6_code);
  }
}

// Calculate checksum for ICMPv4 packet
unsigned short checksum(unsigned short *addr, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
  sum += (sum >> 16);                     /* add carry */
  answer = ~sum;                          /* truncate to 16 bits */
  return (answer);
}

// Send ICMP packet in IPv4 protocol
void send_v4() {
  int len;
  struct icmp *icmp;

  icmp = (struct icmp *) sendbuf;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_id = pid;
  icmp->icmp_seq = packetCount++;
  gettimeofday((struct timeval *) icmp->icmp_data, NULL);

  len = 8 + datalen;    /* checksum ICMP header and data */
  icmp->icmp_cksum = 0;
  icmp->icmp_cksum = checksum((u_short *) icmp, len);

  sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

// Send ICMP packet in IPv6 protocol
void send_v6() {
  int len;
  struct icmp6_hdr *icmp6;

  icmp6 = (struct icmp6_hdr *) sendbuf;
  icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
  icmp6->icmp6_code = 0;
  icmp6->icmp6_id = pid;
  icmp6->icmp6_seq = packetCount++;
  gettimeofday((struct timeval *) (icmp6 + 1), NULL);

  len = 8 + datalen;    /* 8-byte ICMPv6 header */

  //System calculate checksum automatically
  sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

// Main loop for program
void eventLoop() {
  int size;
  socklen_t len;
  ssize_t n;
  timeval tval;

  // In order to use raw socket, the program must be elevated to root privilege!!!
  sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
  size = BUFSIZE;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

  SIGALRM_HANDLER(SIGALRM);    // send first packet

  for (;;) {
    len = pr->salen;
    n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      else
        errorQuit("Function recvfrom error\n");
    }

    gettimeofday(&tval, NULL);
    (*pr->fproc)(recvbuf, n, &tval);
  }
}

// Request to send an ICMP Echo packet every second
static void SIGALRM_HANDLER(int signo) {
  (*pr->fsend)();
  alarm(1);
}

// Function to sub timeval struct
void tv_sub(timeval *out, timeval *in) {
  if ((out->tv_usec -= in->tv_usec) < 0) {  /* out -= in */
    --out->tv_sec;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
}

// Convert the socket struct to IP presentation
static char* sock_to_ip_presentation(const struct sockaddr *sa, socklen_t salen) {
  static char str[256];

  switch (sa->sa_family) {
    case AF_INET: {
      struct sockaddr_in *sin = (struct sockaddr_in *) sa;
      if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
        return NULL;
      return str;
    }
    case AF_INET6: {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;

      if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
        return NULL;
      return str;
    }
    default: {
      snprintf(str, sizeof(str), "sock_to_ip_presentation: unknown AF_xxx: %d, len %d",
               sa->sa_family, salen);
      return str;
    }
  }
}

// Wrapper for sock_to_ip_presentation
static char* sock2ip(const struct sockaddr *sa, socklen_t salen) {
  char* ptr;
  if ((ptr = sock_to_ip_presentation(sa, salen)) == NULL)
    errorQuit("sock_to_ip_presentation error");
  return ptr;
}

// Resolve a hostname to a socket addrinfo struct
static addrinfo* host_service(const char *host, const char *serv, int family, int socktype) {
  addrinfo hints, *res;

  bzero(&hints, sizeof(addrinfo));
  hints.ai_flags = AI_CANONNAME;  // always return canonical name
  hints.ai_family = family;       // AF_UNSPEC, AF_INET, AF_INET6, etc
  hints.ai_socktype = socktype;   // 0, SOCK_STREAM, SOCK_DGRAM, etc

  //Refer to https://www.cnblogs.com/fnlingnzb-learner/p/7542770.html
  if (getaddrinfo(host, serv, &hints, &res) != 0)
    return NULL;

  return res;
}
