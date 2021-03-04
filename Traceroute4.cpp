// Author: Jack Ren
// Warning: this program must be run in root privilege!

// About sock API, refer to https://www.ibm.com/support/knowledgecenter/zh/ssw_ibm_i_71/apis/ssocko.htm

#include "Traceroute4.h"
#include "ArgParser.h"
#include "Err.h"

struct proto {
  void (*fproc)(char *, ssize_t, struct timeval *); // recv function
  void (*fsend)(); // send function
  struct sockaddr *sasend;  // sockaddr for send
  struct sockaddr *sarecv;  // sockaddr for receive
  socklen_t salen;    // length of sockaddr
  int icmpproto;  // IPPROTO_xxx value for ICMP
};

static void recv_v4(char *ptr, ssize_t len, struct timeval *tvrecv);
static void send_v4();
static unsigned short checksum(unsigned short *addr, int len);
static void eventLoop();
static addrinfo* host_service(const char *host, const char *serv, int family, int socktype);
static char* sock_to_ip_presentation(const struct sockaddr *sa, socklen_t salen); // Warning: Non-reentrant
static char* sock2ip(const struct sockaddr *sa, socklen_t salen);
static void tv_sub(struct timeval *, struct timeval *);

static const int datalen = 128; // Bytes of data following ICMP header
static std::string host; // Destination of ICMP packet
static pid_t pid; // Process ID for current MyPing program
static char sendbuf[BUFSIZE], recvbuf[BUFSIZE]; // Buffer for ICMP packets
static int sockfd; // File descriptor for socket
static int ttl = 1; // Time to live Value
static bool recvOK;

proto* pr;
proto proto_v4 = {recv_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP};

static void initArgs(int argc, char **argv) {
  // Parse arguments
  auto args = argParse_ping(argc, argv);
  // Get hostname from arguments
  if(!args.count("a"))
    errorQuit("Hostname unspecified, use -h to display help\n");
  host = args["a"];
}

int main(int argc, char **argv) {
  // Initiate arguments
  initArgs(argc, argv);
  // Get process ID
  pid = getpid();
  // Resolve a hostname to a socket addrinfo struct, IPv4 Only
  addrinfo *ai = host_service(host.c_str(), NULL, AF_INET, 0);
  if(!ai)
    errorQuit("Hostname resolve failed\n");
  // Print prompt
  printf("traceroute to %s (%s): %d data bytes\n", ai->ai_canonname, sock2ip(ai->ai_addr, ai->ai_addrlen), datalen);

  // Initialize according to protocol
  if (ai->ai_family == AF_INET)
    pr = &proto_v4;
  else if (ai->ai_family == AF_INET6) {
    errorQuit("Don't support IPv6\n");
  } else
    errorQuit("Unknown address family %d\n", ai->ai_family);

  pr->sasend = ai->ai_addr;
  pr->sarecv = (sockaddr *) (calloc(1, ai->ai_addrlen));
  pr->salen = ai->ai_addrlen;

  eventLoop();

  return 0;
}

// Receive ICMPv4 packet
static void recv_v4(char *ptr, ssize_t len, struct timeval *tvrecv) {
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

  if (icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == pid){
    tvsend = (struct timeval *) icmp->icmp_data;
    tv_sub(tvrecv, tvsend);
    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    printf("%u:%8.2lf ms\t\t%s\n", icmp->icmp_seq, rtt, sock2ip(pr->sarecv, pr->salen));
    recvOK = true;
    exit(0);
  }else if (icmp->icmp_type == ICMP_TIME_EXCEEDED) {
    char* ipStr = inet_ntoa(ip->ip_src);
    ip = (struct ip *) icmp->icmp_data;
    hlen1 = ip->ip_hl << 2;
    icmp = (struct icmp *) ((char*)ip + hlen1);
    if(icmp->icmp_id != pid)
      return;
    tvsend = (struct timeval *) icmp->icmp_data;
    tv_sub(tvrecv, tvsend);
    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    printf("%u:%8.2lf ms\t\t%s\n", icmp->icmp_seq, rtt, ipStr);
    recvOK = true;
  }
}

// Calculate checksum for ICMPv4 packet
static unsigned short checksum(unsigned short *addr, int len) {
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
static void send_v4() {
  int len;
  struct icmp *icmp;

  icmp = (struct icmp *) sendbuf;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_id = pid;
  icmp->icmp_seq = ttl;
  gettimeofday((struct timeval *) icmp->icmp_data, NULL);

  len = 8 + datalen;    /* checksum ICMP header and data */
  icmp->icmp_cksum = 0;
  icmp->icmp_cksum = checksum((u_short *) icmp, len);

  sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

// Main loop for program
static void eventLoop() {
  int size;
  socklen_t len;
  ssize_t n;
  timeval tval1, tval2;

  // In order to use raw socket, the program must be elevated to root privilege!!!
  sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
  // Set RecvBuf size
  size = BUFSIZE;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
  timeval tvLimit = {5, 0};
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tvLimit, sizeof(timeval));

  for (ttl = 1;ttl <= 256;ttl++) {
    // Set TTL
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    (*pr->fsend)();
    gettimeofday(&tval1, NULL);

    recvOK = false;
    len = pr->salen;

    while(!recvOK) {
      n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
      gettimeofday(&tval2, NULL);
      if (n < 0) {
        if (errno == EINTR)
          continue;
        else{
          printf("%u:          \t\tRequest Timeout.\n", ttl);
          break;
        }
      }
      (*pr->fproc)(recvbuf, n, &tval2);
    }
  }
}

// Function to sub timeval struct
static void tv_sub(timeval *out, timeval *in) {
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
