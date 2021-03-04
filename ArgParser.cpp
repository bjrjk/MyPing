#include "ArgParser.h"
#include "Err.h"

std::unordered_map<std::string, std::string> argParse_ping(int argc, char** argv) {
  using namespace std;
  unordered_map<string, string> args;
  int argCh;

  opterr = 0; // Inhibit the error message 'getopt' prints for unrecognized options

  args["protocol"] = "0"; // Default Protocol unspecified
  args["verbose"] = "1"; // Verbose level

  while ((argCh = getopt(argc, argv, "46a:bhi:qt:v")) != -1) {
    switch (argCh) {
      case '4':
        args["protocol"] = "4";
        break;
      case '6':
        args["protocol"] = "6";
        break;
      case 'a':
        args["a"] = string(optarg);
        break;
      case 'b':
        args["b"] = "1";
        break;
      case 'h':
        errorQuit("Usage: MyPing [Options]\n"
                  "-4 -- Use IPv4 only.\n"
                  "-6 -- Use IPv6 only.\n"
                  "-a [Hostname/IPv4 Address/IPv6 Address] -- Specify ping destination.\n"
                  "-b -- Allow pinging a broadcast address.\n"
                  "-h -- Display help information.\n"
                  "-i [Interval] -- Wait [interval] seconds between sending each packet. [interval] must be an integer.\n"
                  "-q -- Quiet mode, only print statistic information in the end.\n"
                  "-t [TTL(IPv4)/Hop Limit(IPv6) Value] -- Set Time To Live value, Default 128.\n"
                  "-v -- Print more verbose information.\n"
        );
        break;
      case 'i':
        args["i"] = string(optarg);
        break;
      case 'q':
        args["verbose"] = "0";
        break;
      case 't':
        args["t"] = string(optarg);
        break;
      case 'v':
        args["verbose"] = "2";
        break;
      case '?':
        errorQuit("Unknown Option: -%c\n", optopt);
        break;
      case ':':
        errorQuit("Missing required arguments\n");
        break;
    }
  }

  return args;
}

std::unordered_map<std::string, std::string> argParse_traceroute(int argc, char** argv) {
  using namespace std;
  unordered_map<string, string> args;
  int argCh;

  opterr = 0; // Inhibit the error message 'getopt' prints for unrecognized options

  while ((argCh = getopt(argc, argv, "46a:h")) != -1) {
    switch (argCh) {
      case '4':
        args["protocol"] = "4";
        break;
      case '6':
        args["protocol"] = "6";
        break;
      case 'a':
        args["a"] = string(optarg);
        break;
      case 'h':
        errorQuit("Usage: MyTraceroute [Options]\n"
                  "-4 -- Use IPv4 only.\n"
                  "-6 -- Use IPv6 only.\n"
                  "-a [Hostname/IPv4 Address/IPv6 Address] -- Specify traceroute destination.\n"
                  "-h -- Display help information.\n"
        );
        break;
      case '?':
        errorQuit("Unknown Option: -%c\n", optopt);
        break;
      case ':':
        errorQuit("Missing required arguments\n");
        break;
    }
  }

  return args;
}