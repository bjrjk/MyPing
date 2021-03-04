#include "ArgParser.h"
#include "Err.h"

std::unordered_map<std::string, std::string> argParse_ping(int argc, char** argv) {
  using namespace std;
  unordered_map<string, string> args;
  int argCh;

  opterr = 0; // Inhibit the error message 'getopt' prints for unrecognized options

  while ((argCh = getopt(argc, argv, "a:ht:v")) != -1) {
    switch (argCh) {
      case 'a':
        args["a"] = string(optarg);
        break;
      case 'h':
        errorQuit("Usage: MyPing [Options]\n"
                  "-a [Hostname/IPv4 Address/IPv6 Address] -- Specify ping destination\n"
                  "-h -- Display help information\n"
                  "-t [TTL(IPv4)/Hop Limit(IPv6) Value] -- Set Time To Live value, Default 128\n"
                  "-v -- Print more verbose information\n"
        );
        break;
      case 't':
        args["t"] = string(optarg);
        break;
      case 'v':
        args["v"] = "1";
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