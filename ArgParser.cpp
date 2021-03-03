#include "ArgParser.h"
#include "Err.h"

std::unordered_map<std::string, std::string> argParse_ping(int argc, char** argv) {
  using namespace std;
  unordered_map<string, string> args;
  int argCh;

  opterr = 0; // Inhibit the error message 'getopt' prints for unrecognized options

  while ((argCh = getopt(argc, argv, "a:hv")) != -1) {
    switch (argCh) {
      case 'a':
        args["a"] = string(optarg);
        break;
      case 'h':
        errorQuit("Usage: MyPing -a [address]\n"
                  "MyPing -h\n"
        );
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