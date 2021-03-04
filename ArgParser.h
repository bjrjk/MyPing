#ifndef MYPING_ARGPARSER_H
#define MYPING_ARGPARSER_H

#include <cstdlib>
#include <string>
#include <unordered_map>
#include <unistd.h>

std::unordered_map<std::string, std::string> argParse_ping(int argc, char** argv);
std::unordered_map<std::string, std::string> argParse_traceroute(int argc, char** argv);

#endif
