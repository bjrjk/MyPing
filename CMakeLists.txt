cmake_minimum_required(VERSION 3.17)
project(MyPing)

set(CMAKE_CXX_STANDARD 17)

add_executable(MyPing Ping.cpp ArgParser.cpp Err.cpp)
add_executable(MyTraceroute4 Traceroute4.cpp ArgParser.cpp Err.cpp)