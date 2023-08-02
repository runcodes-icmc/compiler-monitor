cmake_minimum_required(VERSION 3.18)
project(monitor C)

set(CMAKE_C_STANDARD 99)
ADD_COMPILE_OPTIONS(-Wall -O2 -static)

include_directories(src)
set(SOURCES src/monitor.c src/monitor.h)

add_executable(monitor src/main.c ${SOURCES})