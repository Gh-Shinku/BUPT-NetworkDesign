cmake_minimum_required(VERSION 3.22.1)
project(DNS-Relay VERSION 0.1.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_APP "Build the DNS Server" ON)
option(BUILD_TESTING_MINE "Build the private test" OFF)

include_directories(include)

if(BUILD_APP)
  add_executable(DNS-Relay src/main.c lib/thpool.c lib/dns.c lib/cache.c lib/hashtable.c lib/array.c)
  target_compile_options(DNS-Relay PRIVATE -O2 -Wall)
endif()

if(BUILD_TESTING_MINE)
  add_executable(hash_test test/hash_test.c lib/hashtable.c)
  target_compile_definitions(hash_test PRIVATE DEBUG)
  add_executable(array_test test/array_test.c lib/array.c)
  add_executable(file_test test/file_test.c)
  add_executable(thpool_test test/thpool_test.c lib/thpool.c)
endif()
