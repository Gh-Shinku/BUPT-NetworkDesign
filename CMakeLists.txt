cmake_minimum_required(VERSION 3.22.1)
project(DNS-Relay VERSION 0.1.0 LANGUAGES C)

# set(CMAKE_C_STANDARD 11)
# set(CMAKE_C_STANDARD_REQUIRED ON)
# set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED glib-2.0)

include_directories(include ${GLIB_INCLUDE_DIRS})

add_library(DNSUtils SHARED
  lib/dns.c)

add_library(ThreadPool SHARED
  lib/thpool.c)

add_executable(DNS-Relay src/main.c)
target_link_libraries(DNS-Relay DNSUtils ThreadPool ${GLIB_LIBRARIES})

add_executable(TestClient src/test_client.c)
target_link_libraries(TestClient DNSUtils ${GLIB_LIBRARIES})
