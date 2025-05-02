cmake_minimum_required(VERSION 3.22.1)
project(DNS-Relay VERSION 0.1.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_APP "Build the DNS Server" ON)
option(BUILD_TESTING "Build the unit tests" OFF)
option(BUILD_TESTING_MINE "Build the private test" OFF)

include_directories(include)

if(BUILD_APP)
  # find_package(PkgConfig REQUIRED)
  # pkg_check_modules(GLIB REQUIRED glib-2.0)

  # include_directories(include ${GLIB_INCLUDE_DIRS})

  add_library(ThreadPool SHARED
    lib/thpool.c)

  add_executable(DNS-Relay src/main.c lib/dns.c lib/cache.c lib/hashtable.c lib/array.c)
  target_link_libraries(DNS-Relay PRIVATE ThreadPool)
  # target_compile_definitions(DNS-Relay PRIVATE DEBUG)
  # target_link_libraries(DNS-Relay ThreadPool ${GLIB_LIBRARIES})

  # add_executable(TestClient src/test_client.c)
  # target_link_libraries(TestClient DNSUtils ${GLIB_LIBRARIES})
endif()

if(BUILD_TESTING)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(CHECK REQUIRED check)
  message(STATUS "Check include dirs: ${CHECK_INCLUDE_DIRS}")
  message(STATUS "Check libraries: ${CHECK_LIBRARIES}")

  add_executable(run_hashtable_tests test/hash_test.c lib/hashtable.c)

  target_include_directories(run_hashtable_tests PRIVATE ${CHECK_INCLUDE_DIRS})
  target_link_libraries(run_hashtable_tests PRIVATE ${CHECK_LIBRARIES})

  enable_testing()

  include(CTest)
  add_test(NAME HashTableTests COMMAND run_hashtable_tests)
endif()

if(BUILD_TESTING_MINE)
  # add_executable(hash_test test/hash_test_own.c lib/hashtable.c)
  # target_compile_definitions(hash_test PRIVATE DEBUG)
  add_executable(array_test test/array_test.c lib/array.c)
  add_executable(file_test test/file_test.c)
endif()
