cmake_minimum_required(VERSION 2.6)
enable_testing()

add_test(FunkyUrls ${CMAKE_SOURCE_DIR}/tests/funky_urls aze)
add_test(HugeReq ${CMAKE_SOURCE_DIR}/tests/huge_req)
add_test(Nominal ${CMAKE_SOURCE_DIR}/tests/typical_ab)
add_test(HugeFile ${CMAKE_SOURCE_DIR}/tests/huge_ab)
add_test(Test404 ${CMAKE_SOURCE_DIR}/tests/404_ab)
add_test(Test403 ${CMAKE_SOURCE_DIR}/tests/403_ab)

add_executable(little src/little.c src/requests.c
		      src/log.c src/hash.c src/str.c
		      src/http.c src/handler.c)
add_executable(hash_test src/hash_test.c src/hash.c)

add_test(utest_hash ${CMAKE_BINARY_DIR}/hash_test)

option(PROFILE ON)
if(PROFILE)
	set(PROF_OPT "-fprofile-arcs -ftest-coverage")
	target_link_libraries(little gcov)
endif(PROFILE)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	execute_process(COMMAND "brew --prefix libev" RESULT_VARIABLE EV_PREFIX)
	set(BREW_EV_INC_PREFIX "${EV_PREFIX}/include")
	set(BREW_EV_LIB_PREFIX "${EV_PREFIX}/lib")
endif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

find_library(LIBEV_LIBRARY NAMES ev PATHS ${BREW_EV_LIB_PREFIX})
find_path(LIBEV_INCLUDE_DIR ev.h
	  PATH_SUFFIXES include/ev include ${BREW_EV_INC_PREFIX})

if (NOT LIBEV_INCLUDE_DIR OR NOT LIBEV_LIBRARY)
	message(FATAL_ERROR "Couldn't find libev header files or library")
endif (NOT LIBEV_INCLUDE_DIR OR NOT LIBEV_LIBRARY)


include_directories(include ${LIBEV_INCLUDE_DIR})

target_link_libraries(little pthread ${LIBEV_LIBRARY})
add_definitions(-D_GNU_SOURCE -Wall -Wextra -g -O0 ${PROF_OPT})
