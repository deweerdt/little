cmake_minimum_required(VERSION 2.6)
enable_testing()

add_test(FunkyUrls ${CMAKE_SOURCE_DIR}/tests/funky_urls aze)
add_test(HugeReq ${CMAKE_SOURCE_DIR}/tests/huge_req)
add_test(Nominal ${CMAKE_SOURCE_DIR}/tests/typical_ab)
add_test(HugeFile ${CMAKE_SOURCE_DIR}/tests/huge_ab)
add_test(Test404 ${CMAKE_SOURCE_DIR}/tests/404_ab)
add_test(Test403 ${CMAKE_SOURCE_DIR}/tests/403_ab)

include_directories(include)

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

target_link_libraries(little pthread jemalloc)
add_definitions(-D_GNU_SOURCE -Wall -Wextra -g -O0 ${PROF_OPT})
