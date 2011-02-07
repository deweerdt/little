CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
ENABLE_TESTING()

ADD_TEST(FunkyUrls ${CMAKE_SOURCE_DIR}/tests/funky_urls aze)
ADD_TEST(HugeReq ${CMAKE_SOURCE_DIR}/tests/huge_req)
ADD_TEST(Nominal ${CMAKE_SOURCE_DIR}/tests/typical_ab)
ADD_TEST(HugeFile ${CMAKE_SOURCE_DIR}/tests/huge_ab)
ADD_TEST(Test404 ${CMAKE_SOURCE_DIR}/tests/404_ab)
ADD_TEST(Test403 ${CMAKE_SOURCE_DIR}/tests/403_ab)

ADD_EXECUTABLE(little src/little.c src/requests.c src/log.c src/hash.c)
ADD_EXECUTABLE(hash_test src/hash_test.c src/hash.c)

ADD_TEST(utest_hash ${CMAKE_BINARY_DIR}/hash_test)

OPTION(PROFILE ON)
IF(PROFILE)
	SET(PROF_OPT "-fprofile-arcs -ftest-coverage")
	TARGET_LINK_LIBRARIES(little gcov)
ENDIF(PROFILE)

TARGET_LINK_LIBRARIES(little pthread jemalloc)
ADD_DEFINITIONS(-D_GNU_SOURCE -Wall -Wextra -g -O0 ${PROF_OPT})
