ENABLE_TESTING()

ADD_TEST(FunkyUrls ${CMAKE_SOURCE_DIR}/tests/funky_urls aze)
ADD_TEST(HugeReq ${CMAKE_SOURCE_DIR}/tests/huge_req)
ADD_TEST(Nominal ${CMAKE_SOURCE_DIR}/tests/typical_ab)
ADD_TEST(HugeFile ${CMAKE_SOURCE_DIR}/tests/huge_ab)
ADD_TEST(Test404 ${CMAKE_SOURCE_DIR}/tests/404_ab)
ADD_TEST(Test403 ${CMAKE_SOURCE_DIR}/tests/403_ab)
ADD_TEST(Base64 ${CMAKE_SOURCE_DIR}/tests/base64)

ADD_EXECUTABLE(little little.c requests.c)

OPTION(PROFILE ON)
IF(PROFILE)
	SET(PROF_OPT "-fprofile-arcs -ftest-coverage")
	TARGET_LINK_LIBRARIES(little gcov)	
ENDIF(PROFILE)

TARGET_LINK_LIBRARIES(little pthread magic ssl)
ADD_DEFINITIONS(-Wall -Wextra -g -O0 ${PROF_OPT})
