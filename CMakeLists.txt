ADD_EXECUTABLE(little little.c)

OPTION(PROFILE ON)
IF(PROFILE)
	SET(PROF_OPT "-fprofile-arcs -ftest-coverage")
	TARGET_LINK_LIBRARIES(little gcov)	
ENDIF(PROFILE)

ADD_DEFINITIONS(-Wall -Wextra -g -O0 ${PROF_OPT})
