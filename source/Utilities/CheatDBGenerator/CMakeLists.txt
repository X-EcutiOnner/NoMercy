cmake_minimum_required(VERSION 3.8)
project(CheatDBGenerator)

add_definitions(-DNOMINMAX)

add_executable (${PROJECT_NAME}
	"${PROJECT_SOURCE_DIR}/src/main.cpp"
	"${PROJECT_SOURCE_DIR}/src/decomment.cpp"
	"${PROJECT_SOURCE_DIR}/../../../extern/include/mini-printf/mini-printf.cpp"
	"${PROJECT_SOURCE_DIR}/../../Core/EngineR3_Core/src/Common/MiniDump.cpp"
)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug") 
	set(EXTRA_LIBS ${EXTRA_LIBS}
		lz4d
		cryptopp_staticd
		xxhashd
	)
else()
	set(EXTRA_LIBS ${EXTRA_LIBS}
		lz4
		cryptopp_static
		xxhash
	)
endif()

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${EXTRA_LIBS})

# Compile required data files
if (CI_BUILD EQUAL 1)
	add_custom_command(TARGET ${PROJECT_NAME}
		POST_BUILD
		WORKING_DIRECTORY ${OUTPUT_DIR}
		COMMAND ${OUTPUT_DIR}/CheatDBGenerator.exe ${OUTPUT_DIR}/../document/internal/cheat_db.json
	)
endif()
