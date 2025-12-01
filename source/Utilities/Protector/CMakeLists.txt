cmake_minimum_required(VERSION 3.8)
project(NoMercyProtector)

file(GLOB NMPROTECTOR_HEADERS
	"src/*.h"
)
file(GLOB NMPROTECTOR_SOURCES
	"src/*.cpp"
)

add_executable(${PROJECT_NAME} ${NMPROTECTOR_SOURCES})

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${PROJECT_NAME} PROPERTY CMAKE_CXX_EXTENSIONS OFF)

target_precompile_headers(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src/pch.h)

add_custom_command(TARGET ${PROJECT_NAME}
	PRE_BUILD
	COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}"
	COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Pdb"
	COMMAND ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Priv"
)
add_custom_command(TARGET ${PROJECT_NAME}
	POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E echo "LINKING: ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${PROJECT_NAME}.exe ${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/${PROJECT_NAME}.exe"
	COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${PROJECT_NAME}.exe ${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Priv/${PROJECT_NAME}.exe
	COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${PROJECT_NAME}.pdb ${OUTPUT_DIR}/../Bin_public/${MAJOR_VERSION}.${gitVersion}/Pdb/${PROJECT_NAME}.pdb
	COMMAND ${CMAKE_COMMAND} -E copy ${OUTPUT_DIR}/${PROJECT_NAME}.exe ${OUTPUT_DIR}/../Bin_public/.debug/${PROJECT_NAME}.exe
)

TARGET_LINK_LIBRARIES(${PROJECT_NAME} dbghelp)
