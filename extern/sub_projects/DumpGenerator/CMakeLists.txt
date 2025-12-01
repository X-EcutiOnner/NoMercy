cmake_minimum_required(VERSION 3.2)
project(DumpGenerator CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ../..)

include_directories(${PROJECT_SOURCE_DIR}/../../include)
include_directories(${PROJECT_SOURCE_DIR}/../../include/phnt)

add_definitions(-DFMT_HEADER_ONLY) # fmt

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable (${PROJECT_NAME}
    src/main.cpp
)
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES LINK_FLAGS    "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE")
