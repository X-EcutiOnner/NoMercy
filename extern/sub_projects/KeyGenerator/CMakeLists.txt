cmake_minimum_required(VERSION 3.2)
project(KeyGenerator CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ../..)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ../..)

include_directories(${PROJECT_SOURCE_DIR}/../../include)
link_directories(${PROJECT_SOURCE_DIR}/../../lib_x64)

file(GLOB SOURCE_FILE_LIST
    "src/*.cpp"
)
add_executable (${PROJECT_NAME} ${SOURCE_FILE_LIST})

target_link_libraries(${PROJECT_NAME} cryptopp_staticd ws2_32 crypt32 libcrypto libssl)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${PROJECT_NAME} PROPERTY CMAKE_CXX_EXTENSIONS OFF)

