cmake_minimum_required(VERSION 3.8)
project(WindowsCoreComponents)

add_definitions(-DUNICODE)
add_definitions(-D_UNICODE)

add_subdirectory(${PROJECT_SOURCE_DIR}/EngineTLS)
add_subdirectory(${PROJECT_SOURCE_DIR}/EngineR3_Core)
add_subdirectory(${PROJECT_SOURCE_DIR}/EngineR3)
