cmake_minimum_required(VERSION 3.8)
project(WindowsClientComponents)

add_definitions(-DUNICODE)
add_definitions(-D_UNICODE)

add_subdirectory(${PROJECT_SOURCE_DIR}/UserModule)
add_subdirectory(${PROJECT_SOURCE_DIR}/StandaloneApp)
add_subdirectory(${PROJECT_SOURCE_DIR}/SampleApp)
