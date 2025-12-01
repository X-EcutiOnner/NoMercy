cmake_minimum_required(VERSION 3.8)
project(Engine_R3)
set(EXE_NAME "R3Engine_x${PLATFORM_NAME_STR}")

add_definitions(-DNOMINMAX)
#add_definitions(-DWIN32_LEAN_AND_MEAN)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_definitions(-DINITGUID)
add_definitions(-D_NO_CVCONST_H)
add_definitions(-DPSAPI_VERSION=1)
add_definitions(-DSTRICT_TYPED_ITEMIDS)
add_definitions(-D_WIN32_DCOM)

file(GLOB LIB_ASSEMBLYS
	"${PROJECT_SOURCE_DIR}/Anti/*.asm"
	"${PROJECT_SOURCE_DIR}/Hook/*.asm"
)
file(GLOB LIB_HEADERS
	"${PROJECT_SOURCE_DIR}/../../Common/*.hpp"
	"${PROJECT_SOURCE_DIR}/*.hpp"
	"${PROJECT_SOURCE_DIR}/Access/*.hpp"
	"${PROJECT_SOURCE_DIR}/Anti/*.hpp"
	"${PROJECT_SOURCE_DIR}/App/*.hpp"
	"${PROJECT_SOURCE_DIR}/Common/*.hpp"
	"${PROJECT_SOURCE_DIR}/Crypto/*.hpp"
	"${PROJECT_SOURCE_DIR}/Emulator/*.hpp"
	"${PROJECT_SOURCE_DIR}/Etw/*.hpp"
	"${PROJECT_SOURCE_DIR}/Etw/Trace/*.hpp"
	"${PROJECT_SOURCE_DIR}/Helper/*.hpp"
	"${PROJECT_SOURCE_DIR}/Hook/*.hpp"
	"${PROJECT_SOURCE_DIR}/Hwid/*.hpp"
	"${PROJECT_SOURCE_DIR}/IO/*.hpp"
	"${PROJECT_SOURCE_DIR}/IPC/*.hpp"
	"${PROJECT_SOURCE_DIR}/Low/*.hpp"
	"${PROJECT_SOURCE_DIR}/Monitor/*.hpp"
	"${PROJECT_SOURCE_DIR}/Network/*.hpp"
	"${PROJECT_SOURCE_DIR}/Network/WS_Commands/*.hpp"
	"${PROJECT_SOURCE_DIR}/Process/*.hpp"
	"${PROJECT_SOURCE_DIR}/Scanner/*.hpp"
	"${PROJECT_SOURCE_DIR}/SDK/*.hpp"
	"${PROJECT_SOURCE_DIR}/SDK/Metin2/*.hpp"
	"${PROJECT_SOURCE_DIR}/SelfProtection/*.hpp"
	"${PROJECT_SOURCE_DIR}/Test/*.hpp"
	"${PROJECT_SOURCE_DIR}/Thread/*.hpp"
	"${PROJECT_SOURCE_DIR}/Window/*.hpp"
)
file(GLOB LIB_SOURCES
	"${PROJECT_SOURCE_DIR}/*.cpp"
	"${PROJECT_SOURCE_DIR}/Access/*.cpp"
	"${PROJECT_SOURCE_DIR}/Anti/*.cpp"
	"${PROJECT_SOURCE_DIR}/App/*.cpp"
	"${PROJECT_SOURCE_DIR}/Common/*.cpp"
	"${PROJECT_SOURCE_DIR}/Crypto/*.cpp"
	"${PROJECT_SOURCE_DIR}/Emulator/*.cpp"
	"${PROJECT_SOURCE_DIR}/Etw/*.cpp"
	"${PROJECT_SOURCE_DIR}/Etw/Trace/*.cpp"
	"${PROJECT_SOURCE_DIR}/Helper/*.cpp"
	"${PROJECT_SOURCE_DIR}/Hook/*.cpp"
	"${PROJECT_SOURCE_DIR}/Hwid/*.cpp"
	"${PROJECT_SOURCE_DIR}/IO/*.cpp"
	"${PROJECT_SOURCE_DIR}/IPC/*.cpp"
	"${PROJECT_SOURCE_DIR}/Low/*.cpp"
	"${PROJECT_SOURCE_DIR}/Monitor/*.cpp"
	"${PROJECT_SOURCE_DIR}/Network/*.cpp"
	"${PROJECT_SOURCE_DIR}/Network/WS_Commands/*.cpp"
	"${PROJECT_SOURCE_DIR}/Process/*.cpp"
	"${PROJECT_SOURCE_DIR}/Scanner/*.cpp"
	"${PROJECT_SOURCE_DIR}/SDK/*.cpp"
	"${PROJECT_SOURCE_DIR}/SDK/Engine/*.cpp"
	"${PROJECT_SOURCE_DIR}/SDK/Metin2/*.cpp"
	"${PROJECT_SOURCE_DIR}/SelfProtection/*.cpp"
	"${PROJECT_SOURCE_DIR}/Test/*.cpp"
	"${PROJECT_SOURCE_DIR}/Thread/*.cpp"
	"${PROJECT_SOURCE_DIR}/Window/*.cpp"
)

add_library(${EXE_NAME}
	STATIC
	${LIB_HEADERS}
	${LIB_SOURCES}
	${LIB_ASSEMBLYS}
)

set_source_files_properties(
	${LIB_ASSEMBLYS}
    PROPERTIES
    COMPILE_FLAGS "/safeseh"
)

target_compile_options(${EXE_NAME} PRIVATE "/Zi")
# target_compile_options(${EXE_NAME} PRIVATE "/INCREMENTAL:NO")
target_compile_options(${EXE_NAME} PRIVATE "/Ob0")
target_compile_options(${EXE_NAME} PRIVATE "/Od")
target_compile_options(${EXE_NAME} PRIVATE "/RTC1")
target_compile_options(${EXE_NAME} PRIVATE "/EHa")
#target_compile_options(${EXE_NAME} PRIVATE "/guard:cf")
target_compile_options(${EXE_NAME} PRIVATE "/DYNAMICBASE")
target_compile_options(${EXE_NAME} PRIVATE "/bigobj")

set_property(TARGET ${EXE_NAME} PROPERTY CXX_STANDARD 17)
set_property(TARGET ${EXE_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${EXE_NAME} PROPERTY CMAKE_CXX_EXTENSIONS OFF)

target_precompile_headers(${EXE_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/PCH.hpp)

if (ENABLE_STATIC_ANALYSIS)
	pvs_studio_add_target(
		TARGET ring3_engine.analyze ALL
		OUTPUT FORMAT errorfile
		ANALYZE ${EXE_NAME}
		LOG ring3_engine_analysis.err
	)
endif()

# "FSLib"
target_link_libraries(${EXE_NAME} "R3CoreEngine_x${PLATFORM_NAME_STR}")

SET_TARGET_PROPERTIES(${EXE_NAME} PROPERTIES LINK_FLAGS "/LARGEADDRESSAWARE")
