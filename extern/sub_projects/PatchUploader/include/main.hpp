#pragma once
#include <Windows.h>
#include <string>
#include <filesystem>
#include <fmt/format.h>
#include <lz4/lz4.h>
#include <lz4/lz4hc.h>
#include <xxhash.h>
#include <cryptopp/sha.h>
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>

#include "../include/BasicLog.hpp"
#include "../../../../source/Common/Keys.hpp"
#include "../../../../source/Common/FilePtr.hpp"
#include "../../../../source/Core/EngineSetup/include/Update_manager.hpp"

extern std::string __GetNoMercyPath();
extern std::string __GetMd5(const std::string& filename);
extern std::string __GetSHA1(const std::string& filename);
extern std::string __GetSHA256(const std::string& filename);
extern bool __WildcardMatch(const std::string& str, const std::string& match);
extern std::string __ReadFileContent(const std::string& stFileName);

extern bool SetupCrashHandler();
