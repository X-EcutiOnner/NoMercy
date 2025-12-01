#pragma once

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <csignal>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <algorithm>
#include <exception>
#include <functional>
#include <mutex>
#include <locale>
#include <chrono>
#include <stack>
#include <new>
#include <future>
#include <thread>
#include <regex>
#include <condition_variable>
#include <atomic>
#include <random>
#include <filesystem>
#include <any>
#include <optional>
#include <vector>
#include <map>
#include <list>
#include <set>
#include <array>
#include <unordered_map>
#include <unordered_set>

#include <phnt_windows.h>
#include <phnt.h>
#include <WbemCli.h>
#include <WbemIdl.h>
#include <wincrypt.h>
#include <Wtsapi32.h>
#include <winevt.h>
#include <UserEnv.h>
#include <rapidjson/document.h>
#include <rapidjson/reader.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/error/en.h>
#include <rapidjson/filereadstream.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/rsa.h>
#include <cryptopp/pem.h>
#include <lazy_importer.hpp>
#include <xorstr.hpp>
#include <wow64pp.hpp>
#include <xxhash.h>
#include <lz4/lz4.h>
#include <lz4/lz4hc.h>
#include <mini-printf/mini-printf.h>
#include <fmt/format.h>
#include <ProtectionMacros.h>

#include "Application.hpp"
#include "../../Common/FilePtr.hpp"
#include "../../Core/EngineR3_Core/include/Defines.hpp"
#include "../../Core/EngineR3_Core/include/WinVerHelper.hpp"
#include "../../Core/EngineR3_Core/include/SafeExecutor.hpp"
#include "../../Core/EngineR3_Core/include/MemAllocator.hpp"
#include "../../Core/EngineR3_Core/include/WinAPIManager.hpp"
#include "../../Core/EngineR3_Core/include/Application.hpp"
#include "../../Core/EngineR3_Core/include/HW-Info.hpp"

#if USE_THEMIDA_SDK == 1
#include <ThemidaSDK.h>
#elif USE_VMPROTECT_SDK == 1
#include <VMProtectSDK.h>
#endif

#undef GetObject

using namespace std::string_literals;
using namespace rapidjson;
using namespace NoMercyCore;
using std::min;
using std::max;
