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
#include <new.h>
#include <eh.h>

#include <phnt_windows.h>
#include <phnt.h>
#include <cguid.h>
#include <objbase.h>
#include <comdef.h>
#include <comutil.h>
#include <comip.h>
#include <wbemidl.h>
#include <wbemdisp.h>

#include <lazy_importer.hpp>
#include <xorstr.hpp>
#include <wow64pp.hpp>
#include <xxhash.h>
#include <lz4/lz4.h>
#include <lz4/lz4hc.h>
#include <mini-printf/mini-printf.h>
#include <fmt/format.h>
#include <ProtectionMacros.h>

#include "../../../Common/StdExtended.hpp"
#include "../../../Common/SimpleTimer.hpp"
#include "../../../Common/AbstractSingleton.hpp"
#include "../../../Common/FilePtr.hpp"

#include "Application.hpp"
#include "Defines.hpp"
#include "ErrorIDs.hpp"

#if USE_THEMIDA_SDK == 1
#include <ThemidaSDK.h>
#elif USE_VMPROTECT_SDK == 1
#include <VMProtectSDK.h>
#endif

using namespace std::string_literals;
using std::min;
using std::max;
