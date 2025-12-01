#pragma once

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef _STL_SECURE_NO_WARNINGS
#define _STL_SECURE_NO_WARNINGS
#endif

#include <sstream>
#include <vector>
#include <string>
#include <functional>
#include <map>
#include <memory>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <csignal>

#include <phnt_windows.h>
#include <phnt.h>
#include <CommCtrl.h>
#include <strsafe.h>

#ifndef padding
#define padding(x) struct { unsigned char __padding##x[(x)]; };
#endif

#ifndef padding_add
#define padding_add(x, y) struct { unsigned char __padding##x[(x) + (y)]; };
#endif

#ifndef padding_sub
#define padding_sub(x, y) struct { unsigned char __padding##x[(x) - (y)]; };
#endif

#ifndef static_assert_size
#define static_assert_size(actual, expected) \
	static_assert((actual) == (expected), "Size assertion failed: " #actual " != " #expected ".");
#endif

#ifndef static_assert_offset
#define static_assert_offset(type, member, expected) \
	static_assert(offsetof((type), (member)) == (expected), "Offset assertion failed: " offsetof((type), (member)) " != " #expected ".");
#endif
