#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <string>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <chrono>
#include <vector>
#include <map>
#include <random>
#include <thread>
#include <iomanip>
#include <regex>
#include <shellapi.h>
#include <comutil.h>
#include <filesystem>
#include <mini-printf/mini-printf.h>
#include <xorstr.hpp>
#include <fmt/format.h>
#include <utf8.h>
#include <rapidjson/document.h>
#include <rapidjson/reader.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/error/en.h>
#include <rapidjson/filereadstream.h>
#include "SimpleTimer.hpp"
using namespace rapidjson;

#ifndef XISALIGNED
#define XISALIGNED(x)  ((((SIZE_T)(x)) & (sizeof(SIZE_T)-1)) == 0)
#endif

static constexpr auto MEMORY_START_ADDRESS   = (ULONGLONG)0; // 0x10000;
static constexpr auto MEMORY_END_ADDRESS_X64 = (ULONGLONG)0x7FFFFFFEFFFF;
static constexpr auto MEMORY_END_ADDRESS_X86 = (ULONGLONG)0x7FFFFFFF;

#pragma warning(push) 
#pragma warning(disable: 4996)

namespace stdext
{
	struct HumanReadableFileSize
	{
		std::uintmax_t size{};
	private:
		friend std::ostream& operator<<(std::ostream& os, HumanReadableFileSize hr)
		{
			int i{};
			double mantissa = static_cast<double>(hr.size);
			for (; mantissa >= 1024.; mantissa /= 1024., ++i)
			{
			}
			
			mantissa = std::ceil(mantissa * 10.) / 10.;
			os << mantissa << xorstr_(L"BKMGTPE")[i];
			return i == 0 ? os : os << xorstr_(L"B (") << hr.size << ')';
		}
		friend std::wostream& operator<<(std::wostream& os, HumanReadableFileSize hr)
		{
			int i{};
			double mantissa = static_cast<double>(hr.size);
			for (; mantissa >= 1024.; mantissa /= 1024., ++i)
			{
			}
			
			mantissa = std::ceil(mantissa * 10.) / 10.;
			os << mantissa << xorstr_(L"BKMGTPE")[i];
			return i == 0 ? os : os << xorstr_(L"B (") << hr.size << ')';
		}
	};

	static std::string size_fmt(uint64_t size)
	{
		std::stringstream ss;
		ss << stdext::HumanReadableFileSize{ size };
		return ss.str();
	}
	
	template <std::size_t Size>
	using ptr_from_size = std::enable_if_t <Size == 4 || Size == 8, std::conditional_t <Size == 8, uint64_t, uint32_t>>;
	
	static bool is_known_debugger_process(const std::wstring& name, bool bSubstr = false)
	{
#ifdef _DEBUG
		const auto lstProcesses = {
			L"conhost.exe",
			L"vsdbg.exe",
			L"devenv.exe",
			L"msvsmon.exe",
			L"vsdebugconsole.exe"
		};

		for (const auto& process : lstProcesses)
		{
			if (bSubstr)
			{
				if (name.find(process) != std::wstring::npos)
					return true;
			}
			else
			{
				if (name == process)
					return true;
			}
		}
#endif
		return false;
	}

	static constexpr bool is_debug_build_only()
	{
#ifdef _DEBUG
		return true;
#else
		return false;
#endif
	}

	static constexpr bool is_debug_build()
	{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		return true;
#else
		return false;
#endif
	}
	
	static bool is_debug_env()
	{
#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		return IsDebuggerPresent();
#else
		return false;
#endif
	}

	static bool is_api_schema_module(const std::wstring module_name)
	{
		if (module_name.length() < 4)
			return false;
		
		const auto base = module_name.substr(0, 4);
		if (base == xorstr_(L"api-") || base == xorstr_(L"ext-"))
			return true;
		
		return false;
	}

	static void periodic_sleep(const uint32_t total, const uint32_t period, const std::function<void()>& callback)
	{
		auto timer = CStopWatch <std::chrono::milliseconds>();
		while (timer.diff() < total)
		{
			callback();
			std::this_thread::sleep_for(std::chrono::milliseconds(period));
		}
	}

	template <class T, class U>
	constexpr T recast(U && u) noexcept
	{
		return reinterpret_cast<T>(std::forward<U>(u));
	}

	template <class T, class... Args>
	static std::unique_ptr <T> make_unique_nothrow(Args&&... args)
		noexcept(noexcept(T(std::forward<Args>(args)...)))
	{
		return std::unique_ptr<T>(new (std::nothrow) T(std::forward<Args>(args)...));
	}

	template <class T, class... Args>
	static std::shared_ptr <T> make_shared_nothrow(Args&&... args)
		noexcept(noexcept(T(std::forward<Args>(args)...)))
	{
		return std::shared_ptr<T>(new (std::nothrow) T(std::forward<Args>(args)...));
	}

	static int8_t str_to_s8(const std::string& s)
	{
		return static_cast<int8_t>(std::strtol(s.c_str(), nullptr, 10));
	}
	static int8_t str_to_s8(const std::wstring& s)
	{
		return static_cast<int8_t>(std::wcstol(s.c_str(), nullptr, 10));
	}
	static int16_t str_to_s16(const std::string& s)
	{
		return static_cast<int16_t>(std::strtol(s.c_str(), nullptr, 10));
	}
	static int16_t str_to_s16(const std::wstring& s)
	{
		return static_cast<int16_t>(std::wcstol(s.c_str(), nullptr, 10));
	}
	static int32_t str_to_s32(const std::string& s)
	{
		return static_cast<int32_t>(std::strtol(s.c_str(), nullptr, 10));
	}
	static int32_t str_to_s32(const std::wstring& s)
	{
		return static_cast<int32_t>(std::wcstol(s.c_str(), nullptr, 10));
	}
	static int64_t str_to_s64(const std::string& s)
	{
		return static_cast<int64_t>(std::strtoll(s.c_str(), nullptr, 10));
	}
	static int64_t str_to_s64(const std::wstring& s)
	{
		return static_cast<int64_t>(std::wcstoll(s.c_str(), nullptr, 10));
	}
	
	static uint8_t str_to_u8(const std::string& s)
	{
		return static_cast<uint8_t>(std::strtoul(s.c_str(), nullptr, 10));
	}
	static uint8_t str_to_u8(const std::wstring& s)
	{
		return static_cast<uint8_t>(std::wcstoul(s.c_str(), nullptr, 10));
	}
	static uint16_t str_to_u16(const std::string& s)
	{
		return static_cast<uint16_t>(std::strtoul(s.c_str(), nullptr, 10));
	}
	static uint16_t str_to_u16(const std::wstring& s)
	{
		return static_cast<uint16_t>(std::wcstoul(s.c_str(), nullptr, 10));
	}
	static uint32_t str_to_u32(const std::string& s)
	{
		return static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 10));
	}
	static uint32_t str_to_u32(const std::wstring& s)
	{
		return static_cast<uint32_t>(std::wcstoul(s.c_str(), nullptr, 10));
	}
	static uint64_t str_to_u64(const std::string& s)
	{
		return static_cast<uint64_t>(std::strtoull(s.c_str(), nullptr, 10));
	}
	static uint64_t str_to_u64(const std::wstring& s)
	{
		return static_cast<uint64_t>(std::wcstoull(s.c_str(), nullptr, 10));
	}

	template <class T>
	static auto get_map_value_by_index(T map, size_t index)
	{
		auto it = map.begin();
		std::advance(it, index);
		return it->second;
	}
	
	template <class vectorT, class objectT>
	static bool remove_vector_object(vectorT vec, objectT obj)
	{
		const auto begin_size = vec.size();
		vec.erase(std::remove(vec.begin(), vec.end(), obj), vec.end());
		return begin_size != vec.size();
	}

	static constexpr unsigned int get_current_year()
	{
		constexpr auto date = __DATE__;
		constexpr auto length = std::char_traits<char>::length(date);
		
		// find the last space in the string in compile time
		constexpr auto last_space = [&]() constexpr
		{
			auto pos = 0;
			for (auto i = 0u; i < length; ++i)
			{
				if (date[i] == ' ')
					pos = i;
			}
			return pos;
		}();
		
		// get the year from the string in compile time
		constexpr auto year = std::string_view{ date + last_space + 1, length - last_space - 2 }.data();
		
		// convert the year to an integer in compile time
		constexpr auto year_int = [year]() constexpr
		{
			auto result = 0;
			for (auto i = 0u; i < 4; ++i)
			{
				result *= 10;
				result += year[i] - '0';
			}
			return result;
		}();

		return year_int;
	}

	static constexpr unsigned int hash(const char* s, int off = 0)
	{
		return !s[off] ? 5381 : (hash(s, off + 1) * 33) ^ s[off];
	}
	static constexpr unsigned int hash(const wchar_t* s, int off = 0)
	{
		return !s[off] ? 5381 : (hash(s, off + 1) * 33) ^ s[off];
	}

	template <typename T, size_t N>
	static constexpr auto stack(const T(&str)[N])
	{
		std::array <T, N> ret{};
		std::copy(std::begin(str), std::end(str), ret.begin());
		return ret;
	}

	template <class T>
	static bool is_number(const T& s)
	{
		return !s.empty() && std::find_if(s.begin(), s.end(), [](unsigned char c) {
			return !std::isdigit(c);
		}) == s.end();
	}

	static uint32_t windows_ticks_to_unix_seconds(int64_t ticks)
	{
		return static_cast<uint32_t>(ticks / 10000000 - 11644473600LL);
	}

	static bool is_valid_uuid(const std::wstring& s)
	{
		static const std::wregex e(xorstr_(L"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12}"));
		return std::regex_match(s, e);
	}

	template <class containerT, class valueT>
	static bool in_vector(containerT container, valueT value)
	{
		return (std::find(container.begin(), container.end(), value) != container.end()) ? true : false;
	}

	template <class containerT, class valueT, class contentT>
	static bool get_map_value(containerT map, valueT key, contentT content)
	{
		auto it = map.find(key);
		if (it != map.end())
		{
			content = it->second;
			return true;
		}
		return false;
	}

	template <typename T>
	static void move_to_back(std::vector <T>& v, size_t idx)
	{
		auto it = v.begin() + idx;
		std::rotate(it, it + 1, v.end());
	}

	static std::wstring number_fmt(uint64_t n)
	{
		std::wstringstream ss;
		ss << n;

		std::wstring s = ss.str();
		s.reserve(s.length() + s.length() / 3);

		for (uint32_t i = 0, j = 3 - s.length() % 3; i < s.length(); ++i, ++j)
		{
			if (i != 0 && j % 3 == 0)
			{
				s.insert(i++, 1, '.');
			}
		}

		return s;
	}

	static uint32_t number_of_files_in_directory(std::filesystem::path path)
	{
		using std::filesystem::directory_iterator;
		std::error_code ec{};
		const auto count = std::distance(directory_iterator(path, ec), directory_iterator{});
		return count;
	}

	static auto is_wow64()
	{
#ifdef _WIN64
		return false;
#else
		return ((DWORD)__readfsdword(0xC0) != 0);
#endif
	}

	static auto is_x64_windows()
	{
#ifdef _WIN64
		return true;
#elif defined(_WIN32)
		return is_wow64();
#else
		return false;
#endif
	}

	static auto is_x64_build()
	{
#ifdef _WIN64
		return true;
#else
		return false;
#endif
	}

	static std::wstring arch_str(bool bIgnoreWow64 = false)
	{
		std::wstring wstBuffer;
#if defined(_M_X64)
		wstBuffer = xorstr_(L"x64");
#elif defined(_M_IX86)
		if (is_wow64())
			wstBuffer = xorstr_(L"x86_64");
		else
			wstBuffer = xorstr_(L"x86");
#endif
		if (bIgnoreWow64 && is_wow64())
			wstBuffer = xorstr_(L"x64");;
		
		return wstBuffer;
	};

	static std::size_t align(size_t val, size_t alignment)
	{
		return (val % alignment == 0) ? val : (val / alignment + 1) * alignment;
	}

	static unsigned long long hextou64_w(wchar_t* s)
	{
		auto locase_w = [](wchar_t c) -> wchar_t {
			if ((c >= 'A') && (c <= 'Z'))
				return c + 0x20;
			else
				return c;
		};
		auto _isdigit_w = [](wchar_t x) {
			return ((x >= L'0') && (x <= L'9'));
		};
		
		if (s == 0)
			return 0;
		
		wchar_t	c;
		unsigned long long	r = 0;

		while (*s != 0)
		{
			c = locase_w(*s);
			s++;
			if (_isdigit_w(c))
				r = 16 * r + (c - L'0');
			else
				if ((c >= L'a') && (c <= L'f'))
					r = 16 * r + (c - L'a' + 10);
				else
					break;
		}
		
		return r;
	}

	static const auto atodw(const char* szValue)
	{
		int nCount = 0;
		unsigned long dwValue = 0;

		while (*(szValue + nCount) != 0)
		{
			dwValue *= 16;

			if ((*(szValue + nCount) >= '0') && (*(szValue + nCount) <= '9'))
				dwValue += *(szValue + nCount) - '0';
			else
				dwValue += *(szValue + nCount) - 'A' + 10;

			nCount++;
		}

		return dwValue;
	}
	static const auto is_hex_string(const std::wstring& str)
	{
		for (const auto& c : str)
		{
			if (!std::isxdigit(c))
				return false;
		}
		return true;
	}
	static const auto string_to_byte_array(const std::wstring& in)
	{
		std::vector<std::uint8_t> out;
		std::wistringstream hexStream(in);

		std::wstring hexPair;
		while (hexStream >> std::setw(2) >> hexPair)
		{
			auto thex = std::stoul(hexPair, nullptr, 16);
			out.emplace_back(static_cast<std::uint8_t>(thex));
		}

		return out;
	}
	static std::wstring display_hex_dump(const std::vector <std::pair <bool, uint8_t>>& vecHexData)
	{
		std::wstring str;

		for (const auto& [mask, pattern] : vecHexData)
		{
			if (!str.empty())
				str += L' ';
			
			if (!mask)
			{
				str += L"?";
			}
			else
			{
				str += pattern / 0x10;
				str.back() += str.back() <= 9 ? L'0' : L'A' - 10;

				str += pattern % 0x10;
				str.back() += str.back() <= 9 ? L'0' : L'A' - 10;
			}
		}
		
		return str;
	}
	static const uint8_t parse_hex_byte(char const letter)
	{
		if (letter >= '0' && letter <= '9')
			return letter - '0';
		else if (letter >= 'A' && letter <= 'F')
			return letter - 'A' + 0xA;
		else if (letter >= 'a' && letter <= 'f')
			return letter - 'a' + 0xA;
		return 0;
	}
	static const auto string_to_pointer(const std::wstring& in)
	{
		std::uintptr_t out = 0;

		std::wstringstream ss;
		ss << std::hex << out;
		ss.str(in);
		ss >> std::hex >> out;

		return out;
	}
	static const auto string_to_pointer64(const std::wstring& in)
	{
		std::uint64_t out = 0;

		std::wstringstream ss;
		ss << std::hex << out;
		ss.str(in);
		ss >> std::hex >> out;

		return out;
	}
	static const auto pointer_to_string_a(std::uintptr_t hex)
	{
		char szBuffer[64]{'\0'};
		_snprintf_s(szBuffer, sizeof(szBuffer), xorstr_("0x%p"), hex);

		return std::string(szBuffer);
	}
	static const auto pointer_to_string_w(std::uintptr_t hex)
	{

		wchar_t wszBuffer[64]{ L'\0' };
		_snwprintf_s(wszBuffer, 64, xorstr_(L"0x%p"), hex);

		return std::wstring(wszBuffer);
	}
	static std::wstring dump_hex(const uint8_t* ptr, const std::size_t length)
	{
		if (!ptr || !length)
			return {};

		std::wstringstream ss;

		std::vector <uint8_t> buffer(length);
		memcpy(&buffer[0], ptr, length);

		for (size_t i = 0; i < length; ++i)
			ss << fmt::format(xorstr_(L"{:#02x}"), buffer.at(i)) << xorstr_(L", ");

		const auto str = ss.str();
		return str.substr(0, str.size() - 2);
	}

	static std::wstring create_random_string(int length)
	{
		auto randchar = []() -> wchar_t {
			const auto c_szCharset = xorstr_(
				L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
			);
			return c_szCharset[rand() % (sizeof(c_szCharset) - 1)];
		};

		std::wstring str(length, 0);
		std::generate_n(str.begin(), length, randchar);
		return str;
	}

	static std::wstring guid_to_str(const GUID* id, wchar_t* out)
	{
		wchar_t* ret = out;
		out += swprintf(out, xorstr_(L"%.8lX-%.4hX-%.4hX-"), id->Data1, id->Data2, id->Data3);

		for (int i = 0; i < sizeof(id->Data4); ++i)
		{
			out += swprintf(out, xorstr_(L"%.2hhX"), id->Data4[i]);
			if (i == 1)
				*(out++) = '-';
		}

		return ret;
	}
	
	template <typename... FormatArgs>
	static std::wstring format_string(std::wstring_view string_template, FormatArgs... format_args)
	{
		const size_t string_size = _snwprintf(nullptr, 0, string_template.data(), std::forward<FormatArgs>(format_args)...);
		if (string_size <= 0) {
			throw std::runtime_error(L"Output string size is malformed");
		}

		auto formatted_string = new (std::nothrow) char[string_size + 1];
		if (formatted_string)
		{
			_snwprintf(formatted_string, string_size + 1, string_template.data(), std::forward<FormatArgs>(format_args)...);

			const auto stOutput = std::wstring(formatted_string);

			delete[] formatted_string;
			return stOutput;
		}

		return {};
	}

	static inline bool is_alphanumeric(const std::string& str)
	{
		return std::all_of(str.begin(), str.end(), ::isalnum);
	}
	static inline bool is_alphanumeric_w(const std::wstring& str)
	{
		return std::all_of(str.begin(), str.end(), ::iswalnum);
	}

	template <class T>
	static void reverse_string(T& str)
	{
		int n = str.length();

		for (int i = 0; i < n / 2; i++)
			std::swap(str[i], str[n - i - 1]);
	}

	template <class T>
	static void replace_all(T s, const T& search, const T& replace)
	{
		for (size_t pos = 0; ; pos += replace.length())
		{
			pos = s.find(search, pos);
			if (pos == T::npos)
				break;

			s.erase(pos, search.length());
			s.insert(pos, replace);
		}
	}

	template <class T>
	static T replace(T str, const T& from, const T& to)
	{
		if (from.empty())
			throw std::runtime_error(xorstr_("from is empty"));

		T out = str;

		std::size_t pos = 0;
		while ((pos = out.find(from, pos)) != T::npos)
		{
			out.replace(pos, from.length(), to);
			pos += to.length();
		}
		return out;
	}

	template <class T>
	static std::vector <T> split_string(const T& input, const T& delim)
	{
		auto output = std::vector<T>();

		std::size_t prev = 0;
		auto cur = input.find(delim);
		while (cur != std::wstring::npos)
		{
			output.emplace_back(input.substr(prev, cur - prev));
			prev = cur + delim.size();
			cur = input.find(delim, prev);
		}

		output.emplace_back(input.substr(prev, cur - prev));
		return output;
	}

	static std::wstring strip_unicode(const std::wstring& str)
	{
		std::wstring stCopy = str;
		stCopy.erase(remove_if(stCopy.begin(), stCopy.end(), [](wchar_t c) { return !(c >= 0 && c < 128); }), stCopy.end());
		return stCopy;
	}

	static bool has_special_char(const char* str)
	{
		return strlen(str) < 4 || str[strspn(str, xorstr_("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"))] != 0;
	}

	static std::wstring wildcart_to_regex(const std::wstring& stWildcard)
	{
		if (stWildcard.empty())
			return {};

		std::wstring stRegex = stWildcard.data();

		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"\\"), xorstr_(L"\\\\"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"^"), xorstr_(L"\\^"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"."), xorstr_(L"\\."));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"$"), xorstr_(L"\\$"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"|"), xorstr_(L"\\|"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"("), xorstr_(L"\\("));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L")"), xorstr_(L"\\)"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"["), xorstr_(L"\\["));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"]"), xorstr_(L"\\]"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"{"), xorstr_(L"\\{"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"}"), xorstr_(L"\\}"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"*"), xorstr_(L"\\*"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"+"), xorstr_(L"\\+"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"?"), xorstr_(L"\\?"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"/"), xorstr_(L"\\/"));

		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"\\*"), xorstr_(L".*"));
		stdext::replace_all<std::wstring>(stRegex, xorstr_(L"\\?"), xorstr_(L"."));

		return stRegex;
	}

	static std::string wchar_to_utf8(const std::wstring& wstSource)
	{
		static_assert(
			sizeof(std::wstring::value_type) == sizeof(char16_t) ||
			sizeof(std::wstring::value_type) == sizeof(char32_t)
		);

		std::string stRet;
		try
		{
			std::vector <std::string::value_type> vecResult;

			if constexpr (sizeof(std::wstring::value_type) == sizeof(char16_t))
				utf8::utf16to8(wstSource.begin(), wstSource.end(), std::back_inserter(vecResult));
			else
				utf8::utf32to8(wstSource.begin(), wstSource.end(), std::back_inserter(vecResult));

			stRet = std::string(vecResult.begin(), vecResult.end());
		}
		catch (utf8::exception& /* e */)
		{
#ifdef _DEBUG
			if (IsDebuggerPresent())
				__debugbreak();
#endif
			return {};
		}
		return stRet;
	}

	static std::wstring utf8_to_wchar(const std::string& stSource)
	{
		static_assert(
			sizeof(std::wstring::value_type) == sizeof(char16_t) ||
			sizeof(std::wstring::value_type) == sizeof(char32_t)
		);

		std::wstring wstRet;
		try
		{
			std::vector<std::wstring::value_type> vecResult;

			if constexpr (sizeof(std::wstring::value_type) == sizeof(char16_t))
				utf8::utf8to16(stSource.begin(), stSource.end(), std::back_inserter(vecResult));
			else
				utf8::utf8to32(stSource.begin(), stSource.end(), std::back_inserter(vecResult));

			wstRet = std::wstring(vecResult.begin(), vecResult.end());
		}
		catch (utf8::exception& /* e */)
		{
#ifdef _DEBUG
			if (IsDebuggerPresent())
				__debugbreak();
#endif
			return {};
		}
		return wstRet;
	}

	static std::string to_ansi(const std::wstring& in)
	{
#ifdef _WIN32
#pragma warning(push) 
#pragma warning(disable: 4242 4244)
#endif // _WIN32
		auto out = std::string(in.begin(), in.end());
#ifdef _WIN32
#pragma warning(push) 
#endif // _WIN32

		return out;
	}
	static std::wstring to_wide(const std::string& in)
	{
#ifdef _WIN32
#pragma warning(push) 
#pragma warning(disable: 4242 4244)
#endif // _WIN32
		auto out = std::wstring(in.begin(), in.end());
#ifdef _WIN32
#pragma warning(push) 
#endif // _WIN32

		return out;
	}

	static std::wstring bstr_to_wide(BSTR in, std::size_t length)
	{
		std::wstring wszName(in, length);
		return wszName;
	}

	static std::string bstr_to_ansi(BSTR in, std::size_t length)
	{
		const auto wstName = bstr_to_wide(in, length);
		return to_ansi(wstName);
	}

	static std::string to_lower_ansi(const std::string& in)
	{
		std::string out = in;
		std::transform(out.begin(), out.end(), out.begin(), [](int c) -> char {
			return static_cast<char>(::tolower(c));
		});
		return out;
	}
	static std::string to_lower_ansi(const std::wstring& in)
	{
		auto out = to_ansi(in);
		std::transform(out.begin(), out.end(), out.begin(), [](int c) -> char {
			return static_cast<char>(::tolower(c));
		});
		return out;
	}

	static std::wstring to_lower_wide(const std::wstring& in)
	{
		std::wstring out = in;
		std::transform(out.begin(), out.end(), out.begin(), [](int c) -> wchar_t {
			return static_cast<wchar_t>(::towlower(c));
		});
		return out;
	}
	static std::wstring to_lower_wide(const std::string& in)
	{
		auto out = to_wide(in);
		std::transform(out.begin(), out.end(), out.begin(), [](int c) -> wchar_t {
			return static_cast<wchar_t>(::tolower(c));
		});
		return out;
	}

	template <class T>
	static bool starts_with(const T& text, const T& substring)
	{
		return text.find(substring) == 0;
	}
	template <class T>
	static bool ends_with(const T& text, const T& substring)
	{
		if (substring.size() > text.size())
			return false;

		return std::equal(substring.rbegin(), substring.rend(), text.rbegin());
	}

	static ANSI_STRING string_to_ansi_string(const std::wstring& in)
	{
		ANSI_STRING out{};
		out.Buffer = (PCHAR)(in.c_str());
		out.Length = (USHORT)in.length();
		out.MaximumLength = (USHORT)in.size();
		return out;
	}
	static UNICODE_STRING string_to_unicode_string(const std::wstring& in)
	{
		UNICODE_STRING out{};
		out.Buffer = (PWCH)(in.c_str());
		out.Length = (USHORT)in.length();
		out.MaximumLength = (USHORT)in.size();
		return out;
	}

	static std::wstring ansi_string_to_string(PCANSI_STRING AnsiString)
	{
		if (!AnsiString || !AnsiString->Buffer || !AnsiString->Length ||
			!AnsiString->MaximumLength || AnsiString->MaximumLength < AnsiString->Length)
		{
			return {};
		}

		return to_wide(std::string(AnsiString->Buffer, AnsiString->Length));
	}

	static std::wstring unicode_string_to_string(PCUNICODE_STRING UnicodeString)
	{
		if (!UnicodeString || !UnicodeString->Buffer || !UnicodeString->Length ||
			!UnicodeString->MaximumLength || UnicodeString->MaximumLength < UnicodeString->Length)
		{
			return {};
		}

		return std::wstring(UnicodeString->Buffer, UnicodeString->Length / sizeof(WCHAR));
	}

	static uint32_t get_current_epoch_time()
	{
		return (uint32_t)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	}
	static uint32_t get_current_epoch_time_ms()
	{
		return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	}
	static uint32_t get_current_epoch_time_2()
	{
		time_t curTime = { 0 };
		std::time(&curTime);
		return (DWORD)curTime;
	}
	static std::wstring get_current_time_string()
	{
		const auto now = std::chrono::system_clock::now();
		const auto t = std::chrono::system_clock::to_time_t(now);

		(void)std::put_time(std::localtime(&t), xorstr_(L"%F %T"));

		const auto tm = *std::localtime(&t);

		wchar_t wszTime[32]{ L'\0' };
		wcsftime(wszTime, 32, xorstr_(L"%H:%M:%S"), &tm);

		return wszTime;
	}
	static std::wstring get_current_date()
	{
		const auto now = std::chrono::system_clock::now();
		const auto t = std::chrono::system_clock::to_time_t(now);

		(void)std::put_time(std::localtime(&t), xorstr_(L"%F %T"));

		const auto tm = *std::localtime(&t);

		wchar_t wszTime[128]{ L'\0' };
		wcsftime(wszTime, 128, xorstr_(L"%H:%M:%S - %d:%m:%Y"), &tm);

		return wszTime;
	}

	using json_data_container_t = std::map <std::wstring /* key */, std::wstring /* value */>;
	static std::wstring dump_json(const json_data_container_t& container)
	{
		GenericStringBuffer<UTF16<> > s;
		PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

		writer.StartObject();
		for (const auto& [key, value] : container)
		{
			writer.Key(key.c_str());
			writer.String(value.c_str());
		}
		writer.EndObject();

		std::wostringstream oss;
		oss << std::setw(4) << s.GetString() << std::endl;
		return oss.str();
	}

	using json_data_container_a_t = std::map <std::string /* key */, std::string /* value */>;
	static std::string dump_json_a(const json_data_container_a_t& container)
	{
		StringBuffer s;
		PrettyWriter <StringBuffer > writer(s);

		writer.StartObject();
		for (const auto& [key, value] : container)
		{
			writer.Key(key.c_str());
			writer.String(value.c_str());
		}
		writer.EndObject();

		std::ostringstream oss;
		oss << std::setw(4) << s.GetString() << std::endl;
		return oss.str();
	}
	
	static std::wstring dump_json_document(rapidjson::GenericDocument<UTF16<>>& doc)
	{
		rapidjson::GenericStringBuffer<UTF16<>> buffer;

		buffer.Clear();

		rapidjson::PrettyWriter<rapidjson::GenericStringBuffer<UTF16<>>, UTF16<>, UTF16<>> writer(buffer);
		if (!doc.Accept(writer))
			return {};

		const auto wstBuffer = std::wstring(buffer.GetString());
		return _wcsdup(wstBuffer.c_str());
	}
	
	static std::wstring dump_json_document(rapidjson::Document& doc)
	{
		rapidjson::StringBuffer buffer;

		buffer.Clear();

		rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
		if (!doc.Accept(writer))
			return {};

		const auto wstBuffer = to_wide(buffer.GetString());
		return _wcsdup(wstBuffer.c_str());
	}
	
	static std::wstring dump_json_document(rapidjson::GenericValue<UTF16<>>& val)
	{
		rapidjson::GenericStringBuffer<UTF16<>> buffer;

		buffer.Clear();

		rapidjson::PrettyWriter<rapidjson::GenericStringBuffer<UTF16<>>, UTF16<>, UTF16<>> writer(buffer);
		if (!val.Accept(writer))
			return {};

		const auto wstBuffer = std::wstring(buffer.GetString());
		return _wcsdup(wstBuffer.c_str());
	}
	
	static std::wstring dump_json_document(rapidjson::Value& val)
	{
		rapidjson::StringBuffer buffer;

		buffer.Clear();

		rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
		if (!val.Accept(writer))
			return {};

		const auto wstBuffer = to_wide(buffer.GetString());
		return _wcsdup(wstBuffer.c_str());
	}

	static void uint32_to_hex_wstring(ULONG n, LPWSTR outbuf)
	{
		if (!outbuf)
			return;

		int i = 12;
		int j = 0;

		do
		{
			outbuf[i] = xorstr_(L"0123456789ABCDEF")[n % 16];
			i--;
			n = n / 16;
		} while (n > 0);

		while (++i < 13)
		{
			outbuf[j++] = outbuf[i];
		}

		outbuf[j] = 0;
	}

#pragma warning(push) 
#pragma warning(disable: 4828)
	// Source: https://stackoverflow.com/questions/24365331/how-can-i-generate-uuid-in-c-without-using-boost-library
	static std::wstring generate_uuid_v4()
	{
		static std::random_device              rd;
		static std::mt19937                    gen(rd());
		static std::uniform_int_distribution<> dis(0, 15);
		static std::uniform_int_distribution<> dis2(8, 11);

		std::wstringstream wss;
		wss << std::hex;

		for (int i = 0; i < 8; i++)
			wss << dis(gen);

		wss << xorstr_(L"-");

		for (int i = 0; i < 4; i++)
			wss << dis(gen);

		wss << xorstr_(L"-4");

		for (int i = 0; i < 3; i++)
			wss << dis(gen);

		wss << xorstr_(L"-");
		wss << dis2(gen);

		for (int i = 0; i < 3; i++)
			wss << dis(gen);

		wss << xorstr_(L"-");

		for (int i = 0; i < 12; i++)
			wss << dis(gen);

		return wss.str();
	}

	static LPSTR* CommandLineToArgvA(LPSTR lpCmdLine, INT* pNumArgs)
	{
		int retval = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpCmdLine, -1, NULL, 0);
		if (!SUCCEEDED(retval))
			return NULL;

		LPWSTR lpWideCharStr = (LPWSTR)malloc(retval * sizeof(WCHAR));
		if (lpWideCharStr == NULL)
			return NULL;

		retval = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpCmdLine, -1, lpWideCharStr, retval);
		if (!SUCCEEDED(retval))
		{
			free(lpWideCharStr);
			return NULL;
		}

		int numArgs;
		LPWSTR* args;
		args = CommandLineToArgvW(lpWideCharStr, &numArgs);
		free(lpWideCharStr);
		if (args == NULL)
			return NULL;

		int storage = numArgs * sizeof(LPSTR);
		for (int i = 0; i < numArgs; ++i)
		{
			BOOL lpUsedDefaultChar = FALSE;
			retval = WideCharToMultiByte(CP_ACP, 0, args[i], -1, NULL, 0, NULL, &lpUsedDefaultChar);
			if (!SUCCEEDED(retval))
			{
				LocalFree(args);
				return NULL;
			}

			storage += retval;
		}

		LPSTR* result = (LPSTR*)LocalAlloc(LMEM_FIXED, storage);
		if (result == NULL)
		{
			LocalFree(args);
			return NULL;
		}

		int bufLen = storage - numArgs * sizeof(LPSTR);
		LPSTR buffer = ((LPSTR)result) + numArgs * sizeof(LPSTR);
		for (int i = 0; i < numArgs; ++i)
		{
			assert(bufLen > 0);
			BOOL lpUsedDefaultChar = FALSE;
			retval = WideCharToMultiByte(CP_ACP, 0, args[i], -1, buffer, bufLen, NULL, &lpUsedDefaultChar);
			if (!SUCCEEDED(retval))
			{
				LocalFree(result);
				LocalFree(args);
				return NULL;
			}

			result[i] = buffer;
			buffer += retval;
			bufLen -= retval;
		}

		LocalFree(args);

		*pNumArgs = numArgs;
		return result;
	}
#pragma warning(pop) 

	template <class Fn, class... Args>
	inline std::result_of_t <Fn&&(Args&&...)> __exception_safe_executor(Fn&& fn, Args&&... args)
	{
		__try
		{
			return std::invoke(std::forward<Fn>(fn), std::forward<Args>(args)...);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			// std::abort();
		}
	}
	template <class Fn, class... Args>
	inline auto exception_safe_async_runner(Fn&& fn, Args&&... args)
	{
		return std::async(std::launch::async, __exception_safe_executor<Fn, Args&&...>, std::forward<Fn>(fn), std::forward<Args>(args)...);
	}
	
	namespace str_conv
	{
		static LPCWSTR ansi_to_wide(__in_opt LPCSTR lpsz, uint32_t code_page = CP_ACP)
		{
			if (!lpsz)
				return nullptr;

			const auto count = MultiByteToWideChar(code_page, MB_PRECOMPOSED, lpsz, -1, NULL, 0);
			if (!count)
				return nullptr;

			auto pBuffer = (void*)new (std::nothrow) wchar_t[count];
			const auto result = MultiByteToWideChar(code_page, MB_PRECOMPOSED, lpsz, -1, (LPWSTR)pBuffer, count);
			if (!result)
			{
				delete[] pBuffer;
				return nullptr;
			}    

			return (LPCWSTR)pBuffer;
		}

		static LPCSTR wide_to_ansi(__in_opt LPCWSTR lpsz, uint32_t code_page = CP_ACP)
		{ 
			if (!lpsz)
				return nullptr;

			const auto count = WideCharToMultiByte(code_page, 0, lpsz, -1, NULL, 0, NULL, NULL);
			if (!count)
				return nullptr;

			auto pBuffer = (void*)new (std::nothrow) char[count];
			const auto result = WideCharToMultiByte(code_page, 0, lpsz, -1, (LPSTR)pBuffer, count, NULL, NULL);
			if (!result)
			{
				delete[] pBuffer;
				return nullptr;
			}    

			return (LPCSTR)pBuffer;
		}

		static LPCWSTR wide_to_be_wide(__in_opt LPCWSTR lpsz, UINT cch)
		{
			if (!lpsz)
				return nullptr;

			auto pBuffer = new (std::nothrow) WCHAR[cch+1];    
			for (UINT i = 0; i < cch; i++)
			{
				pBuffer[i] = (WCHAR)MAKEWORD((lpsz[i]>>8), (lpsz[i]&0xFF));
			}
			pBuffer[cch] = 0;

			return (LPCWSTR)pBuffer;
		}

		static LPCSTR wide_to_utf8_ansi(__in_opt LPCWSTR lpsz)
		{
			if (!lpsz)
				return nullptr;

			const auto count = WideCharToMultiByte(CP_UTF8, 0, lpsz, /* -1 */ wcslen(lpsz), NULL, 0, NULL, NULL);
			if (!count)
				return nullptr;

			auto pBuffer = new (std::nothrow) char[count];
			const auto result = WideCharToMultiByte(CP_UTF8, 0, lpsz, /* -1 */ wcslen(lpsz), (LPSTR)pBuffer, count, NULL, NULL);    
			if (!result)
			{      
				delete[] pBuffer;
				return nullptr;
			}    

			return (LPCSTR)pBuffer;
		}

		static LPCSTR ansi_to_utf8_ansi(__in_opt LPCSTR lpsz)
		{
			if (!lpsz)
				return nullptr;

			const auto count = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpsz, -1, NULL, 0);
			if (!count)
				return nullptr;

			auto pBuffer = new (std::nothrow) wchar_t[count];
			const auto result = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, lpsz, -1, (LPWSTR)pBuffer, count);
			if (!result)
			{
				delete[] pBuffer;
				return nullptr;
			}

			const auto pszResult = (LPCSTR)wide_to_utf8_ansi(pBuffer);
	
			delete[] pBuffer;		
			return pszResult;
		}

		static LPCWSTR utf8_ansi_to_wide(__in_opt LPCSTR lpsz)
		{
			if (!lpsz)
				return nullptr;

			const auto count = MultiByteToWideChar(CP_UTF8, 0, lpsz, /* -1 */ strlen(lpsz), NULL, 0);
			if (!count)
				return nullptr;

			auto pBuffer = new (std::nothrow) wchar_t[count];
			const auto result = MultiByteToWideChar(CP_UTF8, 0, lpsz, /* -1 */ strlen(lpsz), (LPWSTR)pBuffer, count);    
			if (!result)
			{      
				delete[] pBuffer;
				return nullptr;
			}    

			return (LPCWSTR)pBuffer;
		}

		static LPCWSTR utf8_ansi_to_wide(__in_opt LPCSTR pStr, UINT cch)
		{
			if (!pStr)
				return nullptr;

			const auto count = MultiByteToWideChar(CP_UTF8, 0, pStr, cch, NULL, 0);
			if (!count)
				return nullptr;

			auto pBuffer = new (std::nothrow) wchar_t[count+1];
			const auto result = MultiByteToWideChar(CP_UTF8, 0, pStr, cch, (LPWSTR)pBuffer, count);    
			if (!result)
			{      
				delete[] pBuffer;
				return nullptr;
			}
			pBuffer[count] = 0;

			return (LPCWSTR)pBuffer;
		}

		static LPCSTR utf8_ansi_to_ansi(__in_opt LPCSTR lpsz)
		{
			return wide_to_ansi(utf8_ansi_to_wide(lpsz));
		}
	};


	namespace CRT
	{
		namespace mem
		{
			static int toupper(int c)
			{
				if (c >= 'a' && c <= 'z') return c - 'a' + 'A';
				return c;
			}

			static void* memcpy(void* dest, const void* src, unsigned __int64 count)
			{
				char* char_dest = (char*)dest;
				char* char_src = (char*)src;
				if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
				{
					while (count > 0)
					{
						*char_dest = *char_src;
						char_dest++;
						char_src++;
						count--;
					}
				}
				else
				{
					char_dest = (char*)dest + count - 1;
					char_src = (char*)src + count - 1;
					while (count > 0)
					{
						*char_dest = *char_src;
						char_dest--;
						char_src--;
						count--;
					}
				}
				return dest;
			}
			static void* memccpy(void* to, const void* from, int c, unsigned __int64 count)
			{
				char t;
				unsigned __int64 i;
				char* dst = (char*)to;
				const char* src = (const char*)from;
				for (i = 0; i < count; i++)
				{
					dst[i] = t = src[i];
					if (t == 0) break;
					if (t == c) return &dst[i + 1];
				}
				return 0;
			}
			static void* memchr(const void* s, int c, unsigned __int64 n)
			{
				if (n)
				{
					const char* p = (const char*)s;
					do
					{
						if (*p++ == c) return (void*)(p - 1);
					} while (--n != 0);
				}
				return 0;
			}
			static int  memcmp(const void* s1, const void* s2, unsigned __int64 n)
			{
				if (n != 0)
				{
					const unsigned char* p1 = (unsigned char*)s1, * p2 = (unsigned char*)s2;
					do
					{
						if (*p1++ != *p2++) return (*--p1 - *--p2);
					} while (--n != 0);
				}
				return 0;
			}
			static int  memicmp(const void* s1, const void* s2, unsigned __int64 n)
			{
				if (n != 0)
				{
					const unsigned char* p1 = (unsigned char*)s1, * p2 = (unsigned char*)s2;
					do
					{
						if (toupper(*p1) != toupper(*p2)) return (*p1 - *p2);
						p1++;
						p2++;
					} while (--n != 0);
				}
				return 0;
			}

			static void* memmove(void* dest, const void* src, unsigned __int64 count)
			{
				char* char_dest = (char*)dest;
				char* char_src = (char*)src;
				if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
				{
					while (count > 0)
					{
						*char_dest = *char_src;
						char_dest++;
						char_src++;
						count--;
					}
				}
				else
				{
					char_dest = (char*)dest + count - 1;
					char_src = (char*)src + count - 1;
					while (count > 0)
					{
						*char_dest = *char_src;
						char_dest--;
						char_src--;
						count--;
					}
				}
				return dest;
			}

#pragma optimize("", off)
			static VOID __memset(__out void* lpDest, __in int nVal, __in SIZE_T nCount)
			{
				LPBYTE d;
				SIZE_T n;

				d = (LPBYTE)lpDest;
				nVal &= 0xFF;
				if (XISALIGNED(d))
				{
					n = ((SIZE_T)nVal) | (((SIZE_T)nVal) << 8);
					n = n | (n << 16);
#if defined(_M_X64) || defined(_M_IA64) || defined(_M_AMD64)
					n = n | (n << 32);
#endif //_M_X64 || _M_IA64 || _M_AMD64
					while (nCount >= sizeof(SIZE_T))
					{
						*((SIZE_T*)d) = n;
						d += sizeof(SIZE_T);
						nCount -= sizeof(SIZE_T);
					}
				}
				//the following code is not fully optimized on purpose just but avoid VC compiler to insert undesired "_memset" calls
				if (nCount > 0)
				{
					do
					{
						*d++ = (BYTE)nVal;
					} while (--nCount > 0);
				}
				return;
			}
#pragma optimize("", on)
			static VOID __memcpy(__out void* lpDest, __in const void* lpSrc, __in SIZE_T nCount)
			{
				LPBYTE s, d;

				s = (LPBYTE)lpSrc;
				d = (LPBYTE)lpDest;
				if (XISALIGNED(s) && XISALIGNED(d))
				{
					while (nCount >= sizeof(SIZE_T))
					{
						*((SIZE_T*)d) = *((SIZE_T*)s);
						s += sizeof(SIZE_T);
						d += sizeof(SIZE_T);
						nCount -= sizeof(SIZE_T);
					}
				}
				while (nCount > 0)
				{
					*d++ = *s++;
					nCount--;
				}
				return;
			}
			static VOID __memmove(__out void* lpDest, __in const void* lpSrc, __in SIZE_T nCount)
			{
				LPBYTE s, d;

				s = (LPBYTE)lpSrc;
				d = (LPBYTE)lpDest;
				if (d <= s || d >= (s + nCount))
				{
					//dest is before source or non-overlapping buffers
					//copy from lower to higher addresses
					if (d + sizeof(SIZE_T) <= s && XISALIGNED(s) && XISALIGNED(d))
					{
						while (nCount >= sizeof(SIZE_T))
						{
							*((SIZE_T*)d) = *((SIZE_T*)s);
							s += sizeof(SIZE_T);
							d += sizeof(SIZE_T);
							nCount -= sizeof(SIZE_T);
						}
					}
					while ((nCount--) > 0)
						*d++ = *s++;
				}
				else
				{
					//dest is past source or overlapping buffers
					//copy from higher to lower addresses
					if (nCount >= sizeof(SIZE_T) && XISALIGNED(s) && XISALIGNED(d))
					{
						s += nCount;
						d += nCount;
						while (nCount > 0 && (!XISALIGNED(nCount))) {
							--s;
							--d;
							*d = *s;
							nCount--;
						}
						while (nCount > 0)
						{
							s -= sizeof(SIZE_T);
							d -= sizeof(SIZE_T);
							*((SIZE_T*)d) = *((SIZE_T*)s);
							nCount -= sizeof(SIZE_T);
						}
					}
					else
					{
						s += nCount;
						d += nCount;
						while (nCount > 0)
						{
							--s;
							--d;
							*d = *s;
							nCount--;
						}
					}
				}
				return;
			}
			static int __memcmp(__in const void* lpBuf1, __in const void* lpBuf2, __in SIZE_T nCount)
			{
				LPBYTE b1, b2;

				if (nCount == 0)
					return 0;
				b1 = (LPBYTE)lpBuf1;
				b2 = (LPBYTE)lpBuf2;
				while ((--nCount) > 0 && b1[0] == b2[0])
				{
					b1++;
					b2++;
				}
				return (int)(b1[0] - b2[0]);
			}
		}
		namespace string
		{
			static int toupper(int c)
			{
				if (c >= 'a' && c <= 'z') return c - 'a' + 'A';
				return c;
			}
			static int tolower(int c)
			{
				if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
				return c;
			}

			static char* _cslwr(char* x)
			{
				char* y = x;
				while (*y)
				{
					*y = tolower(*y);
					y++;
				}
				return x;
			}
			static char* _csupr(char* x)
			{
				char* y = x;
				while (*y)
				{
					*y = tolower(*y);
					y++;
				}
				return x;
			}

			static  int strlen(const char* string)
			{
				int cnt = 0;
				if (string)
				{
					for (; *string != 0; ++string) ++cnt;
				}
				return cnt;
			}
			static const char* strcpy(char* buffer, const char* string)
			{
				char* ret = buffer;
				while (*string) *buffer++ = *string++;
				*buffer = 0;
				return ret;
			}
			static  const char* strcpy(char* buffer, const wchar_t* string)
			{
				char* ret = buffer;
				while (*string) *buffer++ = char(*string++);
				*buffer = 0;
				return ret;
			}

			static int strcmp(const char* cs, const char* ct)
			{
				if (cs && ct)
				{
					while (*cs == *ct)
					{
						if (*cs == 0 && *ct == 0) return 0;
						if (*cs == 0 || *ct == 0) break;
						cs++;
						ct++;
					}
					return *cs - *ct;
				}
				return -1;
			}
			static int stricmp(const char* cs, const char* ct)
			{
				if (cs && ct)
				{
					while (tolower(*cs) == tolower(*ct))
					{
						if (*cs == 0 && *ct == 0) return 0;
						if (*cs == 0 || *ct == 0) break;
						cs++;
						ct++;
					}
					return tolower(*cs) - tolower(*ct);
				}
				return -1;
			}

			static int stricmp(UCHAR cs, const char* ct)
			{
				if (ct)
				{
					while (tolower(cs) == tolower(*ct))
					{
						if (cs == 0 && *ct == 0) return 0;
						if (cs == 0 || *ct == 0) break;

						ct++;
					}
					return tolower(cs) - tolower(*ct);
				}
				return -1;
			}

			static int _strncmp_a(const char* s1, const char* s2, size_t cchars)
			{
				char c1, c2;

				if (s1 == s2)
					return 0;

				if (s1 == 0)
					return -1;

				if (s2 == 0)
					return 1;

				if (cchars == 0)
					return 0;

				do {
					c1 = *s1;
					c2 = *s2;
					s1++;
					s2++;
					cchars--;
				} while ((c1 != 0) && (c1 == c2) && (cchars > 0));

				return (int)(c1 - c2);
			}

			static size_t _strlen_a(const char* s)
			{
				char* s0 = (char*)s;

				if (s == 0)
					return 0;

				while (*s != 0)
					s++;

				return (s - s0);
			}
			static size_t _strlen_w(const wchar_t* s)
			{
				wchar_t* s0 = (wchar_t*)s;

				if (s == 0)
					return 0;

				while (*s != 0)
					s++;

				return (s - s0);
			}

			static char* _strncpy_a(char* dest, size_t ccdest, const char* src, size_t ccsrc)
			{
				char* p;

				if ((dest == 0) || (src == 0) || (ccdest == 0))
					return dest;

				ccdest--;
				p = dest;

				while ((*src != 0) && (ccdest > 0) && (ccsrc > 0)) {
					*p = *src;
					p++;
					src++;
					ccdest--;
					ccsrc--;
				}

				*p = 0;
				return dest;
			}








			static wchar_t* _cslwr(wchar_t* x)
			{
				wchar_t* y = x;
				while (*y)
				{
					*y = towlower(*y);
					y++;
				}
				return x;
			}
			static wchar_t* _csupr(wchar_t* x)
			{
				wchar_t* y = x;
				while (*y)
				{
					*y = towupper(*y);
					y++;
				}
				return x;
			}

			static int strlen(const wchar_t* string)
			{
				int cnt = 0;
				if (string)
				{
					for (; *string != 0; ++string) ++cnt;
				}
				return cnt;
			}
			static  const wchar_t* strcpy(wchar_t* buffer, const wchar_t* string)
			{
				wchar_t* ret = buffer;
				while (*string) *buffer++ = *string++;
				*buffer = L'\0';
				return ret;
			}
			static const wchar_t* strcpy(wchar_t* buffer, const char* string)
			{
				wchar_t* ret = buffer;
				while (*string) *buffer++ = wchar_t(*string++);
				*buffer = 0;
				return ret;
			}

			static int strcmp(const wchar_t* cs, const wchar_t* ct)
			{
				if (cs && ct)
				{
					while (*cs == *ct)
					{
						if (*cs == 0 && *ct == 0) return 0;
						if (*cs == 0 || *ct == 0) break;
						cs++;
						ct++;
					}
					return *cs - *ct;
				}
				return -1;
			}
			static  int stricmp(const wchar_t* cs, const wchar_t* ct)
			{
				if (cs && ct)
				{
					while (towlower(*cs) == towlower(*ct))
					{
						if (*cs == 0 && *ct == 0) return 0;
						if (*cs == 0 || *ct == 0) break;
						cs++;
						ct++;
					}
					return towlower(*cs) - towlower(*ct);
				}
				return -1;
			}



			static wchar_t* wstrchr(const wchar_t* s, wchar_t c)
			{
				wchar_t cc = c;
				const wchar_t* sp = (wchar_t*)0;
				while (*s)
				{
					if (*s == cc) sp = s;
					s++;
				}
				if (cc == 0) sp = s;
				return (wchar_t*)sp;
			}
			static wchar_t* wstrtok_s(wchar_t* str, const wchar_t* delim, wchar_t** ctx)
			{
				if (!str) str = *ctx;
				while (*str && wstrchr(delim, *str)) str++;
				if (!*str)
				{
					*ctx = str;
					return 0;
				}
				*ctx = str + 1;
				while (**ctx && !wstrchr(delim, **ctx)) (*ctx)++;
				if (**ctx) *(*ctx)++ = 0;
				return str;
			}
			static  bool iswdigit(wchar_t c) { return c >= L'0' && c <= L'9'; }
			static __int64 wtoi64(const wchar_t* nptr)
			{
				wchar_t* s = (wchar_t*)nptr;
				__int64 acc = 0;
				int neg = 0;
				if (nptr == 0) return 0;
				// while (*s = L' ') s++;
				if (*s == L'-')
				{
					neg = 1;
					s++;
				}
				else if (*s == L'+') s++;
				while (iswdigit(*s))
				{
					acc = 10 * acc + (*s - L'0');
					s++;
				}
				if (neg) acc *= -1;
				return acc;
			}
			static int wtoi(const wchar_t* nptr)
			{
				wchar_t* s = (wchar_t*)nptr;
				int acc = 0;
				int neg = 0;
				if (nptr == 0) return 0;
				// while (*s = L' ') s++;
				if (*s == L'-')
				{
					neg = 1;
					s++;
				}
				else if (*s == L'+') s++;
				while (iswdigit(*s))
				{
					acc = 10 * acc + (*s - L'0');
					s++;
				}
				if (neg) acc *= -1;
				return acc;
			}
			static wchar_t* itow(int number, wchar_t* destination, int base)
			{
				int count = 0;
				do
				{
					int digit = number % base;
					destination[count++] = (digit > 9) ? digit - 10 + L'A' : digit + L'0';
				} while ((number /= base) != 0);
				destination[count] = 0;
				int i;
				for (i = 0; i < count / 2; ++i)
				{
					wchar_t symbol = destination[i];
					destination[i] = destination[count - i - 1];
					destination[count - i - 1] = symbol;
				}
				return destination;
			}


			static const char* strstr(char const* _Str, char const* _SubStr)
			{
				const char* bp = _SubStr;
				const char* back_pos;
				while (*_Str != 0 && _Str != 0 && _SubStr != 0)
				{
					back_pos = _Str;
					while (tolower(*back_pos++) == tolower(*_SubStr++))
					{
						if (*_SubStr == 0)
						{
							return (char*)(back_pos - strlen(bp));
						}
					}
					++_Str;
					_SubStr = bp;
				}
				return 0;
			}


			static char* strcatA(char* dest, const char* src)
			{
				if ((dest == 0) || (src == 0))
					return dest;

				while (*dest != 0)
					dest++;

				while (*src != 0) {
					*dest = *src;
					dest++;
					src++;
				}

				*dest = 0;
				return dest;
			}

			static wchar_t* strcatW(wchar_t* dest, const wchar_t* src)
			{
				if ((dest == 0) || (src == 0))
					return dest;

				while (*dest != 0)
					dest++;

				while (*src != 0) {
					*dest = *src;
					dest++;
					src++;
				}

				*dest = 0;
				return dest;
			}
		}
	}
};

#pragma warning(pop) 
