#include <windows.h>
#include <cstdlib>
#include <cassert>
#include <ctime>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <fmt/format.h>
#include <sqlite3.h>
#include <cxxopts.hpp>
#include "../../source/Core/EngineR3_Core/include/Defines.hpp"
using namespace std::string_literals;

#ifdef _DEBUG
#pragma comment(lib, "sqlite3d.lib")
#else
#pragma comment(lib, "sqlite3.lib")
#endif

static auto gs_bIgnoreAlreadyDecryptedDBs = false;
static constexpr auto gsc_nDbKeySize = 256;
static constexpr unsigned char gsc_pDbKey[gsc_nDbKeySize] = {
	0x79, 0x8A, 0x42, 0x0F, 0x2B, 0x1E, 0x6F, 0xCD, 0x98, 0xE3, 0x04, 0x93,
	0x5E, 0xF0, 0x87, 0x11, 0x7C, 0x65, 0x7D, 0x8D, 0x26, 0x9C, 0xE5, 0x97,
	0x7B, 0x13, 0x1D, 0xAA, 0x37, 0x5D, 0x5A, 0x99, 0x54, 0x12, 0x62, 0x27,
	0x9F, 0x9C, 0xE2, 0x72, 0xF4, 0x9A, 0x8C, 0x8A, 0x61, 0x45, 0x52, 0x1E,
	0xC1, 0xE4, 0xBD, 0x6A, 0x28, 0xF7, 0x67, 0xA8, 0xF1, 0x5B, 0x90, 0x9F,
	0xDB, 0x29, 0x1D, 0xD6, 0x53, 0xFC, 0x45, 0xBC, 0xD3, 0x30, 0x8C, 0x3C,
	0x24, 0xD8, 0x56, 0x6B, 0x72, 0x89, 0xC7, 0x38, 0x0B, 0x87, 0x1B, 0x58,
	0x5A, 0x99, 0x41, 0xD0, 0xDE, 0xE2, 0xB0, 0xF3, 0xCF, 0x62, 0x9E, 0x95,
	0x6D, 0xB6, 0x8C, 0x67, 0xB3, 0x1A, 0xC9, 0x79, 0x28, 0x87, 0x9E, 0x1B,
	0x0F, 0x62, 0xF0, 0x67, 0xB3, 0xD1, 0xED, 0x42, 0xD3, 0xCA, 0x5C, 0xC2,
	0x1D, 0x3A, 0x1D, 0x48, 0x3A, 0x62, 0x1D, 0x34, 0xE8, 0x24, 0xBB, 0x45,
	0x84, 0x88, 0xA5, 0x1E, 0x51, 0x0C, 0xB2, 0x33, 0x6B, 0x62, 0xC1, 0x6D,
	0x8B, 0x2C, 0xE7, 0xF3, 0xA9, 0xB0, 0x35, 0x0C, 0x18, 0xF9, 0xA7, 0x0E,
	0x56, 0xAA, 0x27, 0xA8, 0x3A, 0x74, 0xBE, 0xED, 0xA9, 0x1C, 0x9C, 0x41,
	0x35, 0xAE, 0xE9, 0x18, 0xE1, 0xF0, 0xE5, 0x56, 0x19, 0x2C, 0xA3, 0x36,
	0xC1, 0xC4, 0xDA, 0x25, 0x27, 0xEC, 0x3F, 0x5B, 0x41, 0x4D, 0x21, 0xDA,
	0xB7, 0x84, 0xDF, 0x8F, 0x6B, 0x58, 0xA3, 0x0C, 0xA2, 0x97, 0x13, 0x9F,
	0x14, 0xB7, 0x4C, 0x2D, 0x73, 0x56, 0xDF, 0x92, 0x1F, 0xED, 0x09, 0xF9,
	0x3A, 0x83, 0x2B, 0xE3, 0xB5, 0x3B, 0xBB, 0x91, 0x17, 0x6E, 0xA2, 0xC7,
	0x41, 0x92, 0x35, 0xC8, 0x75, 0x76, 0x22, 0xB7, 0x5C, 0x23, 0x17, 0x13,
	0xE1, 0xFC, 0x4A, 0xC2, 0x0A, 0x6A, 0x36, 0x29, 0xF3, 0x7D, 0x6C, 0xE5,
	0xE3, 0x29, 0xD4, 0x77
};
struct SDbContext
{
	int32_t category;
	std::string func;
	int32_t level;
	std::wstring data;
	int64_t time;
};

inline std::string GetCategoryName(int32_t category)
{
	switch (category)
	{
		case LOG_GENERAL:
			return "General";
		case LOG_HOOK:
			return "Hook";
		case LOG_SCANNER:
			return "Scanner";
		case LOG_SDK:
			return "SDK";
		case LOG_WMI:
			return "WMI";
		case LOG_NETWORK:
			return "Network";
		case LOG_KERNEL:
			return "Kernel";
		default:
			return std::to_string(category);
	};
}
inline std::string GetLogLevelStr(int32_t level)
{
	switch (level)
	{
		case 0:
			return "SYS_LOG";
		case 1:
			return "ERR_LOG";
		case 2:
			return "CRIT_LOG";
		case 3:
			return "WARN_LOG";
		case 4:
			return "DEV_LOG";
		case 5:
			return "TRACE_LOG";
		default:
			return std::to_string(level);
	}
}
inline std::string GetNameFromPath(std::string stFileName)
{
	auto iLastSlash = stFileName.find_last_of("\\/");
	return stFileName.substr(iLastSlash + 1, stFileName.length() - iLastSlash);
}
inline void WriteToFile(const std::string& szFileName, const std::string& szText)
{
	std::ofstream f(szFileName.c_str(), std::ofstream::out | std::ofstream::app);
	f << szText.c_str() << std::endl;
	f.close();
}
inline std::string OpenFileDialog(const std::string& stTitle)
{
	char buffer[1024] = { 0 };

	OPENFILENAMEA ofns = { 0 };
	ofns.lStructSize = sizeof(ofns);
	ofns.lpstrFile = buffer;
	ofns.nMaxFile = sizeof(buffer);
	ofns.lpstrTitle = stTitle.c_str();

	if (!GetOpenFileNameA(&ofns))
	{
		printf("GetOpenFileNameA failed with error: %u\n", GetLastError());
		return "";
	}
	return buffer;
}

int32_t main(int32_t argc, char* argv[])
{
	auto decrypt_routine = [](std::string target_db) {
		if (target_db.empty())
		{
			target_db = OpenFileDialog("Choose database to decrypt");
			if (target_db.empty())
			{
				printf("Target database file is not found\n");
				return false;
			}
		}

		if (!std::filesystem::exists(target_db))
		{
			printf("Target file: %s does not exist\n", target_db.c_str());
			return false;
		}

		sqlite3* db = nullptr;
		auto ret = sqlite3_open(target_db.c_str(), &db);
		if (ret != SQLITE_OK)
		{
			printf("sqlite3_open failed with error: %d\n", ret);
			return false;
		}

		ret = sqlite3_key(db, gsc_pDbKey, gsc_nDbKeySize);
		if (ret != SQLITE_OK)
		{
			printf("sqlite3_key failed with error: %d\n", ret);
			return false;
		}

		ret = sqlite3_rekey(db, nullptr, 0);
		if (ret != SQLITE_OK)
		{
			printf("sqlite3_rekey failed with error: %d\n", ret);
			if ((gs_bIgnoreAlreadyDecryptedDBs && ret != SQLITE_NOTADB) || !gs_bIgnoreAlreadyDecryptedDBs) // SQLITE_NOTADB means that database is already decrypted
				return false;
		}

		printf("Target database: %s successfully decrypted.\n", target_db.c_str());
		sqlite3_close(db);
		return true;
	};

	auto dump_routine = [](std::string target_db) {
		DWORD last_error = 0;
		if (!CreateDirectoryA("dump", nullptr) && (last_error = GetLastError()) != ERROR_ALREADY_EXISTS)
		{
			printf("CreateDirectoryA failed with error: %u\n", last_error);
			return false;
		}

		if (target_db.empty())
		{
			target_db = OpenFileDialog("Choose database to decrypt");
			if (target_db.empty())
			{
				printf("Target database file is not found\n");
				return false;
			}
		}

		if (!std::filesystem::exists(target_db))
		{
			printf("Target file: %s does not exist\n", target_db.c_str());
			return false;
		}

		sqlite3* db = nullptr;
		auto ret = sqlite3_open(target_db.c_str(), &db);
		if (ret != SQLITE_OK)
		{
			printf("sqlite3_open failed with error: %d\n", ret);
			return false;
		}

		sqlite3_stmt* statement = nullptr;
		ret = sqlite3_prepare(db, "SELECT * FROM Logs", -1, &statement, 0);
		if (ret != SQLITE_OK)
		{
			printf("sqlite3_prepare: %s\n", sqlite3_errmsg(db));
			return false;
		}

		ret = sqlite3_step(statement);
		const auto col_count = sqlite3_column_count(statement);

		std::vector <SDbContext> data_container;
		while (ret == SQLITE_ROW)
		{
			if (col_count != 5)
			{
				printf("column count mismatch: %d\n", col_count);
				return false;
			}

			SDbContext ctx{ 0 };
			ctx.category = sqlite3_column_int(statement, 0);
			ctx.func = (const char*)sqlite3_column_text(statement, 1);
			ctx.level = sqlite3_column_int(statement, 2);
			ctx.data = (const wchar_t*)sqlite3_column_text16(statement, 3);
			ctx.time = sqlite3_column_int64(statement, 4);
			data_container.emplace_back(ctx);
			
			ret = sqlite3_step(statement);
		}

		sqlite3_finalize(statement);

		for (const auto& [category, func, level, data, time] : data_container)
		{
			const auto readable_level = GetLogLevelStr(level);
			const auto dump_file = fmt::format("dump\\{}_{}_dump.txt", GetNameFromPath(target_db), GetCategoryName(category));
			std::string human_readable_time = std::ctime(&time);
			human_readable_time.pop_back();

			const auto data_a = stdext::to_ansi(data);
			WriteToFile(dump_file, fmt::format("[{}] - {} - {} :: {}", human_readable_time, readable_level, func, data_a));
		}

		printf("Target database: %s successfully dumped.\n", target_db.c_str());
		sqlite3_close(db);
		return true;	
	};

	auto run_worker = [&](const std::string& type, const std::string& target_db)
	{
		auto ret = 0;

		printf("Target file: %s\n", target_db.c_str());

		if (type == "decrypt")
			ret = decrypt_routine(target_db);
		else if (type == "dump")
			ret = dump_routine(target_db);
		else if (type == "full")
		{
			if (!decrypt_routine(target_db))
			{
				printf("%s decrypt failed\n", target_db.c_str());
				return EXIT_FAILURE;
			}
			ret = dump_routine(target_db);
		}

		if (!ret)
			printf("Log file: %s processing failed for type: %s\n", target_db.c_str(), type.c_str());
		return ret;
	};

	cxxopts::Options options(argv[0], "");

	options.add_options()
		("t,type", "Work type", cxxopts::value<std::string>())
		("f,file", "Target file", cxxopts::value<std::string>())
		("h,help", "Print usage")
	;

	if (argc < 2)
	{
		printf("%s\n", options.help().c_str());
		return EXIT_FAILURE;
	}

	try
	{
		auto result = options.parse(argc, argv);
		if (!result.count("type") || result.count("help"))
		{
			printf("%s\n", options.help().c_str());
			return EXIT_FAILURE;
		}

		auto ret = false;
		const auto target_db = result.count("file") ? result["file"].as<std::string>() : ""s;
		const auto type = result["type"].as<std::string>();

		if (result.count("ignore_decrypted"))
		{
			gs_bIgnoreAlreadyDecryptedDBs = true;
		}

		if (type != "decrypt" && type != "dump" && type != "full")
		{
			printf("Unknown work type: %s\n", type.c_str());
			return EXIT_FAILURE;
		}
		
		std::error_code ec{};
		std::filesystem::remove_all("dump", ec);
		if (ec)
		{
			printf("Failed to remove dump directory: %s\n", ec.message().c_str());
		}

		if (target_db == "*")
		{
			for (const auto& entry : std::filesystem::directory_iterator("."))
			{
				if (!entry.is_regular_file())
					continue;

				if (entry.path().extension() != ".log")
					continue;

				ret = run_worker(type, entry.path().string());
			}
		}
		else
		{
			ret = run_worker(type, target_db);
		}

		printf("Target database: %s successfully processed.\n", target_db.c_str());
		std::cin.get();
		return ret ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	catch (const cxxopts::exceptions::exception& ex)
	{
		const auto msg = fmt::format("IO Console parse exception: {}", ex.what());
		MessageBoxA(NULL, msg.c_str(), "Error", MB_OK | MB_ICONERROR);
		return EXIT_FAILURE;
	}
	catch (const std::exception& ex)
	{
		const auto msg = fmt::format("IO System exception: {}", ex.what());
		MessageBoxA(NULL, msg.c_str(), "Error", MB_OK | MB_ICONERROR);
		return EXIT_FAILURE;
	}
	catch (...)
	{
		assert(0 && "IO Unhandled exception");
		return EXIT_FAILURE;
	}
}
