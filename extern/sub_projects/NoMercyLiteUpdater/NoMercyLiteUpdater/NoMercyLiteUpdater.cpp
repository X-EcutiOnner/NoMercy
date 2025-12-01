#include <iostream>
#include <Windows.h>
#include <cpr/cpr.h>
#include <fmt/format.h>
#include <zlib.h>
#include <sys/stat.h>

#define LZO_E_OK 1
#define LZO_E_INPUT_OVERRUN (-1)
#define LZO_E_EOF_NOT_FOUND (-2)
#define LZO_E_INPUT_NOT_CONSUMED (-3)

// LZO decompression (https://raw.githubusercontent.com/martysama0134/mt2lz/master/mt2lz/mt2lz.cpp)
int lzo_decompress(const unsigned char* in, unsigned long in_len, unsigned char* out, unsigned long* out_len)
{
	register unsigned char* op;
	register const unsigned char* ip;
	register unsigned long t;
	register const unsigned char* m_pos;

	const unsigned char* const ip_end = in + in_len;
	unsigned char* const op_end = out + *out_len;

	*out_len = 0;

	op = out;
	ip = in;

	if (*ip > 17)
	{
		t = *ip++ - 17;
		if (t < 4)
			goto match_next;
		do
			*op++ = *ip++;
		while (--t > 0);
		goto first_literal_run;
	}

	while (ip < ip_end)
	{
		t = *ip++;
		if (t >= 16)
			goto match;
		if (t == 0)
		{
			while (*ip == 0)
			{
				t += 255;
				ip++;
			}
			t += 15 + *ip++;
		}
		((*(volatile unsigned int*)(volatile void*)(op)) =
			(unsigned long)(*(volatile const unsigned int*)(volatile const void*)(ip)));
		op += 4;
		ip += 4;
		if (--t > 0)
		{
			if (t >= 4)
			{
				do
				{
					((*(volatile unsigned int*)(volatile void*)(op)) =
						(unsigned long)(*(volatile const unsigned int*)(volatile const void*)(ip)));
					op += 4;
					ip += 4;
					t -= 4;
				} while (t >= 4);
				if (t > 0)
					do
						*op++ = *ip++;
				while (--t > 0);
			}
			else
				do
					*op++ = *ip++;
			while (--t > 0);
		}

	first_literal_run:

		t = *ip++;
		if (t >= 16)
			goto match;
		m_pos = op - (1 + 0x0800);
		m_pos -= t >> 2;
		m_pos -= *ip++ << 2;
		*op++ = *m_pos++;
		*op++ = *m_pos++;
		*op++ = *m_pos;
		goto match_done;

		do
		{
		match:
			if (t >= 64)
			{
				m_pos = op - 1;
				m_pos -= (t >> 2) & 7;
				m_pos -= *ip++ << 3;
				t = (t >> 5) - 1;
				goto copy_match;
			}
			else if (t >= 32)
			{
				t &= 31;
				if (t == 0)
				{
					while (*ip == 0)
					{
						t += 255;
						ip++;
					}
					t += 31 + *ip++;
				}
				m_pos = op - 1;
				m_pos -= (*(volatile const unsigned short*)(volatile const void*)(ip)) >> 2;
				ip += 2;
			}
			else if (t >= 16)
			{
				m_pos = op;
				m_pos -= (t & 8) << 11;
				t &= 7;
				if (t == 0)
				{
					while (*ip == 0)
					{
						t += 255;
						ip++;
					}
					t += 7 + *ip++;
				}
				m_pos -= (*(volatile const unsigned short*)(volatile const void*)(ip)) >> 2;
				ip += 2;
				if (m_pos == op)
					goto eof_found;
				m_pos -= 0x4000;
			}
			else
			{
				m_pos = op - 1;
				m_pos -= t >> 2;
				m_pos -= *ip++ << 2;
				*op++ = *m_pos++;
				*op++ = *m_pos;
				goto match_done;
			}

			if (t >= 2 * 4 - (3 - 1) && (op - m_pos) >= 4)
			{
				((*(volatile unsigned int*)(volatile void*)(op)) =
					(unsigned long)(*(volatile const unsigned int*)(volatile const void*)(m_pos)));
				op += 4;
				m_pos += 4;
				t -= 4 - (3 - 1);
				do
				{
					((*(volatile unsigned int*)(volatile void*)(op)) =
						(unsigned long)(*(volatile const unsigned int*)(volatile const void*)(m_pos)));
					op += 4;
					m_pos += 4;
					t -= 4;
				} while (t >= 4);
				if (t > 0)
					do
						*op++ = *m_pos++;
				while (--t > 0);
			}
			else
			{
			copy_match:
				*op++ = *m_pos++;
				*op++ = *m_pos++;
				do
					*op++ = *m_pos++;
				while (--t > 0);
			}


		match_done:
			t = ip[-2] & 3;
			if (t == 0)
				break;

		match_next:
			*op++ = *ip++;
			if (t > 1)
			{
				*op++ = *ip++;
				if (t > 2)
				{
					*op++ = *ip++;
				}
			}
			t = *ip++;
		} while (ip < ip_end);
	}
	*out_len = ((unsigned long)((op)-(out)));
	return LZO_E_EOF_NOT_FOUND;

eof_found:
	*out_len = ((unsigned long)((op)-(out)));
	return (ip == ip_end ? LZO_E_OK : (ip < ip_end ? LZO_E_INPUT_NOT_CONSUMED : LZO_E_INPUT_OVERRUN));
}

bool DecompressLZO(unsigned char*& buffer, std::size_t& length)
{
	unsigned long uncompressedSize = *(unsigned long*)buffer;
	unsigned char* uncompressedBuffer = new unsigned char[uncompressedSize];
	memset(uncompressedBuffer, 0, uncompressedSize);

	unsigned long finalSize = 0;
	lzo_decompress((PBYTE)buffer + 4, uncompressedSize, uncompressedBuffer, &finalSize);
	if (finalSize != uncompressedSize)
	{
		printf("There was an error when decompressing %s file.\n");
		printf("%i %i\n", finalSize, uncompressedSize);
		return false;
	}
	
	buffer = uncompressedBuffer;
	length = finalSize;
	return true;
}

// Validate semver
static bool isValidVersion(const std::string& version)
{
	if (version.empty())
		return false;

	size_t pos = 0;
	for (int i = 0; i < 3; ++i)
	{
		const auto nextPos = version.find('.', pos);
		if (nextPos == std::string::npos)
			return false;

		const auto part = version.substr(pos, nextPos - pos);
		if (part.empty())
			return false;

		for (const auto c : part)
		{
			if (!isdigit(c))
				return false;
		}

		pos = nextPos + 1;
	}

	const auto part = version.substr(pos);
	if (part.empty())
		return false;

	for (const auto c : part)
	{
		if (!isdigit(c))
			return false;
	}

	return true;
}

int main()
{
	printf("NoMercy Lite Updater started!\n");

	// Get latest version
	auto res = cpr::Get(cpr::Url{ "https://storage.nomercy.ac/latest" });
	if (res.error.code != cpr::ErrorCode::OK)
	{
		printf("Failed to get latest version from server! Internal error: %u (%s)\n", res.error.code, res.error.message.c_str());
		return EXIT_FAILURE;
	}
	else if (res.status_code != 200)
	{
		printf("Failed to get latest version from server! Server responded with status code %u\n", res.status_code);
		return EXIT_FAILURE;
	}
	const auto latestVersion = res.text;
	if (latestVersion.empty())
	{
		printf("Failed to get latest version from server! Server responded with empty string");
		return EXIT_FAILURE;
	}
	else if (!isValidVersion(latestVersion))
	{
		printf("Failed to get latest version from server! Server responded with invalid version string");
		return EXIT_FAILURE;
	}

	// Read file list with (crc32, size, mtime1, mtime2, local_path) format
	res = cpr::Get(cpr::Url{ fmt::format("https://storage.nomercy.ac/{}/crclist", latestVersion)});
	if (res.error.code != cpr::ErrorCode::OK)
	{
		printf("Failed to get file list from server! Internal error: %u (%s)\n", res.error.code, res.error.message.c_str());
		return EXIT_FAILURE;
	}
	else if (res.status_code != 200)
	{
		printf("Failed to get file list from server! Server responded with status code %u\n", res.status_code);
		return EXIT_FAILURE;
	}
	const auto fileList = res.text;
	if (fileList.empty())
	{
		printf("Failed to get file list from server! Server responded with empty string");
		return EXIT_FAILURE;
	}

	// Parse file list
	std::vector<std::tuple<uint32_t, uint32_t, uint32_t, uint32_t, std::string>> files;
	std::istringstream iss(fileList);
	std::string line;
	while (std::getline(iss, line))
	{
		if (line.empty())
			continue;

		std::istringstream iss2(line);
		std::string crc32, size, mtime1, mtime2, path;
		if (!(iss2 >> crc32 >> size >> mtime1 >> mtime2 >> path))
		{
			printf("Failed to parse file list from server! Server responded with invalid file list");
			return EXIT_FAILURE;
		}

		files.emplace_back(std::make_tuple(std::stoul(crc32, nullptr, 16), std::stoul(size), std::stoul(mtime1), std::stoul(mtime2), path));
	}

	// Create directories
	for (const auto& file : files)
	{
		const auto path = std::get<4>(file);
		const auto pos = path.find_last_of('/');
		if (pos == std::string::npos)
			continue;

		const auto dir = path.substr(0, pos);
		CreateDirectoryA(dir.c_str(), nullptr);
	}

	// Download files
	for (const auto& file : files)
	{
		const auto path = std::get<4>(file);
		const auto url = fmt::format("https://storage.nomercy.ac/{}/{}.lz", latestVersion, path);
		printf("Downloading file %s from %s\n", path.c_str(), url.c_str());

		const auto res = cpr::Get(cpr::Url{ url });
		if (res.error.code != cpr::ErrorCode::OK)
		{
			printf("Failed to download file %s! Internal error: %u (%s)\n", path.c_str(), res.error.code, res.error.message.c_str());
			return EXIT_FAILURE;
		}
		else if (res.status_code != 200)
		{
			printf("Failed to download file %s! Server responded with status code %u\n", path.c_str(), res.status_code);
			return EXIT_FAILURE;
		}

		const auto data = res.text;
		if (data.empty())
		{
			printf("Failed to download file %s! Server responded with empty string\n", path.c_str());
			return EXIT_FAILURE;
		}

		const auto curr_crc32 = std::get<0>(file);
		const auto curr_size = std::get<1>(file);
		const auto curr_mtime1 = std::get<2>(file);
		const auto curr_mtime2 = std::get<3>(file);

		auto buffer = (unsigned char*)data.c_str();
		auto length = data.size();
		if (!DecompressLZO(buffer, length))
		{
			printf("Failed to decompress file %s!\n", path.c_str());
			return EXIT_FAILURE;
		}

		// Delete file if it exists
		DeleteFileA(path.c_str());

		// Write file
		FILE* f;
		if (fopen_s(&f, path.c_str(), "wb") != 0)
		{
			printf("Failed to write file %s! fopen_s failed\n", path.c_str());
			return EXIT_FAILURE;
		}
		fwrite(buffer, length, 1, f);
		fclose(f);

		// Validate file
		if (curr_crc32 != 0)
		{
			// Validate CRC32
			const auto crc = crc32(0, buffer, length);
			if (crc != curr_crc32)
			{
				printf("Failed to validate file %s! CRC32 mismatch\n", path.c_str());
				return EXIT_FAILURE;
			}
		}
		else if (curr_size != 0)
		{
			// Validate size
			if (length != curr_size)
			{
				printf("Failed to validate file %s! Size mismatch\n", path.c_str());
				return EXIT_FAILURE;
			}
		}
		else if (curr_mtime1 != 0 && curr_mtime2 != 0)
		{
			// Define constants
			const int64_t EPOCH_AS_FILETIME = 116444736000000000LL; // January 1, 1970 as MS file time
			const int64_t HUNDREDS_OF_NANOSECONDS = 10000000LL;

			// Get the last modification time of the file
			struct _stat fileStat;
			if (_stat(path.c_str(), &fileStat) != 0)
			{
				printf("Failed to validate file %s! _stat failed\n", path.c_str());
				return EXIT_FAILURE;
			}

			// Convert Unix timestamp to Windows FILETIME
			int64_t unixTime = static_cast<int64_t>(fileStat.st_mtime);
			int64_t fileTime = (unixTime * HUNDREDS_OF_NANOSECONDS) + EPOCH_AS_FILETIME;

			// Split mtime into mtime1 and mtime2
			unsigned int mtime1 = static_cast<unsigned int>(fileTime >> 32);
			unsigned int mtime2 = static_cast<unsigned int>(fileTime & 0xFFFFFFFF);

			// Validate mtime
			if (mtime1 != curr_mtime1 || mtime2 != curr_mtime2)
			{
				printf("Failed to validate file %s! Mtime mismatch\n", path.c_str());
				return EXIT_FAILURE;
			}
		}

		printf("Successfully downloaded file %s\n", path.c_str());

		// Sleep for 1 second to prevent server from getting overloaded
		Sleep(1000);
	}

	printf("NoMercy Lite Updater finished!\n");
	return EXIT_SUCCESS;
}
