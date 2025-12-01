#include "../../include/PCH.hpp"
#include "../../include/CryptFunctions.hpp"
#include "../../../../Common/StdExtended.hpp"
#include "../../../../Common/BasicCrypt.hpp"
#include <cryptopp/sha.h>
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <tlsh/tlsh.h>

namespace NoMercyCore
{
	CCryptFunctions::CCryptFunctions()
	{
	}
	CCryptFunctions::~CCryptFunctions()
	{
	}

	DWORD CCryptFunctions::GetStringHash(LPVOID lpBuffer, BOOL bUnicode, std::size_t uLen)
	{
		DWORD dwHash = 0;
		LPSTR strBuffer = (LPSTR)lpBuffer;

		while (uLen--)
		{
			dwHash = (dwHash >> 13) | (dwHash << 19);
			dwHash += (DWORD)*strBuffer++;

			if (bUnicode)
				strBuffer++;
		}
		return dwHash;
	}

	VOID CCryptFunctions::AppendRandomData(PBYTE pBuffer, DWORD uBuffLen)
	{
		static BOOL s_bOnce = TRUE;
		if (s_bOnce)
		{
			srand(g_winAPIs->GetTickCount());
			s_bOnce = FALSE;
		}

		for (DWORD i = 0; i < uBuffLen; i++)
			pBuffer[i] = (BYTE)rand();
	}
	LPBYTE CCryptFunctions::GetRandomData(DWORD dwBuffLen)
	{
		LPBYTE lpBuffer = (LPBYTE)malloc(dwBuffLen);
		AppendRandomData(lpBuffer, dwBuffLen);
		return lpBuffer;
	}
	ULONG CCryptFunctions::GetRandomInt(ULONG uMin, ULONG uMax)
	{
		if (uMax < (ULONG)0xFFFFFFFF)
			uMax++;

		return (rand() % (uMax - uMin)) + uMin;
	}
	std::wstring CCryptFunctions::GetRandomString(int iLength)
	{
		static wchar_t __alphabet[] = { L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h', L'i', L'j', L'k', L'l', L'm', L'n', L'o', L'p', L'q', L'r', L's', L't', L'u', L'v', L'w', L'x', L'y', L'z', L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'I', L'J', L'K', L'L', L'M', L'N', L'O', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9', L'0', 0x0 }; // abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
		static std::wstring charset = __alphabet;
		std::wstring result;
		result.resize(iLength);

		for (int i = 0; i < iLength; i++)
			result[i] = charset[rand() % charset.length()];

		return result;
	}

	std::wstring CCryptFunctions::EncryptString(std::wstring szIn, const size_t size, BYTE byKey)
	{
		BYTE pData[1024]{ 0 };
		wcsncpy((wchar_t*)pData, szIn.c_str(), 1024);

		BasicCrypt::EncryptBuffer(pData, size, byKey);

		std::wstring szOut = std::wstring(reinterpret_cast<const wchar_t*>(pData));
		return szOut;
	}
	std::wstring CCryptFunctions::DecryptString(std::wstring szIn, const size_t size, BYTE byKey)
	{
		BYTE pData[1024]{ 0 };
		wcsncpy((wchar_t*)pData, szIn.c_str(), 1024);

		BasicCrypt::DecryptBuffer(pData, size, byKey);

		std::wstring szOut = std::wstring(reinterpret_cast<const wchar_t*>(pData));
		return szOut;
	}

	DWORD CCryptFunctions::GetFileSize(const std::wstring& szName)
	{
		auto dwSize = 0;

		auto hFile = g_winAPIs->CreateFileW(szName.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile && hFile != INVALID_HANDLE_VALUE)
			dwSize = g_winAPIs->GetFileSize(hFile, nullptr);

		if (dwSize == INVALID_FILE_SIZE)
			dwSize = 0;

		CWinAPIManager::Instance().SafeCloseHandle(hFile);
		return dwSize;
	}
	
	std::wstring CCryptFunctions::GetFileMd5(const std::wstring& filename)
	{	
		auto filedata = CApplication::Instance().DirFunctionsInstance()->ReadFileContent(filename);
		if (filedata.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"File: '%s' read failed! Error: %d", filename.c_str(), errno);
			return L"";
		}
		return GetMd5(filedata);
	}
	std::string CCryptFunctions::GetMd5(LPVOID lpBuffer, DWORD dwSize)
	{
		std::string stBuffer;
		try
		{
			CryptoPP::Weak1::MD5 md5;
			auto hashfilter = new CryptoPP::HashFilter(md5);
			hashfilter->Attach(new CryptoPP::HexEncoder(new CryptoPP::StringSink(stBuffer), false));

			CryptoPP::StringSource((const byte*)lpBuffer, dwSize, true, hashfilter);
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}
		return stBuffer;
	}
	std::string CCryptFunctions::GetMd5(const std::string& data)
	{
		std::string stBuffer;
		try
		{
			CryptoPP::Weak1::MD5 md5;
			auto hashfilter = new CryptoPP::HashFilter(md5);
			hashfilter->Attach(new CryptoPP::HexEncoder(new CryptoPP::StringSink(stBuffer), false));

			CryptoPP::StringSource(data, true, hashfilter);
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}
		return stBuffer;
	};
	std::wstring CCryptFunctions::GetMd5(const std::wstring& data)
	{
		auto data_a = stdext::to_ansi(data);
		return stdext::to_wide(GetMd5(data_a));
	};

	std::string CCryptFunctions::GetSHA256(const std::string& data)
	{
		std::string stBuffer;
		
		try
		{
			CryptoPP::SHA256 sha;
			/*
			uint8_t csum[CryptoPP::SHA256::DIGESTSIZE];

			sha.CalculateDigest(csum, (const byte*)c_lpData, cbSize);
			CryptoPP::StringSource ss(csum, sizeof(csum), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(stBuffer)));
			*/
			CryptoPP::StringSource(
				data,
				true,
				new CryptoPP::HashFilter(
					sha,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(
							stBuffer
						)
					)
				)
			);
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}
		return stBuffer;
	}
	std::wstring CCryptFunctions::GetSHA256(const std::wstring& data)
	{
		auto data_a = stdext::to_ansi(data);
		return stdext::to_wide(GetSHA256(data_a));
	};
	std::wstring CCryptFunctions::GetSHA256(std::uint8_t* pData, std::size_t cbSize)
	{
		std::string stBuffer;

		try
		{
			CryptoPP::SHA256 sha;
			/*
			uint8_t csum[CryptoPP::SHA256::DIGESTSIZE];

			sha.CalculateDigest(csum, (const byte*)pData, cbSize);
			CryptoPP::StringSource ss(csum, sizeof(csum), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(stBuffer)));
			*/
//			/*
			CryptoPP::StringSource(
				pData,
				cbSize,
				true,
				new CryptoPP::HashFilter(
					sha,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(
							stBuffer
						)
					)
				)
			);
//			*/
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}
		return stdext::to_lower_wide(stBuffer);
	}
	std::wstring CCryptFunctions::GetFileSHA256(const std::wstring& filename)
	{
		auto filedata = CApplication::Instance().DirFunctionsInstance()->ReadFileContent(filename);
		if (filedata.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"File: '%s' read failed! Error: %d", filename.c_str(), errno);
			return L"";
		}
		return GetSHA256(filedata);
	}

	std::string CCryptFunctions::GetSHA1(const std::string& data)
	{
		std::string stBuffer;
		try
		{
			CryptoPP::SHA1 sha;

			CryptoPP::StringSource(
				data,
				true,
				new CryptoPP::HashFilter(
					sha,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(
							stBuffer
						)
					)
				)
			);
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}
		return stBuffer;
	}
	std::wstring CCryptFunctions::GetSHA1(const std::wstring& data)
	{
		auto data_a = stdext::to_ansi(data);
		return stdext::to_wide(GetSHA1(data_a));
	};
	std::wstring CCryptFunctions::GetFileSHA1(const std::wstring& filename)
	{
		std::wstring wstBuffer;

		auto fnGetFileSHA1Ex = [&]() {
			std::string stBuffer;
			try
			{
				CryptoPP::SHA1 hash;

				const auto filename_a = stdext::to_ansi(filename);
				CryptoPP::FileSource(filename_a.c_str(), true,
					new CryptoPP::HashFilter(hash,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink(stBuffer)
						)
					)
				);
			}
			catch (const CryptoPP::Exception& exception)
			{
				if (exception.GetErrorType() == exception.IO_ERROR)
				{
					auto filedata = CApplication::Instance().DirFunctionsInstance()->ReadFileContent(filename);
					if (filedata.empty())
					{
						APP_TRACE_LOG(LL_ERR, L"File: '%s' read failed! Error: %d", filename.c_str(), errno);
						return;
					}
					wstBuffer = GetSHA1(filedata);
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
				}
			}

			if (!stBuffer.empty())
				wstBuffer = stdext::to_wide(stBuffer);
		};

		auto fnGetFileSHA1Safe = [&fnGetFileSHA1Ex]() {
			__try
			{
				fnGetFileSHA1Ex();
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};

		fnGetFileSHA1Safe();
		return wstBuffer;
	}

	bool CCryptFunctions::IsBase64(const std::wstring& str)
	{
#pragma warning(push) 
#pragma warning(disable: 4129)
		return std::regex_search(str, std::wregex(xorstr_(L"[^A-Z0-9+\/=]")));
#pragma warning(push) 
	}
	std::wstring CCryptFunctions::EncodeBase64(const std::wstring& str)
	{
		auto data_a = stdext::to_ansi(str);
		
		std::string encoded;
		try
		{
			CryptoPP::StringSource ss(data_a, true,
				new CryptoPP::Base64Encoder(
					new CryptoPP::StringSink(encoded)
				) // Base64Encoder
			); // StringSource
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}

		auto wstEncoded = stdext::to_wide(encoded);
		if (!wstEncoded.empty() && wstEncoded.back() == L'\n')
			wstEncoded.pop_back();

		return wstEncoded;
	};
	std::wstring CCryptFunctions::EncodeBase64(const uint8_t* buffer, size_t bufferSize)
	{
		std::string encodedString;

		try
		{
			CryptoPP::StringSink stringSink(encodedString);

			CryptoPP::Base64Encoder encoder(&stringSink);
			CryptoPP::ArraySource(buffer, bufferSize, true,
				new CryptoPP::Redirector(encoder)
			);

			encoder.MessageEnd();
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}

		return stdext::to_wide(encodedString);
	};
	std::wstring CCryptFunctions::DecodeBase64(const std::wstring& str)
	{
		std::string decoded;

		auto data_a = stdext::to_ansi(str);
		
		try
		{
			CryptoPP::StringSource ss(data_a, true,
				new CryptoPP::Base64Decoder(
					new CryptoPP::StringSink(decoded)
				) // Base64Decoder
			); // StringSource
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}

		return stdext::to_wide(decoded);
	};

	std::wstring CCryptFunctions::EncryptAES(const std::wstring& data, const std::wstring& key)
	{
		// TODO: USE BUFFER INSTEAD OF STRING

		std::string outBuffer;
		auto data_a = stdext::to_ansi(data);
		auto key_a = stdext::to_ansi(key);

		try
		{
			CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc((const byte*)key_a.data(), key_a.size(), (const byte*)key_a.data() + key_a.size());
			enc.ProcessData((byte*)outBuffer.data(), (const byte*)data_a.data(), data_a.size());
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}

		return stdext::to_wide(outBuffer);
	};
	std::wstring CCryptFunctions::DecryptAES(const std::wstring& data, const std::wstring& key)
	{
		std::string outBuffer;
		auto data_a = stdext::to_ansi(data);
		auto key_a = stdext::to_ansi(key);

		try
		{
			CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec((const byte*)key_a.data(), key_a.size(), (const byte*)key_a.data() + key_a.size());
			dec.ProcessData((byte*)outBuffer.data(), (const byte*)data_a.data(), data_a.size());
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Cryptopp exception: %u (%hs)", exception.GetErrorType(), exception.GetWhat().c_str());
		}

		return stdext::to_wide(outBuffer);
	};

	// TODO
	std::wstring CCryptFunctions::GetFileCRC32(const std::wstring& filename)
	{
		return {};
	}
	std::wstring CCryptFunctions::GetFileAuthentihash(const std::wstring& filename)
	{
		return {};
	}
	std::wstring CCryptFunctions::GetFileImphash(const std::wstring& filename)
	{
		return {};
	}
	std::wstring CCryptFunctions::GetFileImpfuzzy(const std::wstring& filename)
	{
		return {};
	}
	std::wstring CCryptFunctions::GetFileSSDEEP(const std::wstring& filename)
	{
		return {};
	}
	std::wstring CCryptFunctions::GetFileTLSH(const std::wstring& filename)
	{
		const auto wstBuffer = CApplication::Instance().DirFunctionsInstance()->ReadFileContent(filename);
		if (wstBuffer.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"File: '%s' read failed! Error: %d", filename.c_str(), errno);
			return L"";
		}
		
		auto tlshHash = stdext::make_unique_nothrow<Tlsh>();
		if (!tlshHash)
		{
			APP_TRACE_LOG(LL_ERR, L"Memory allocation for tlsh failed with error: %d", errno);
			return L"";
		}

		tlshHash->update(reinterpret_cast<const unsigned char*>(wstBuffer.data()), wstBuffer.size());
		tlshHash->final();

		if (!tlshHash->isValid())
		{
			APP_TRACE_LOG(LL_ERR, L"Tlsh hash is not valid");
			return L"";
		}

		const std::string stHashResult = tlshHash->getHash(TRUE);
		if (stHashResult.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Tlsh getHash failed!");
		}

		return stdext::to_wide(stHashResult);
	}

	bool CCryptFunctions::CompressLZ4(const std::vector<uint8_t>& data, std::vector<uint8_t>& compressedData)
	{
		const auto bound = LZ4_compressBound(data.size());
		compressedData.resize(bound);

		const auto compressedSize = LZ4_compress_HC(
			reinterpret_cast<const char*>(data.data()), reinterpret_cast<char*>(compressedData.data()),
			data.size(), bound, LZ4HC_CLEVEL_MAX
		);

		if (compressedSize >= bound || compressedSize == 0)
		{
			APP_TRACE_LOG(LL_ERR, L"Compression fail! Raw: %u Compressed: %u Capacity: %u", data.size(), compressedSize, bound);
			return false;
		}

		compressedData.resize(compressedSize);
		return true;
	}
	bool CCryptFunctions::DecompressLZ4(const std::vector<uint8_t>& compressedData, std::vector<uint8_t>& decompressedData, size_t expectedSize)
	{
		decompressedData.resize(expectedSize);

		const auto decompressedSize = LZ4_decompress_safe(
			reinterpret_cast<const char*>(compressedData.data()), reinterpret_cast<char*>(decompressedData.data()),
			compressedData.size(), expectedSize
		);

		if (decompressedSize != expectedSize)
		{
			APP_TRACE_LOG(LL_ERR, L"Decompression fail! Compressed: %u Decompressed: %u Expected: %u", compressedData.size(), decompressedSize, expectedSize);
			return false;
		}

		return true;
	}
};
