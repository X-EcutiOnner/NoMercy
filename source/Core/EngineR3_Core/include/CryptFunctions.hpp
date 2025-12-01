#pragma once

#ifndef SHA1_HASH_LENGTH
#define SHA1_HASH_LENGTH 40
#endif

namespace NoMercyCore
{
	class CCryptFunctions : public CSingleton <CCryptFunctions>
	{
		public:
			CCryptFunctions();
			virtual ~CCryptFunctions();

			VOID AppendRandomData(PBYTE pBuffer, DWORD uBuffLen);
			LPBYTE GetRandomData(DWORD dwBuffLen);
			ULONG GetRandomInt(ULONG uMin, ULONG uMax);
			std::wstring GetRandomString(int iLength);

			std::wstring EncryptString(std::wstring szIn, const size_t size, BYTE byKey);
			std::wstring DecryptString(std::wstring szIn, const size_t size, BYTE byKey);

			DWORD GetStringHash(LPVOID lpBuffer, BOOL bUnicode, std::size_t uLen);

			bool IsBase64(const std::wstring& str);
			std::wstring EncodeBase64(const std::wstring& str);
			std::wstring EncodeBase64(const uint8_t* buf, size_t len);
			std::wstring DecodeBase64(const std::wstring& str);

			std::wstring EncryptAES(const std::wstring& data, const std::wstring& key);
			std::wstring DecryptAES(const std::wstring& data, const std::wstring& key);

			std::string GetMd5(LPVOID lpBuffer, DWORD dwSize);
			std::string GetMd5(const std::string& data);
			std::wstring GetMd5(const std::wstring& data);
			std::string GetSHA1(const std::string& data);
			std::wstring GetSHA1(const std::wstring& data);
			std::string GetSHA256(const std::string& data);
			std::wstring GetSHA256(const std::wstring& data);
			std::wstring GetSHA256(std::uint8_t* pData, std::size_t cbSize);

			std::wstring GetFileMd5(const std::wstring& filename);
			std::wstring GetFileSHA1(const std::wstring& filename);
			std::wstring GetFileSHA256(const std::wstring& filename);
			DWORD GetFileSize(const std::wstring& szName);

			std::wstring GetFileCRC32(const std::wstring& filename);
			std::wstring GetFileAuthentihash(const std::wstring& filename);
			std::wstring GetFileImphash(const std::wstring& filename);
			std::wstring GetFileImpfuzzy(const std::wstring& filename);
			std::wstring GetFileSSDEEP(const std::wstring& filename);
			std::wstring GetFileTLSH(const std::wstring& filename);

			bool CompressLZ4(const std::vector<uint8_t>& data, std::vector<uint8_t>& compressedData);
			bool DecompressLZ4(const std::vector<uint8_t>& compressedData, std::vector<uint8_t>& decompressedData, size_t expectedSize);
	};
};
