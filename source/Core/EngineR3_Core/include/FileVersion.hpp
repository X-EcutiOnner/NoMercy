#pragma once

namespace NoMercyCore
{
	struct LANGANDCODEPAGE
	{
		WORD wLanguage{ 0 };
		WORD wCodePage{ 0 };
	};

	class CFileVersion
	{
	public:
		CFileVersion();
		~CFileVersion();

		bool QueryFile(std::wstring path);

		bool GetFixedInfo(VS_FIXEDFILEINFO& vsffi);
		std::wstring GetFixedFileVersion();
		std::wstring GetFixedProductVersion();
		std::wstring GetProductLanguage();
		std::wstring GetTimestamp();

		auto GetFilePath() const			{ return m_wstTargetFile; };
		auto GetComments() const			{ return m_wstComments; };
		auto GetCompanyName() const			{ return m_wstCompanyName; };
		auto GetFileDescription() const		{ return m_wstFileDescription; };
		auto GetFileVersion() const			{ return m_wstFileVersion; };
		auto GetInternalName() const		{ return m_wstInternalName; };
		auto GetLegalCopyright() const		{ return m_wstLegalCopyright; };
		auto GetLegalTrademarks() const		{ return m_wstLegalTrademarks; };
		auto GetOriginalFilename() const	{ return m_wstOriginalFilename; };
		auto GetProductName() const			{ return m_wstProductName; };
		auto GetProductVersion() const		{ return m_wstProductVersion; };
		auto GetPrivateBuild() const		{ return m_wstPrivateBuild; };
		auto GetSpecialBuild() const		{ return m_wstSpecialBuild; };

	protected:
		bool __GetAndSaveValue(const std::wstring& keyword, std::wstring& ref_value, DWORD lang_char_set = 0) const;

	private:
		std::wstring m_wstTargetFile;
		uint32_t m_nLocaleTableSize;
		char* m_pVerInfo;
		int32_t m_dwLangCharset;

		std::wstring m_wstComments;
		std::wstring m_wstCompanyName;
		std::wstring m_wstFileDescription;
		std::wstring m_wstFileVersion;
		std::wstring m_wstInternalName;
		std::wstring m_wstLegalCopyright;
		std::wstring m_wstLegalTrademarks;
		std::wstring m_wstOriginalFilename;
		std::wstring m_wstProductName;
		std::wstring m_wstProductVersion;
		std::wstring m_wstPrivateBuild;
		std::wstring m_wstSpecialBuild;
	};
};
