#pragma once

namespace NoMercyCore
{
	enum class ESLLLoadType : uint8_t
	{
		NONE,
		LOAD_FROM_FILE,
		LOAD_FROM_MEMORY
	};

	struct SMappedFileCtx
	{
		bool bIsLoadedFromFile{ false };
		bool bIsReleased{ false };
		std::wstring wstOriginalName{ L"" };
		std::wstring wstName{ L"" };
		uint8_t* lpMappedData{ nullptr };
		uint32_t nMappedSize{ 0 };
		uint8_t* lpRawData{ nullptr };
		uint64_t nRawSize{ 0 };
	};

	class CSecureLoadLibrary : std::enable_shared_from_this <CSecureLoadLibrary>
	{
	public:
		CSecureLoadLibrary();
		virtual ~CSecureLoadLibrary();

		bool Load(const std::wstring& stName, ESLLLoadType eLoadType);
		bool Release(const std::wstring& stName);

		void GetLoadedModuleList(std::vector <std::wstring>& vecModules);
		HMODULE Find(const std::wstring& stName);
		SMappedFileCtx* Get(const std::wstring& stName);
		
	protected:
		bool LoadFromFile(const std::wstring& stName, const std::wstring& stModuleName);
		bool LoadFromMemory(const std::wstring& stName, const std::wstring& wstModuleName);
		bool Map(const std::wstring& stOriginalName, const std::wstring& stName, uint64_t offset = 0, uint32_t size = 0);

	private:
		std::vector <SMappedFileCtx> m_vMappedFiles;
	};
};
