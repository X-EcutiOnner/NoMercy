#pragma once

namespace NoMercy
{
	struct SHARE_MEMORY_INFO
	{
		int nProcessCount{ 0 };
	};

	class ShareMemory
	{
	public:
		ShareMemory(const std::wstring& stName);
		~ShareMemory();

		bool OpenShareMemory();
		void CloseShareMemory();

		LPBYTE CreateView(DWORD dwOffset, DWORD dwLength);
		void DestroyView(LPBYTE pViewPtr);

		bool WriteMem(BYTE* date, size_t len);
		bool ReadMem(BYTE* date, size_t len);

		uint32_t GetSize() const;
		inline LPVOID MemoryAddress() const { return m_buf; };

		bool Lock(uint32_t nTimeoutMS);
		bool Unlock();

	private:
		std::wstring m_stName;
		BYTE* m_buf;
		HANDLE m_handle;
		BYTE* m_file;
		HANDLE m_hLockMtx;
		SHARE_MEMORY_INFO m_shareMemInfo;
		DWORD m_dwAllocGranularity;
		std::map <LPBYTE, LPBYTE> m_mapViews;
	};
};
