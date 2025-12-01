#pragma once

namespace NoMercy
{
	enum EMemAllocDetectionType
	{
		ByExternalAllocation = 1
	};

	struct SMemGuardCtx
	{
		MEMORY_BASIC_INFORMATION mbi;
		EMemAllocDetectionType detectBy;
	};

	typedef bool(__stdcall* MemoryGuardCallback)(SMemGuardCtx* guard_info);

	struct SMemWatcherCtx
	{
		std::map<PVOID, DWORD> RegionInfo;
		MemoryGuardCallback callback;
		bool WasFilled;
	};

	class CMemAllocWatcher : public std::enable_shared_from_this <CMemAllocWatcher>
	{
	public:
		CMemAllocWatcher();
		virtual ~CMemAllocWatcher();

		bool InitializeThread();
		void ReleaseThread();

		void AppendMemoryRegion(PVOID BaseAddress, ULONG RegionSize);
		void SetCallback(MemoryGuardCallback callback);

		bool IsWhitelistedObject(const std::wstring& wstFilename, bool bShouldBeSigned = true);
		std::vector <std::wstring> GetWhitelist();

	protected:			
		DWORD					MemAllocWatcherThreadProcessor(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		std::mutex m_mtxLock;
		SMemWatcherCtx m_pWatcherCtx;
		std::vector <std::wstring> m_vecWhitelist;
	};
};
