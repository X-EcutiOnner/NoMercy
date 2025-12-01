#pragma once

namespace NoMercy
{
	enum EManualMapScanTypes : uint8_t
	{
		MMAP_DLL_HEADERS = 0x1,
		MMAP_DLL_THREAD = 0x2,
		MMAP_CRT_STUB = 0x3,
		MMAP_IMPORT_TABLE = 0x4
	};

	struct SManualMapScanCtx
	{
		LPVOID base_address{ nullptr };
		uint8_t detectionType{ 0 };
		DWORD AllocatedProtect{ 0 };
		PVOID AllocatedBase{ nullptr };
		DWORD AllocatedSize{ 0 };
	};
	
	class CManualMapScanner : public std::enable_shared_from_this <CManualMapScanner>
	{		
		struct SScanData
		{
			std::function<void(SManualMapScanCtx*)> notifyCallback;
			uint8_t scanType;
		};

	public:
		CManualMapScanner();
		virtual ~CManualMapScanner();

		bool InitializeThread();
		void ReleaseThread();

	protected:
		void WatchMemoryAllocations(SScanData* scanData, const void* ptr, size_t length);
		void ScanForDllThread(SScanData* scanner_data);
		void ScanForCheats(SScanData* scanner_data);
		
		DWORD					ManualMapScannerThreadProcessor(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		std::mutex m_mtxLock;
	};
}
