#pragma once

namespace NoMercy
{
	struct SGameRegionData
	{
		HANDLE		process;
		PVOID		base;
		SIZE_T		size;
		uint64_t	checksum;
	};

	class CGameMemoryMonitor : public std::enable_shared_from_this <CGameMemoryMonitor>
	{
	public:
		CGameMemoryMonitor();
		virtual ~CGameMemoryMonitor();

		bool InitializeMonitorThread();
		void ReleaseThread();
		auto IsInitialized() const { return m_bIsInitialized; };

		void AddProcessToCheckList(HANDLE hProcess);

	protected:
		bool IsAddedRegion(HANDLE hProcess, LPVOID lpSectionBase, SIZE_T cbSize);
		bool ValidateRegions();
		void AddToCheckList(HANDLE hProcess, LPVOID lpSectionBase, SIZE_T cbSize);

	protected:
		DWORD					RegionMonitorRoutine(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		bool m_bIsInitialized;

		std::map <HANDLE, std::vector <HMODULE>>		 m_mapCheckList;
		std::vector <std::shared_ptr <SGameRegionData> > m_vRegions;
		std::vector <std::shared_ptr <SGameRegionData> > m_vMemoryPages;
	};
};
