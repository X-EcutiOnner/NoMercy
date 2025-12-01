#pragma once

namespace NoMercy
{
	struct SModuleSectionData
	{
		HANDLE		process;
		PVOID		base;
		SIZE_T		size;
		uint64_t	checksum;
	};

	class CModuleSectionMonitor : public std::enable_shared_from_this <CModuleSectionMonitor>
	{
	public:
		CModuleSectionMonitor();
		virtual ~CModuleSectionMonitor();

		bool InitializeMonitorThread();
		void ReleaseThread();
		auto IsInitialized() const { return m_bIsInitialized; };

		void AddProcessToCheckList(HANDLE hProcess);

	protected:
		bool IsSkippedRegion(HANDLE hProcess, LPVOID lpSectionBase);
		bool IsAddedRegion(HANDLE hProcess, LPVOID lpSectionBase, SIZE_T cbSize);
		bool ValidateRegions();
		void AddToCheckList(HANDLE hProcess, LPVOID lpSectionBase, SIZE_T cbSize);
		bool ScanModuleFileSections(HANDLE hProcess, LPVOID lpModuleBase, const std::wstring& wstBaseName);

	protected:
		DWORD					ModuleSectionMonitorRoutine(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		bool m_bIsInitialized;

		std::map <HANDLE, std::vector <HMODULE>>			m_mapCheckList;
		std::map <HANDLE, PVOID>							m_mapSkippedList;
		std::vector <std::shared_ptr <SModuleSectionData> > m_vRegions;
		std::vector <std::shared_ptr <SModuleSectionData> > m_vMemoryPages;
	};
};
