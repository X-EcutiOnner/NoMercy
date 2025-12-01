#pragma once

namespace NoMercy
{
	class CHardwareBreakpointWatcher : public std::enable_shared_from_this <CHardwareBreakpointWatcher>
	{
	public:
		CHardwareBreakpointWatcher();
		virtual ~CHardwareBreakpointWatcher();

		bool InitWatcher();
		void ReleaseWatcher();

		auto IsInitialized() const { return m_bIsInitialized; };
		void SetInitialized() { m_bIsInitialized = true; };

		auto GetInitializedTID() const { return m_dwInitializedThreadID; };
		bool IsTrapAddress(PVOID pvAddr) const;

		bool SetupHwbpTrap();
		bool ValidateHwbpTrap();

	private:
		bool m_bIsInitialized;
		DWORD m_dwInitializedThreadID;
	};
};
