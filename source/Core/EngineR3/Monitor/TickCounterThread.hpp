#pragma once

namespace NoMercy
{
	class CTickCounter : public std::enable_shared_from_this <CTickCounter>
	{
	public:
		CTickCounter();
		virtual ~CTickCounter();

		bool InitializeThread();
		void ReleaseThread();
		auto IsInitialized() const { return m_bIsInitialized; };

	protected:
		DWORD					TickCounterRoutine(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		bool m_bIsInitialized;
	};
};
