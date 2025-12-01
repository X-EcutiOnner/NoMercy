#pragma once

namespace NoMercy
{
	class CWindowWatcher : public std::enable_shared_from_this <CWindowWatcher>
	{
	public:
		CWindowWatcher();
		virtual ~CWindowWatcher();

		bool Initialize();
		void Release();

		auto IsInitialized() const { return m_bInitialized; };

	protected:
		DWORD					ThreadRoutine(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		bool m_bInitialized;
		HWINEVENTHOOK m_hWndHandlerHook;
	};
}
