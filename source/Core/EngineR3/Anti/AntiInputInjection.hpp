#pragma once

namespace NoMercy
{
	enum class EMouseStatus : uint8_t
	{
		NONE,
		PRESSED,
		RELEASED
	};
	enum class EKeyboardStatus : uint8_t
	{
		NONE,
		UP,
		DOWN
	};

	class CInputInjectMonitor : std::enable_shared_from_this <CInputInjectMonitor>
	{
	public:
		CInputInjectMonitor();
		virtual ~CInputInjectMonitor();
		
		void OnMouseKeyPress(int32_t iKeyIdx, EMouseStatus bStatus);
		EMouseStatus GetMouseKeyStatus(int32_t iKeyIdx);
		
		void OnKeyboardKeyPress(int32_t iKeyIdx, EKeyboardStatus bStatus);
		EKeyboardStatus GetKeyboardKeyStatus(int32_t iKeyIdx);

		WNDPROC GetWindowMsgProc() { return m_wndpOldProc; };
		void SetWindowHandle(HWND hWnd) { m_hWnd = hWnd; };
	
		bool InitializeRawWindowHook();
		void DestroyRawWindowHook();

		bool InitializeWindowMessageHook();
		void DestroyWindowMessageHook();

	private:
		HWND m_hWnd;
		WNDPROC m_wndpOldProc;
		HHOOK m_hkMessageHook;
		bool m_bRegistered;
		std::map <int32_t, EMouseStatus> m_mapMouseKeyStatusList;
		std::map <int32_t, EKeyboardStatus> m_mapKeyboardKeyStatusList;
	};
};
