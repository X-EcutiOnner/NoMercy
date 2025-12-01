#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "AntiInputInjection.hpp"
#include <hidusage.h>

#define KEY_IDX_BTN_L 0
#define KEY_IDX_BTN_M 1
#define KEY_IDX_BTN_R 2

namespace NoMercy
{
	LRESULT CALLBACK WindowMessageHandler(int32_t code, WPARAM wParam, LPARAM lParam)
	{
		static const auto sc_hGameWnd = NoMercyCore::CApplication::Instance().DataInstance()->GetClientMainWindow();
		const auto message = (MSG*)lParam;
//		APP_TRACE_LOG(LL_SYS, L"Window message: %p (%u) to %p, Game: %p", message, message ? message->message : 0, message ? message->hwnd : nullptr, sc_hGameWnd);
	
		if (!message || !message->hwnd)
			return g_winAPIs->CallNextHookEx(0, code, wParam, lParam);
		
		if (sc_hGameWnd == message->hwnd)
		{
			switch (message->message)
			{
				case WM_LBUTTONDOWN:
				{
					CApplication::Instance().InputInjectMonitorInstance()->OnMouseKeyPress(KEY_IDX_BTN_L, EMouseStatus::PRESSED);
					break;
				}
				case WM_LBUTTONUP:
				{
					CApplication::Instance().InputInjectMonitorInstance()->OnMouseKeyPress(KEY_IDX_BTN_L, EMouseStatus::RELEASED);
					break;
				}
				case WM_MBUTTONDOWN:
				{
					CApplication::Instance().InputInjectMonitorInstance()->OnMouseKeyPress(KEY_IDX_BTN_M, EMouseStatus::PRESSED);
					break;
				}
				case WM_MBUTTONUP:
				{
					CApplication::Instance().InputInjectMonitorInstance()->OnMouseKeyPress(KEY_IDX_BTN_M, EMouseStatus::RELEASED);
					break;
				}
				case WM_RBUTTONDOWN:
				{
					CApplication::Instance().InputInjectMonitorInstance()->OnMouseKeyPress(KEY_IDX_BTN_R, EMouseStatus::PRESSED);
					break;
				}
				case WM_RBUTTONUP:
				{
					CApplication::Instance().InputInjectMonitorInstance()->OnMouseKeyPress(KEY_IDX_BTN_R, EMouseStatus::RELEASED);
					break;
				}

				default:
					break;
			}

			return g_winAPIs->CallNextHookEx(0, code, wParam, lParam);
		}

		return 1;
	}

	LRESULT CALLBACK RawWindowHookMsgProc(HWND hWnd, uint32_t message, WPARAM wParam, LPARAM lParam)
	{
		static const auto sc_hGameWnd = NoMercyCore::CApplication::Instance().DataInstance()->GetClientMainWindow();

//		APP_TRACE_LOG(LL_SYS, L"Window message: %u to %p, Game: %p, Params: (%p/%p)", message, hWnd, sc_hGameWnd, wParam, lParam);

		if (sc_hGameWnd == hWnd)
		{
			switch (message)
			{
				// Mouse
				case WM_LBUTTONDOWN:
				{
					if (CApplication::Instance().InputInjectMonitorInstance()->GetMouseKeyStatus(KEY_IDX_BTN_L) == EMouseStatus::PRESSED)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MOUSE_INPUT_INJECTION, 1);
					}
					break;
				}
				case WM_MBUTTONDOWN:
				{
					if (CApplication::Instance().InputInjectMonitorInstance()->GetMouseKeyStatus(KEY_IDX_BTN_M) == EMouseStatus::PRESSED)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MOUSE_INPUT_INJECTION, 2);
					}
					break;
				}
				case WM_RBUTTONDOWN:
				{
					if (CApplication::Instance().InputInjectMonitorInstance()->GetMouseKeyStatus(KEY_IDX_BTN_R) == EMouseStatus::PRESSED)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MOUSE_INPUT_INJECTION, 3);
					}
					break;
				}
				
				//Keyboard
				case WM_KEYDOWN:
				{
					if (CApplication::Instance().InputInjectMonitorInstance()->GetKeyboardKeyStatus(wParam) == EKeyboardStatus::DOWN)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_KEYBOARD_INPUT_INJECTION, 1);
					}
					break;
				}
				case WM_KEYUP:
				{
					if (CApplication::Instance().InputInjectMonitorInstance()->GetKeyboardKeyStatus(wParam) == EKeyboardStatus::UP)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_KEYBOARD_INPUT_INJECTION, 2);
					}
					break;
				}

				case WM_INPUT:
				{
					if (GET_RAWINPUT_CODE_WPARAM(wParam) == RIM_INPUT)
					{
						APP_TRACE_LOG(LL_SYS, L"Raw input message to %p", hWnd);

						uint8_t* lpb = nullptr;
						uint32_t dwSize = 0;
						g_winAPIs->GetRawInputData((HRAWINPUT)lParam, RID_INPUT, nullptr, &dwSize, sizeof(RAWINPUTHEADER));
						if (!dwSize)
						{
							APP_TRACE_LOG(LL_ERR, L"GetRawInputData failed with error: %u", g_winAPIs->GetLastError());
							return 0;
						}
						const auto dwRequiredSize = dwSize;
						
						lpb = (uint8_t*)CMemHelper::Allocate(dwSize);
						if (!lpb)
						{
							APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for raw input data");
							return 0;
						}
						
						const auto dwRetSize = g_winAPIs->GetRawInputData((HRAWINPUT)lParam, RID_INPUT, lpb, &dwSize, sizeof(RAWINPUTHEADER));
						if (dwRetSize != dwRequiredSize)
						{
							APP_TRACE_LOG(LL_ERR, L"GetRawInputData(2) failed with error: %u, required size: %u, returned size: %u", g_winAPIs->GetLastError(), dwRequiredSize, dwRetSize);
							CMemHelper::Free(lpb);
							return 0;
						}

						auto pInput = (RAWINPUT*)(lpb);

						// ----

						/*
						if (pInput->header.dwType == RIM_TYPEKEYBOARD)
						{
							if ((pInput->data.keyboard.Flags & 0x1) == RI_KEY_MAKE)
							{
								CApplication::Instance().InputInjectMonitorInstance()->OnKeyboardKeyPress(pInput->data.keyboard.VKey, EKeyboardStatus::DOWN);
							}
							else if ((pInput->data.keyboard.Flags & 0x1) == RI_KEY_BREAK)
							{
								CApplication::Instance().InputInjectMonitorInstance()->OnKeyboardKeyPress(pInput->data.keyboard.VKey, EKeyboardStatus::UP);
							}
						}
						else if (pInput->header.dwType == RIM_TYPEMOUSE)
						{
							// TODO
						}
						*/

						// ----
						
						if (!pInput->header.hDevice)
						{
							APP_TRACE_LOG(LL_ERR, L"pInput->header.hDevice is null, type: %u", pInput->header.dwType);
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MOUSE_INPUT_INJECTION, 4);

							CMemHelper::Free(lpb);
							return 0;
						}
						else
						{
							if (pInput->data.keyboard.Message == WM_KEYDOWN) {
								CApplication::Instance().InputInjectMonitorInstance()->OnKeyboardKeyPress(pInput->data.keyboard.VKey, EKeyboardStatus::DOWN);
							}
							else if (pInput->data.keyboard.Message == WM_KEYUP) {
								CApplication::Instance().InputInjectMonitorInstance()->OnKeyboardKeyPress(pInput->data.keyboard.VKey, EKeyboardStatus::UP);
							}
							else {
								APP_TRACE_LOG(LL_ERR, L"Unknown message: %u", pInput->data.keyboard.Message);
							}
						}

						auto raw_mouse = pInput->data.mouse;
						if (IsBadReadPtr(&raw_mouse, sizeof(raw_mouse)))
						{
							APP_TRACE_LOG(LL_ERR, L"raw_mouse is not valid pointer");

							CMemHelper::Free(lpb);
							return 0;
						}

						auto detection_flag = false;
						if (raw_mouse.usFlags & MOUSE_MOVE_ABSOLUTE)
							detection_flag = true;

						if (detection_flag)
						{
							APP_TRACE_LOG(LL_ERR, L"Mouse emulation detected");
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_MOUSE_INPUT_INJECTION, 5);

							CMemHelper::Free(lpb);
							return 0;
						}

						wchar_t wszDeviceName[1024]{ L'\0' };
						uint32_t uiDeviceNameSize = 1024;
						if (g_winAPIs->GetRawInputDeviceInfoW(pInput->header.hDevice, RIDI_DEVICENAME, wszDeviceName, &uiDeviceNameSize) != (UINT)-1)
						{
							// TODO: filter
							// Input device name: '\\?\HID#VID_046D&PID_C52B&MI_00#8&32c1a571&0&0000#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}'
							APP_TRACE_LOG(LL_WARN, L"Input device name: %s", wszDeviceName);
						}
						else
						{
							APP_TRACE_LOG(LL_ERR, L"GetRawInputDeviceInfoA failed with error: %u", g_winAPIs->GetLastError());
						}

						if (pInput->header.dwType == RIM_TYPEMOUSE)
						{
							auto pMouseData = pInput->data.mouse;

							auto mouseFlags = pMouseData.usFlags;

							auto bInjected = (mouseFlags & LLMHF_INJECTED) == LLMHF_INJECTED;
							auto bInjected2 = (mouseFlags & LLMHF_LOWER_IL_INJECTED) == LLMHF_LOWER_IL_INJECTED;
							auto bInjected3 = (mouseFlags & MOUSE_MOVE_ABSOLUTE);

							APP_TRACE_LOG(LL_CRI, L"Injected status test flags: %p ret: %d/%d/%d", mouseFlags, bInjected, bInjected2, bInjected3);
						}

						CMemHelper::Free(lpb);
					}
					break;
				}

				default:
					break;
			}

			return CApplication::Instance().InputInjectMonitorInstance()->GetWindowMsgProc()(hWnd, message, wParam, lParam);
		}

		return 0;
	}
		

	CInputInjectMonitor::CInputInjectMonitor() :
		m_hWnd(nullptr), m_wndpOldProc(nullptr), m_hkMessageHook(nullptr), m_bRegistered(false)
	{
		m_mapMouseKeyStatusList[0] = EMouseStatus::NONE;
		m_mapMouseKeyStatusList[1] = EMouseStatus::NONE;
		m_mapMouseKeyStatusList[2] = EMouseStatus::NONE;
	}
	CInputInjectMonitor::~CInputInjectMonitor()
	{
	}

	
	void CInputInjectMonitor::OnMouseKeyPress(int32_t iKeyIdx, EMouseStatus bStatus)
	{
		APP_TRACE_LOG(LL_SYS, L"OnMouseKeyPress: %d, %d", iKeyIdx, bStatus);
		m_mapMouseKeyStatusList[iKeyIdx] = bStatus;
	}
	EMouseStatus CInputInjectMonitor::GetMouseKeyStatus(int32_t iKeyIdx)
	{
		if (m_mapMouseKeyStatusList.find(iKeyIdx) == m_mapMouseKeyStatusList.end())
			return EMouseStatus::NONE;
		return m_mapMouseKeyStatusList[iKeyIdx];
	}
	
	void CInputInjectMonitor::OnKeyboardKeyPress(int32_t iKeyIdx, EKeyboardStatus bStatus)
	{
		APP_TRACE_LOG(LL_SYS, L"OnKeyboardKeyPress: %d, %d", iKeyIdx, bStatus);
		m_mapKeyboardKeyStatusList[iKeyIdx] = bStatus;
	}
	EKeyboardStatus CInputInjectMonitor::GetKeyboardKeyStatus(int32_t iKeyIdx)
	{
		if (m_mapKeyboardKeyStatusList.find(iKeyIdx) == m_mapKeyboardKeyStatusList.end())
			return EKeyboardStatus::NONE;
		return m_mapKeyboardKeyStatusList[iKeyIdx];
	}

	
	bool CInputInjectMonitor::InitializeWindowMessageHook()
	{
		const auto dwTID = g_winAPIs->GetWindowThreadProcessId(m_hWnd, 0);
		if (dwTID == 0)
		{
			APP_TRACE_LOG(LL_ERR, L"GetWindowThreadProcessId failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		m_hkMessageHook = g_winAPIs->SetWindowsHookExW(WH_GETMESSAGE, &WindowMessageHandler, 0, dwTID);
		if (m_hkMessageHook == nullptr)
		{
			APP_TRACE_LOG(LL_ERR, L"SetWindowsHookExA failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}
		
		APP_TRACE_LOG(LL_SYS, L"Window message hook initialized");
		return true;
	}
	void CInputInjectMonitor::DestroyWindowMessageHook()
	{
		if (m_hkMessageHook)
		{
			g_winAPIs->UnhookWindowsHookEx(m_hkMessageHook);
			m_hkMessageHook = nullptr;
		}
	}

	
	bool CInputInjectMonitor::InitializeRawWindowHook()
	{
		const auto bIsUnicodeWnd = g_winAPIs->IsWindowUnicode(m_hWnd);
		APP_TRACE_LOG(LL_SYS, L"Installing raw window hook to: %p, Unicode: %d", m_hWnd, bIsUnicodeWnd ? 1 : 0);

		WNDPROC wndpOldProc = nullptr;
		if (bIsUnicodeWnd)
			wndpOldProc = (WNDPROC)g_winAPIs->SetWindowLongW(m_hWnd, GWLP_WNDPROC, (LONG_PTR)&RawWindowHookMsgProc);
		else
			wndpOldProc = (WNDPROC)g_winAPIs->SetWindowLongA(m_hWnd, GWLP_WNDPROC, (LONG_PTR)&RawWindowHookMsgProc);

		if (!wndpOldProc)
		{
			APP_TRACE_LOG(LL_ERR, L"SetWindowLong failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}
		m_wndpOldProc = wndpOldProc;

		RAWINPUTDEVICE rid[2]{};
		
		rid[0].usUsagePage = HID_USAGE_PAGE_GENERIC;
		rid[0].usUsage = HID_USAGE_GENERIC_KEYBOARD;
		rid[0].dwFlags = RIDEV_INPUTSINK;
		rid[0].hwndTarget = m_hWnd;

		rid[1].usUsagePage = HID_USAGE_PAGE_GENERIC;
		rid[1].usUsage = HID_USAGE_GENERIC_KEYBOARD;
		rid[1].dwFlags = RIDEV_INPUTSINK;
		rid[1].hwndTarget = m_hWnd;

		if (!g_winAPIs->RegisterRawInputDevices(rid, ARRAYSIZE(rid), sizeof(rid[0])))
		{
			APP_TRACE_LOG(LL_ERR, L"RegisterRawInputDevices failed with error: %u", g_winAPIs->GetLastError());

			if (g_winAPIs->IsWindowUnicode(m_hWnd))
				g_winAPIs->SetWindowLongW(m_hWnd, GWLP_WNDPROC, (LONG_PTR)wndpOldProc);
			else
				g_winAPIs->SetWindowLongA(m_hWnd, GWLP_WNDPROC, (LONG_PTR)wndpOldProc);

			return false;
		}
		
		APP_TRACE_LOG(LL_SYS, L"Raw input hook registered");
		m_bRegistered = true;
		return true;
	}

	void CInputInjectMonitor::DestroyRawWindowHook()
	{
		if (m_bRegistered)
		{
			RAWINPUTDEVICE rid[2]{};

			rid[0].usUsagePage = HID_USAGE_PAGE_GENERIC;
			rid[0].usUsage = HID_USAGE_GENERIC_MOUSE;
			rid[0].dwFlags = RIDEV_REMOVE;
			rid[0].hwndTarget = m_hWnd;

			rid[1].usUsagePage = HID_USAGE_PAGE_GENERIC;
			rid[1].usUsage = HID_USAGE_GENERIC_KEYBOARD;
			rid[1].dwFlags = RIDEV_REMOVE;
			rid[1].hwndTarget = m_hWnd;

			g_winAPIs->RegisterRawInputDevices(rid, ARRAYSIZE(rid), sizeof(rid[0]));
			m_bRegistered = false;
		}
		
		if (m_wndpOldProc)
		{
			if (g_winAPIs->IsWindowUnicode(m_hWnd))
				g_winAPIs->SetWindowLongW(m_hWnd, GWLP_WNDPROC, (LONG_PTR)m_wndpOldProc);
			else
				g_winAPIs->SetWindowLongA(m_hWnd, GWLP_WNDPROC, (LONG_PTR)m_wndpOldProc);
			
			m_wndpOldProc = nullptr;
		}
	}
};
