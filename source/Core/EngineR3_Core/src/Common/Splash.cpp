#include "../../include/PCH.hpp"
#include "../../include/DI_hwid.hpp"
#include "../../include/Splash.hpp"

namespace NoMercyCore
{
	static LRESULT CALLBACK ExtWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		static CSplash* spl = nullptr;

		if (uMsg == WM_CREATE)
			spl = (CSplash*)((LPCREATESTRUCT)lParam)->lpCreateParams;

		if (spl)
			return spl->WindowProc(hwnd, uMsg, wParam, lParam);
		else
			return g_winAPIs->DefWindowProcW(hwnd, uMsg, wParam, lParam);
	}
	LRESULT CALLBACK CSplash::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
			HANDLE_MSG(hwnd, WM_PAINT, OnPaint);
		}

		return g_winAPIs->DefWindowProcW(hwnd, uMsg, wParam, lParam);
	}

	CSplash::CSplash()
	{
		Init();
	}
	CSplash::CSplash(HBITMAP hBitmap, COLORREF colTrans)
	{
		Init();

		SetBitmap(hBitmap);
		SetTransparentColor(colTrans);
	}
	CSplash::~CSplash()
	{
		FreeResources();
	}

	void CSplash::OnPaint(HWND hwnd)
	{
		if (!m_hBitmap)
			return;

		PAINTSTRUCT ps;
		HDC hDC = g_winAPIs->BeginPaint(hwnd, &ps);
		if (!hDC)
			return;

		RECT rect;
		if (!g_winAPIs->GetClientRect(m_hwnd, &rect))
		{
			g_winAPIs->EndPaint(hwnd, &ps);
			return;
		}

		HDC hMemDC = g_winAPIs->CreateCompatibleDC(hDC);
		if (!hMemDC)
		{
			g_winAPIs->EndPaint(hwnd, &ps);
			return;
		}

		HBITMAP hOldBmp = (HBITMAP)g_winAPIs->SelectObject(hMemDC, m_hBitmap);
		if (!hOldBmp)
		{
			g_winAPIs->DeleteDC(hMemDC);
			g_winAPIs->EndPaint(hwnd, &ps);
			return;
		}

		g_winAPIs->BitBlt(hDC, 0, 0, m_dwWidth, m_dwHeight, hMemDC, 0, 0, SRCCOPY);

		g_winAPIs->SelectObject(hMemDC, hOldBmp);
		g_winAPIs->DeleteDC(hMemDC);
		g_winAPIs->EndPaint(hwnd, &ps);
	}

	void CSplash::Init()
	{
		m_hThread = nullptr;
		m_hwnd = nullptr;
		m_lpszClassName = TEXT("SPLASH");
		m_colTrans = 0;
	}

	HWND CSplash::RegAndCreateWindow()
	{
		WNDCLASSEX wndclass{};
		wndclass.cbSize = sizeof(wndclass);
		wndclass.style = CS_BYTEALIGNCLIENT | CS_BYTEALIGNWINDOW;
		wndclass.lpfnWndProc = ExtWndProc;
		wndclass.cbClsExtra = 0;
		wndclass.cbWndExtra = DLGWINDOWEXTRA;
		wndclass.hInstance = g_winAPIs->GetModuleHandleW_o(nullptr);
		wndclass.hIcon = nullptr;
		wndclass.hCursor = g_winAPIs->LoadCursorW(nullptr, IDC_WAIT);
		wndclass.hbrBackground = (HBRUSH)g_winAPIs->GetStockObject(LTGRAY_BRUSH);
		wndclass.lpszMenuName = nullptr;
		wndclass.lpszClassName = m_lpszClassName;
		wndclass.hIconSm = nullptr;

		if (!g_winAPIs->RegisterClassExW(&wndclass))
		{
			APP_TRACE_LOG(LL_ERR, L"RegisterClassExW failed with error %u", g_winAPIs->GetLastError());
			return nullptr;
		}

		RECT rc_system{ 0 };
		g_winAPIs->SystemParametersInfoW(SPI_GETWORKAREA, 0, &rc_system, 0);

		int x = rc_system.right - 360;
		int y = rc_system.bottom - 90;

		m_hwnd = g_winAPIs->CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, m_lpszClassName, TEXT("SplashWnd"), WS_POPUP, x, y, m_dwWidth, m_dwHeight, nullptr, nullptr, nullptr, this);
		if (m_hwnd)
		{
			MakeTransparent();

			g_winAPIs->ShowWindow(m_hwnd, SW_SHOW);
			g_winAPIs->UpdateWindow(m_hwnd);
		}
		else
		{
			APP_TRACE_LOG(LL_ERR, L"CreateWindowExW failed with error %u", g_winAPIs->GetLastError());
		}

		return m_hwnd;
	}

	int CSplash::DoLoop()
	{
		MSG msg;
		while (g_winAPIs->GetMessageW(&msg, nullptr, 0, 0))
		{
			g_winAPIs->TranslateMessage(&msg);
			g_winAPIs->DispatchMessageW(&msg);
		}

		return msg.wParam;
	}

	void CSplash::ShowSplash()
	{
		m_hThread = g_winAPIs->OpenThread(THREAD_TERMINATE, FALSE, g_winAPIs->GetCurrentThreadId());

		CloseSplash();
		RegAndCreateWindow();
		DoLoop();
	}

	bool CSplash::SetBitmap(HBITMAP hBitmap)
	{
		int nRetValue;
		BITMAP csBitmapSize;

		FreeResources();

		if (hBitmap)
		{
			m_hBitmap = hBitmap;

			nRetValue = g_winAPIs->GetObjectW(hBitmap, sizeof(csBitmapSize), &csBitmapSize);
			if (nRetValue == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"GetObjectW failed with error %u", g_winAPIs->GetLastError());

				FreeResources();
				return false;
			}
			m_dwWidth = (DWORD)csBitmapSize.bmWidth;
			m_dwHeight = (DWORD)csBitmapSize.bmHeight;
		}

		return true;
	}

	void CSplash::FreeResources()
	{
		if (m_hBitmap)
			g_winAPIs->DeleteObject(m_hBitmap);

		m_hBitmap = nullptr;
	}

	bool CSplash::CloseSplash()
	{
		if (m_hwnd)
		{
			g_winAPIs->DestroyWindow(m_hwnd);
			m_hwnd = 0;

			g_winAPIs->UnregisterClassW(m_lpszClassName, g_winAPIs->GetModuleHandleW_o(nullptr));

			if (m_hThread)
			{
				g_winAPIs->TerminateThread(m_hThread, 0);
				g_winAPIs->CloseHandle(m_hThread);
				m_hThread = nullptr;
			}
			return true;
		}

		return false;
	}

	bool CSplash::SetTransparentColor(COLORREF col)
	{
		m_colTrans = col;

		return MakeTransparent();
	}

	bool CSplash::MakeTransparent()
	{
		if (m_hwnd && g_winAPIs->SetLayeredWindowAttributes && m_colTrans)
		{
			g_winAPIs->SetWindowLongW(m_hwnd, GWL_EXSTYLE, g_winAPIs->GetWindowLongW(m_hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
			g_winAPIs->SetLayeredWindowAttributes(m_hwnd, m_colTrans, 0, LWA_COLORKEY);
		}

		return TRUE;
	}
}
