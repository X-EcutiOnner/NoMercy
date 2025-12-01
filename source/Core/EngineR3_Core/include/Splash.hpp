#pragma once

namespace NoMercyCore
{
	class CSplash
	{
	public:
		virtual ~CSplash();
		CSplash();
		CSplash(HBITMAP hBitmap, COLORREF colTrans);

		void ShowSplash();
		bool CloseSplash();

		LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

	protected:
		void Init();
		void FreeResources();
		int DoLoop();
		void OnPaint(HWND hwnd);

		bool SetBitmap(HBITMAP hBitmap);

		bool SetTransparentColor(COLORREF col);
		bool MakeTransparent();
		HWND RegAndCreateWindow();

	private:
		HANDLE m_hThread;
		HWND m_hwnd;
		COLORREF m_colTrans;
		DWORD m_dwWidth;
		DWORD m_dwHeight;
		HBITMAP m_hBitmap;
		LPCTSTR m_lpszClassName;
	};
}
