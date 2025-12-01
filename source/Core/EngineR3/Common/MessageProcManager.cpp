#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "MessageProcManager.hpp"

namespace NoMercy
{
#define _DispatchClientMessage_idx 21

	int WINAPI h_DispatchClientMessage_A_win32(HWND* hwnd, DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc);
	int WINAPI h_DispatchClientMessage_W_win32(HWND* hwnd, DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc);

	int WINAPI h_DispatchClientMessage_A_win64(HWND* hwnd,
#ifdef _M_IX86
		DWORD aling_32,
#endif	
		DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc
	);
	int WINAPI h_DispatchClientMessage_W_win64(HWND* hwnd,
#ifdef _M_IX86
		DWORD aling_32,
#endif	
		DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc
	);

	typedef struct _fnClient
	{
		struct pfnelement
		{
			void* pFunc;
#ifdef _M_IX86
			DWORD aling_x32;
#endif
		} element[40];
	} fnClient, * pfnClient;
	
	typedef struct _fnClient32
	{
		struct pfnelement
		{
			void* pFunc;
		} element[40];
	} fnClient32, * pfnClient32;

	typedef int (WINAPI* _DispatchClientMessagex64)(HWND* hwnd,
#ifdef _M_IX86 
		DWORD aling_32,
#endif
		DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc
	);
	typedef int (WINAPI* _DispatchClientMessagex32)(HWND* hwnd, DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc);

	void* vtbl_pDispatchA = 0;
	void* vtbl_pDispatchW = 0;
	BYTE* o_DispatchClientMessage_A = 0;
	BYTE* o_DispatchClientMessage_W = 0;

	BYTE* get_dispatch_client_message_a()
	{
		return o_DispatchClientMessage_A;
	}
	BYTE* get_dispatch_client_message_w()
	{
		return o_DispatchClientMessage_W;
	}

	inline bool dispatched_check_msg(DWORD msg)
	{
		switch (msg)
		{
			// keyborad
			case WM_KEYDOWN:
			case WM_KEYUP:
			// mouse
			case WM_LBUTTONDOWN:
			case WM_LBUTTONDBLCLK:
			case WM_LBUTTONUP:
			case WM_RBUTTONDOWN:
			case WM_RBUTTONDBLCLK:
			case WM_RBUTTONUP:
			case WM_MBUTTONDOWN: 
			case WM_MBUTTONDBLCLK:
			case WM_MBUTTONUP:
			case WM_MOUSEWHEEL: 
			case WM_MOUSEHWHEEL:
			{
				APP_TRACE_LOG(LL_CRI, L"[DispatchClient] Device Emulation [SendMessage] key: %u", msg);
				return false;
			}

			default:
				return true;
		}
	}

	int WINAPI h_DispatchClientMessage_A_win64(HWND* hwnd,
#ifdef _M_IX86
		DWORD aling_32,
#endif	
		DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc)
	{
		if (hwnd)
		{
			if (!dispatched_check_msg(msg))
			{
				APP_TRACE_LOG(LL_WARN, L"[DispatchClientMessage_A] Emulated message");
				// return 0;
			}
		}

		return  ((_DispatchClientMessagex64)get_dispatch_client_message_a())(
			hwnd,
#ifdef _M_IX86
			aling_32,
#endif
			msg, wparam, lparam, proc);
	}
	int WINAPI h_DispatchClientMessage_W_win64(HWND* hwnd,
#ifdef _M_IX86
		DWORD aling_32,
#endif	
		DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc)
	{
		if (hwnd)
		{
			if (!dispatched_check_msg(msg))
			{
				APP_TRACE_LOG(LL_WARN, L"[DispatchClientMessage_W] Emulated message");
				// return 0;
			}
		}

		return ((_DispatchClientMessagex64)get_dispatch_client_message_w())(
			hwnd,
#ifdef _M_IX86
			aling_32,
#endif
			msg, wparam, lparam, proc
		);
	}

	int WINAPI h_DispatchClientMessage_A_win32(HWND* hwnd, DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc)
	{
		if (hwnd)
		{
			if (!dispatched_check_msg(msg))
			{
				APP_TRACE_LOG(LL_CRI, L"DispatchClientMessage_A Emulated message!");
				// return 0;
			}
		}

		return ((_DispatchClientMessagex32)get_dispatch_client_message_a())(hwnd, msg, wparam, lparam, proc);
	}
	int WINAPI h_DispatchClientMessage_W_win32(HWND* hwnd, DWORD msg, WPARAM wparam, LPARAM lparam, WNDPROC proc)
	{
		if (hwnd)
		{
			if (!dispatched_check_msg(msg))
			{
				APP_TRACE_LOG(LL_CRI, L"DispatchClientMessage_W Emulated message!");
				// return 0;
			}
		}

		return ((_DispatchClientMessagex32)get_dispatch_client_message_w())(hwnd, msg, wparam, lparam, proc);
	}


	bool InitializeExperimentalWindowHook()
	{
		if (!g_winAPIs->RtlRetrieveNtUserPfn)
			return true;

		void* fnClientA = nullptr, * fnClientW = nullptr, * fnClientWorker = nullptr;

		const auto ntStatus = g_winAPIs->RtlRetrieveNtUserPfn(&fnClientA, &fnClientW, &fnClientWorker);
		APP_TRACE_LOG(LL_SYS, L"RtlRetrieveNtUserPfn result: %p", ntStatus);

		if (!NT_SUCCESS(ntStatus))
			return false;

		APP_TRACE_LOG(LL_SYS, L"fnClientA[%p] fnClientW[%p] fnClientWorker[%p]", fnClientA, fnClientW, fnClientWorker);

		if (!fnClientA || !fnClientW || !fnClientWorker)
			return false;

		/*
			pfnClient->
				0x0 pFunc  ----->[ jmp [ntdll_vtbl[1]] ]->_user32_func1
				0x8 pFunc  ----->[ jmp [ntdll_vtbl[2]] ]->_user32_func2
				0x10 pFunc ----->[ jmp [ntdll_vtbl[3]] ]->_user32_func3
				0x18 pFunc ----->[ jmp [ntdll_vtbl[4]] ]->_user32_func4
				...
				...
		*/

		if (stdext::is_x64_windows())
		{
#ifdef _M_IX86
			vtbl_pDispatchA = (void*)*(DWORD*)((DWORD)((pfnClient)fnClientA)->element[_DispatchClientMessage_idx].pFunc + 2);
			vtbl_pDispatchW = (void*)*(DWORD*)((DWORD)((pfnClient)fnClientW)->element[_DispatchClientMessage_idx].pFunc + 2);
#else
			vtbl_pDispatchA = (void*)(*(DWORD*)((DWORD64)((pfnClient)fnClientA)->element[_DispatchClientMessage_idx].pFunc + 2) +
				(DWORD64)((pfnClient)fnClientA)->element[_DispatchClientMessage_idx].pFunc + 6
			);
			vtbl_pDispatchW = (void*)(*(DWORD*)((DWORD64)((pfnClient)fnClientA)->element[_DispatchClientMessage_idx].pFunc + 2) +
				(DWORD64)((pfnClient)fnClientA)->element[_DispatchClientMessage_idx].pFunc + 6
			);
#endif
		}
		else
		{
			vtbl_pDispatchA = (void*)*(DWORD*)((DWORD)((pfnClient32)fnClientA)->element[_DispatchClientMessage_idx].pFunc + 2);
			vtbl_pDispatchW = (void*)*(DWORD*)((DWORD)((pfnClient32)fnClientW)->element[_DispatchClientMessage_idx].pFunc + 2);
		}

		o_DispatchClientMessage_A = (BYTE*)*(DWORD*)vtbl_pDispatchA;
		o_DispatchClientMessage_W = (BYTE*)*(DWORD*)vtbl_pDispatchW;
		
		APP_TRACE_LOG(LL_SYS, L"vtbl_pDispatchA[%p] vtbl_pDispatchW[%p]", vtbl_pDispatchA, vtbl_pDispatchW);
		APP_TRACE_LOG(LL_SYS, L"o_DispatchClientMessage_A[%p] o_DispatchClientMessage_W[%p]", o_DispatchClientMessage_A, o_DispatchClientMessage_W);
		
		DWORD dwOldProtectA = 0;
		g_winAPIs->VirtualProtect((void*)vtbl_pDispatchA, 0xB8, PAGE_EXECUTE_READWRITE, &dwOldProtectA);
		
		DWORD dwOldProtectW = 0;
		g_winAPIs->VirtualProtect((void*)vtbl_pDispatchW, 0xB8, PAGE_EXECUTE_READWRITE, &dwOldProtectW);

		if (stdext::is_x64_windows())
		{
#ifdef _M_IX86
			*(DWORD*)vtbl_pDispatchA = (DWORD)h_DispatchClientMessage_A_win64;
			*(DWORD*)vtbl_pDispatchW = (DWORD)h_DispatchClientMessage_W_win64;
#else
			*(DWORD64*)vtbl_pDispatchA = (DWORD64)h_DispatchClientMessage_A_win64;
			*(DWORD64*)vtbl_pDispatchW = (DWORD64)h_DispatchClientMessage_W_win64;
#endif
		}
		else
		{
			*(DWORD*)vtbl_pDispatchA = (DWORD)h_DispatchClientMessage_A_win32;
			*(DWORD*)vtbl_pDispatchW = (DWORD)h_DispatchClientMessage_W_win32;
		}

		g_winAPIs->VirtualProtect((void*)vtbl_pDispatchA, 0xB8, dwOldProtectA, &dwOldProtectA);
		g_winAPIs->VirtualProtect((void*)vtbl_pDispatchW, 0xB8, dwOldProtectW, &dwOldProtectW);
		return true;
	}

	void ReleaseExperimentalWindowHook()
	{
		if (!vtbl_pDispatchA || !vtbl_pDispatchW)
			return;

		DWORD dwOldProtectA = 0;
		g_winAPIs->VirtualProtect((void*)vtbl_pDispatchA, 0xB8, PAGE_EXECUTE_READWRITE, &dwOldProtectA);

		DWORD dwOldProtectW = 0;
		g_winAPIs->VirtualProtect((void*)vtbl_pDispatchW, 0xB8, PAGE_EXECUTE_READWRITE, &dwOldProtectW);

		if (stdext::is_x64_windows())
		{
			*(DWORD64*)vtbl_pDispatchA = (DWORD64)o_DispatchClientMessage_A;
			*(DWORD64*)vtbl_pDispatchW = (DWORD64)o_DispatchClientMessage_W;
		}
		else
		{
			*(DWORD*)vtbl_pDispatchA = (DWORD)o_DispatchClientMessage_A;
			*(DWORD*)vtbl_pDispatchW = (DWORD)o_DispatchClientMessage_W;
		}

		g_winAPIs->VirtualProtect((void*)vtbl_pDispatchA, 0xB8, dwOldProtectA, &dwOldProtectA);
		g_winAPIs->VirtualProtect((void*)vtbl_pDispatchW, 0xB8, dwOldProtectW, &dwOldProtectW);
	}
};
