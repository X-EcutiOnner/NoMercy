/*
LRESULT CALLBACK DebugProc(int code, WPARAM wParam, LPARAM lParam)
{
     return CallNextHookEx(NULL, code, wParam, lParam);
}
*/

// g_winAPIs->SetWindowsHookExA(WH_DEBUG, DebugProc, g_winModules->hBaseModule, NULL);