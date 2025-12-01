#include <phnt_windows.h>
#include <phnt.h>
#include "../include/tls_callback.h"

#ifdef _WIN64
    #pragma comment (linker, "/INCLUDE:_tls_used")
    #pragma comment (linker, "/INCLUDE:tls_callback_func")
#else
    #pragma comment (linker, "/INCLUDE:__tls_used")
    #pragma comment (linker, "/INCLUDE:_tls_callback_func")
#endif

#ifdef _WIN64
    #pragma const_seg(".CRT$XLB")
    EXTERN_C const
#else
    #pragma data_seg(".CRT$XLB")
    EXTERN_C
#endif

PIMAGE_TLS_CALLBACK tls_callback_func = __TlsCallback;

#ifdef _WIN64
    #pragma const_seg()
#else
    #pragma data_seg()
#endif
