#pragma once

#ifndef _DEBUG

#if USE_CODE_VIRTUALIZER_SDK == 1
#include <Protector/CodeVirtualizer/VirtualizerSDK.h>
#define __PROTECTOR__ "CodeVirtualizer"

#define __PROTECTOR_START__(x)		VIRTUALIZER_EAGLE_BLACK_START
#define __PROTECTOR_END__(x)		VIRTUALIZER_EAGLE_BLACK_END

#define __MUTATE_START__(x)			VIRTUALIZER_MUTATE_ONLY_START
#define __MUTATE_END__(x)			VIRTUALIZER_MUTATE_ONLY_END

#elif USE_SHIELDEN_SDK == 1
#include <Protector/Shielden/SESDK.h>
#define __PROTECTOR__ "Shielden"

#define __PROTECTOR_START__(x)	SE_PROTECT_START_VIRTUALIZATION
#define __MUTATE_START__(x)		SE_PROTECT_START_MUTATION

#define __PROTECTOR_END__(x)	SE_PROTECT_END
#define __MUTATE_END__(x)		SE_PROTECT_END

#elif USE_THEMIDA_SDK == 1
#include <ThemidaSDK.h>
#define __PROTECTOR__ "Themida"

#define __PROTECTOR_START__(x)	VM_START
#define __PROTECTOR_END__(x)	VM_END

#define __MUTATE_START__(x)		MUTATE_START
#define __MUTATE_END__(x)		MUTATE_END

#elif USE_VMPROTECT_SDK == 1
#include <VMProtectSDK.h>
#define __PROTECTOR__ "VMProtect"

#define __PROTECTOR_START__(x)	VMProtectBegin(x);
#define __MUTATE_START__(x)		VMProtectBeginMutation(x);

#define __PROTECTOR_END__(x)	VMProtectEnd();
#define __MUTATE_END__(x)		VMProtectEnd();

#else

#define __PROTECTOR__ "None"

#define __PROTECTOR_START__(x)
#define __PROTECTOR_END__(x)

#define __MUTATE_START__(x)
#define __MUTATE_END__(x)

#endif

#else

#define __PROTECTOR__ "None"

#define __PROTECTOR_START__(x)
#define __PROTECTOR_END__(x)

#define __MUTATE_START__(x)
#define __MUTATE_END__(x)

#endif
