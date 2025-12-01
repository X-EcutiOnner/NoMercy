#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SelfProtection.hpp"


namespace NoMercy
{
	void OnThreadAttached()
	{
//#ifdef __EXPERIMENTAL__
		if (IS_VALID_SMART_PTR(g_winAPIs) && g_winAPIs->GetCurrentThreadId)
		{
			if (CApplication::InstancePtr() && CApplication::Instance().AppIsReady())
			{ 
				if (NoMercyCore::CApplication::Instance().DataInstance()->GetAppType() == NM_CLIENT)
				{
					APP_TRACE_LOG(LL_SYS, L"Thread attached! TID: %u", g_winAPIs->GetCurrentThreadId());

					CONTEXT ctx{ 0 };
					if (!g_winAPIs->GetThreadContext(NtCurrentThread(), &ctx))
						memset(&ctx, 0, sizeof(ctx));

					auto bSuspicious = false;
					CApplication::Instance().AnalyserInstance()->OnThreadCreated(g_winAPIs->GetCurrentThreadId(), NtCurrentThread(), &ctx, bSuspicious);
				}
			}
		}
//#endif
	}

	BOOLEAN NTAPI FakeMain(PVOID DllHandle, ULONG Reason, PVOID)
	{
		if (Reason == DLL_THREAD_ATTACH)
		{
			OnThreadAttached();
		}
		else if (Reason == DLL_PROCESS_DETACH)
		{
			if (CApplication::InstancePtr())
			{
				APP_TRACE_LOG(LL_CRI, L"Process detach message handled!");
				CApplication::Instance().Finalize();
			}
		}
		return TRUE;
	}

	void InsertIntoList(LIST_ENTRY* pOurListEntry, LIST_ENTRY* pK32ListEntry)
	{
		LIST_ENTRY* pEntryToInsertAfter = pK32ListEntry->Flink;

		pOurListEntry->Flink = pEntryToInsertAfter;
		pOurListEntry->Blink = pEntryToInsertAfter->Blink;

		pEntryToInsertAfter->Blink = pOurListEntry;

		pOurListEntry->Blink->Flink = pOurListEntry;
	}
	bool CSelfProtection::SetupEntrypointWatchdog()
	{
		const auto spAntiModule = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiModuleInformations();
		if (!IS_VALID_SMART_PTR(spAntiModule))
		{
			APP_TRACE_LOG(LL_ERR, L"Anticheat module informations ptr is null!");
			return false;
		}

		LDR_DATA_TABLE_ENTRY* pK32Entry = nullptr;
		auto ntStatus = g_winAPIs->LdrFindEntryForAddress(g_winModules->hKernel32, &pK32Entry);
		if (!NT_SUCCESS(ntStatus) || !pK32Entry)
		{
			APP_TRACE_LOG(LL_ERR, L"LdrFindEntryForAddress (1) failed with status: %p", ntStatus);
			return false;
		}

		LDR_DATA_TABLE_ENTRY* pEntry = nullptr;
		ntStatus = g_winAPIs->LdrFindEntryForAddress(spAntiModule->DllBase, &pEntry);
		if (!NT_SUCCESS(ntStatus) || !pEntry)
		{
			APP_TRACE_LOG(LL_ERR, L"LdrFindEntryForAddress (2) failed with status: %p", ntStatus);
			return false;
		}

		pEntry->EntryPoint = &FakeMain;
//		pEntry->Flags |= 0x00080000 | 0x00000004;
//		pEntry->Flags &= ~(0x00040000);
//		pEntry->DllBase = (PVOID)(((ULONG_PTR)pEntry->DllBase) + 2);

		InsertIntoList(&pEntry->InInitializationOrderLinks, &pK32Entry->InInitializationOrderLinks);
		return true;
	}

	PLDR_DATA_TABLE_ENTRY GetInLoadOrderModuleList()
	{
		return (PLDR_DATA_TABLE_ENTRY)NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink;
	}
	PLDR_DATA_TABLE_ENTRY GetInMemoryOrderModuleList()
	{
		return (PLDR_DATA_TABLE_ENTRY)NtCurrentPeb()->Ldr->InMemoryOrderModuleList.Flink;
	}
	PLDR_DATA_TABLE_ENTRY GetInInitOrderModuleList()
	{
		return (PLDR_DATA_TABLE_ENTRY)NtCurrentPeb()->Ldr->InInitializationOrderModuleList.Flink;
	}

	void CSelfProtection::HideModuleLinks(HMODULE hModule)
	{
#ifdef __EXPERIMENTAL__
		auto cursor = GetInLoadOrderModuleList();
		while (cursor && cursor->DllBase)
		{
			cursor = (PLDR_DATA_TABLE_ENTRY)cursor->InLoadOrderLinks.Flink;
			if (cursor && cursor->DllBase == hModule)
			{
				auto prev = (PLDR_DATA_TABLE_ENTRY)cursor->InLoadOrderLinks.Blink;

				cursor->BaseDllName = prev->BaseDllName;
				cursor->FullDllName = prev->FullDllName;

				// unlink from hash table
				cursor->HashLinks.Blink->Flink = cursor->HashLinks.Flink;
				cursor->HashLinks.Flink->Blink = cursor->HashLinks.Blink;

				// unlink from lists
				cursor->InLoadOrderLinks.Blink->Flink = cursor->InLoadOrderLinks.Flink;
				cursor->InLoadOrderLinks.Flink->Blink = cursor->InLoadOrderLinks.Blink;
			}
		}

		cursor = GetInMemoryOrderModuleList();
		while (cursor && cursor->DllBase)
		{
			cursor = (PLDR_DATA_TABLE_ENTRY)cursor->InMemoryOrderLinks.Flink;
			if (cursor && cursor->DllBase == hModule)
			{
				auto prev = (PLDR_DATA_TABLE_ENTRY)cursor->InMemoryOrderLinks.Blink;

				cursor->BaseDllName = prev->BaseDllName;
				cursor->FullDllName = prev->FullDllName;

				// unlink from hash table
				cursor->HashLinks.Blink->Flink = cursor->HashLinks.Flink;
				cursor->HashLinks.Flink->Blink = cursor->HashLinks.Blink;

				// unlink from lists
				cursor->InMemoryOrderLinks.Blink->Flink = cursor->InMemoryOrderLinks.Flink;
				cursor->InMemoryOrderLinks.Flink->Blink = cursor->InMemoryOrderLinks.Blink;
			}
		}

		/*
		cursor = GetInInitOrderModuleList();
		while (cursor && cursor->DllBase)
		{
			cursor = (PLDR_DATA_TABLE_ENTRY)cursor->InInitializationOrderLinks.Flink;
			if (cursor && cursor->DllBase == hModule)
			{
				auto prev = (PLDR_DATA_TABLE_ENTRY)cursor->InInitializationOrderLinks.Blink;

				cursor->BaseDllName = prev->BaseDllName;
				cursor->FullDllName = prev->FullDllName;

				// unlink from hash table
				cursor->HashLinks.Blink->Flink = cursor->HashLinks.Flink;
				cursor->HashLinks.Flink->Blink = cursor->HashLinks.Blink;

				// unlink from lists
				cursor->InInitializationOrderLinks.Blink->Flink = cursor->InInitializationOrderLinks.Flink;
				cursor->InInitializationOrderLinks.Flink->Blink = cursor->InInitializationOrderLinks.Blink;
			}
		}
		*/
#endif
	}
};
