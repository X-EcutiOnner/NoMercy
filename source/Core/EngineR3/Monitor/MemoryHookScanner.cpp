#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "MemoryHookScanner.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"

#ifdef _WIN64
constexpr bool gsc_bX86 = false;
#else
constexpr bool gsc_bX86 = true;
#endif

namespace NoMercy
{
	enum INSTRUCTION_TYPE
	{
		JMP_ABS = 0,
		JMP_PTR = 1,
		CALL_ABS = 2,
		CALL_PTR = 3,
		PTR_64 = 4,
		UNKNOWN = 5
	};


	CHookScanner::CHookScanner()
	{
	}
	CHookScanner::~CHookScanner()
	{
	}

	bool CHookScanner::__IsPrologueWhole(const DWORD_PTR base)
	{
		struct PROLOGUE_INSTRUCTION
		{
			PVOID base{ nullptr };
			SIZE_T length{ 0 };
			BYTE opcode[3]{ 0x0 };
			BYTE opcodeLen{ 0x0 };
			INSTRUCTION_TYPE type{ UNKNOWN };
		};

		auto GetTargetModule = [&, base]() -> std::tuple <PVOID, std::string> {
			std::tuple <PVOID, std::string> result = std::make_tuple(nullptr, "");
			static std::map <std::wstring, SignStatus> s_mapCheckedModules;

			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->EnumerateModules([&, base](LDR_DATA_TABLE_ENTRY* pModule) {
				if (pModule)
				{
					if (base >= (DWORD_PTR)pModule->DllBase && base <= ((DWORD_PTR)pModule->DllBase + pModule->SizeOfImage))
					{
						const auto stModuleName = stdext::to_lower_wide(pModule->BaseDllName.Buffer);
						const auto stFileName = stdext::to_lower_wide(pModule->FullDllName.Buffer);

						auto stMirrorModuleName = fmt::format(xorstr_(L"nm_hml_{0}"), stModuleName);
						auto wstTargetPath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->TempPath();
						wstTargetPath += stMirrorModuleName;
						
						if (!g_winAPIs->PathFileExistsW(wstTargetPath.c_str()))
						{
							APP_TRACE_LOG(LL_SYS, L"Mirror module file: %s creating for: %s", wstTargetPath.c_str(), stFileName.c_str());

							if (!g_winAPIs->CopyFileW(stFileName.c_str(), wstTargetPath.c_str(), FALSE))
							{
								APP_TRACE_LOG(LL_ERR, L"Module: %s mirror file: %s copy failed with error: %u", stFileName.c_str(), wstTargetPath.c_str(), g_winAPIs->GetLastError());
								return;
							}

							if (!g_winAPIs->SetFileAttributesW(wstTargetPath.c_str(), FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN))
							{
								APP_TRACE_LOG(LL_ERR, L"Module: %s mirror file: %s set attr failed with error: %u", stFileName.c_str(), wstTargetPath.c_str(), g_winAPIs->GetLastError());
								return;
							}
						}
						else
						{
							const auto it = s_mapCheckedModules.find(wstTargetPath);
							if (it != s_mapCheckedModules.end())
							{
								const auto nSignRet = it->second;
								if (nSignRet != SignStatus::Valid)
									return;
							}
							else
							{
								const auto dwCheckSignRet = PeSignatureVerifier::CheckFileSignature(wstTargetPath, true);
								const auto dwSignStatus = TrustVerifyWrapper::convertSignInfo(dwCheckSignRet);

								s_mapCheckedModules.emplace(wstTargetPath, dwSignStatus);

								if (dwSignStatus != SignStatus::Valid)
									return;
							}
						}
					
						const auto stTargetPath = stdext::to_ansi(wstTargetPath);
						result = std::make_tuple(pModule->DllBase, stTargetPath);
					}
				}
			});

			return result;
		};
		auto GetInstruction = [](DWORD_PTR base_addr, PROLOGUE_INSTRUCTION* Instruction) {
			Instruction->base = reinterpret_cast<PVOID>(base_addr);
			Instruction->type = UNKNOWN;
			Instruction->opcode[0] = *(BYTE*)base_addr;
			Instruction->opcode[1] = *(BYTE*)(base_addr + 0x1);
			Instruction->opcode[2] = *(BYTE*)(base_addr + 0x2);
			Instruction->opcodeLen = 3;
			Instruction->length = 7;

			if (*(BYTE*)base_addr == 0x48)
			{
				if (*(BYTE*)(base_addr + 0x1) == 0xFF && *(BYTE*)(base_addr + 0x2) == 0x25)
				{
					Instruction->type = PTR_64;
					Instruction->opcode[0] = 0x48;
					Instruction->opcode[1] = 0xFF;
					Instruction->opcode[2] = 0x25;
					Instruction->opcodeLen = 3;
					Instruction->length = 7;
				}
			}
			else if (*(BYTE*)base_addr == 0xFF)
			{
				if (*(BYTE*)(base_addr + 0x1) == 0x25)
				{
					Instruction->type = JMP_PTR;
					Instruction->opcode[0] = 0xFF;
					Instruction->opcode[1] = 0x25;
					Instruction->opcodeLen = 2;
					Instruction->length = 6;
				}
				else if (*(BYTE*)(base_addr + 0x1) == 0x15)
				{
					Instruction->type = CALL_PTR;
					Instruction->opcode[0] = 0xFF;
					Instruction->opcode[1] = 0x15;
					Instruction->opcodeLen = 2;
					Instruction->length = 6;
				}
			}
			else if (*(BYTE*)base_addr == 0x90)
			{
				if (*(BYTE*)(base_addr + 0x1) == 0xE9)
				{
					Instruction->type = JMP_ABS;
					Instruction->opcode[0] = 0x90;
					Instruction->opcode[1] = 0xE9;
					Instruction->opcodeLen = 2;
					Instruction->length = 6;
				}
				if (*(BYTE*)(base_addr + 0x1) == 0x90 && *(BYTE*)(base_addr + 0x2) == 0xE9)
				{
					Instruction->type = JMP_ABS;
					Instruction->opcode[0] = 0x90;
					Instruction->opcode[1] = 0x90;
					Instruction->opcode[2] = 0xE9;
					Instruction->opcodeLen = 3;
					Instruction->length = 7;
				}
			}
			else if (*(BYTE*)base_addr == 0x8B)
			{
				if (*(BYTE*)(base_addr + 0x1) == 0xFF && *(BYTE*)(base_addr + 0x2) == 0xE9)
				{
					Instruction->type = JMP_ABS;
					Instruction->opcode[0] = 0x8B;
					Instruction->opcode[1] = 0xFF;
					Instruction->opcode[2] = 0xE9;
					Instruction->opcodeLen = 3;
					Instruction->length = 7;
				}
			}
			else if (*(BYTE*)base_addr == 0xE9)
			{
				Instruction->type = JMP_ABS;
				Instruction->opcode[0] = 0xE9;
				Instruction->opcodeLen = 1;
				Instruction->length = 5;
			}
			else if (*(BYTE*)base_addr == 0xE8)
			{
				Instruction->type = CALL_ABS;
				Instruction->opcode[0] = 0xE8;
				Instruction->opcodeLen = 1;
				Instruction->length = 5;
			}
			else if (*(BYTE*)base_addr == 0xEB)
			{
				Instruction->type = CALL_ABS;
				Instruction->opcode[0] = 0xEB;
				Instruction->opcodeLen = 1;
				Instruction->length = 5;
			}
			else if (*(BYTE*)base_addr == 0x9A)
			{
				Instruction->type = CALL_ABS;
				Instruction->opcode[0] = 0x9A;
				Instruction->opcodeLen = 1;
				Instruction->length = 5;
			}
			return Instruction;
		};
		auto SameDeltaDestination = [&](PROLOGUE_INSTRUCTION* mapped_ins, PROLOGUE_INSTRUCTION* mem_ins) -> bool {
			if (mapped_ins->type == UNKNOWN && mem_ins->type == UNKNOWN)
			{
				if (*(BYTE*)mapped_ins->base != *(BYTE*)mem_ins->base)
				{
					return true;
				}
				return false;
			}
			auto ReverseDelta = [&, mem_ins](DWORD_PTR CurrentAddress, DWORD Delta, size_t InstructionLength, bool bigger = false) -> DWORD_PTR {
				if (bigger)
					return ((CurrentAddress + (Delta + InstructionLength)) - 0xFFFFFFFE);
				return CurrentAddress + (Delta + InstructionLength);
			};
			auto GetDeltaOffset = [](PROLOGUE_INSTRUCTION* ins) -> DWORD {
				if (ins->type == JMP_ABS || ins->type == CALL_ABS)
					return 0x1;

				else if (ins->type == JMP_PTR || ins->type == CALL_PTR)
					return 0x2;

				if (ins->type == PTR_64)
					return 0x3;

				return 0x0;
			};
			auto IsGreaterThan = [](LPCVOID Src, LPCVOID Dest, SIZE_T Delta) -> BOOLEAN {
				return (Src < Dest ? (SIZE_T)Dest - (SIZE_T)Src : (SIZE_T)Src - (SIZE_T)Dest) > Delta;
			};
			auto IsGreaterThan2Gb = [&, IsGreaterThan](LPCVOID Src, LPCVOID Dest) -> BOOLEAN {
				return IsGreaterThan(Src, Dest, 2 * 1024 * 1048576UL);
			};
			
			DWORD Delta = 0;
			memcpy(&Delta, (PVOID)((DWORD_PTR)mapped_ins->base + GetDeltaOffset(mapped_ins)), 4);

			DWORD_PTR DestinyAddr = 0x0;
			if (GetDeltaOffset(mapped_ins) == 0x2 && gsc_bX86)
				DestinyAddr = Delta;
			else
				DestinyAddr = ReverseDelta((DWORD_PTR)mapped_ins->base, Delta, mapped_ins->length);

			if (IsGreaterThan2Gb(mapped_ins->base, (PVOID)DestinyAddr) && GetDeltaOffset(mapped_ins) != 0x2)
				DestinyAddr = ReverseDelta((DWORD_PTR)mapped_ins->base, Delta, mapped_ins->length, true);

			auto stModuleFullName = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)DestinyAddr, false));
			auto stModuleName = stModuleFullName;
			stModuleName = stModuleName.size() > 5 ? stModuleName.substr(5, stModuleName.size()) : stModuleName;

			if (stdext::starts_with(stModuleName, std::wstring(xorstr_(L"l_"))))
				stModuleName = stdext::replace(stModuleName, std::wstring(xorstr_(L"l_")), L""s);

			memcpy(&Delta, (PVOID)((DWORD_PTR)mem_ins->base + GetDeltaOffset(mem_ins)), 4);

			if (GetDeltaOffset(mem_ins) == 0x2 && gsc_bX86)
				DestinyAddr = Delta;
			else
				DestinyAddr = ReverseDelta((DWORD_PTR)mem_ins->base, Delta, mem_ins->length);

			if (IsGreaterThan2Gb(mem_ins->base, (PVOID)DestinyAddr) && GetDeltaOffset(mem_ins) != 0x2)
				DestinyAddr = ReverseDelta((DWORD_PTR)mem_ins->base, Delta, mem_ins->length, true);

			const auto stSecondName = stdext::to_lower_wide(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)DestinyAddr, false));

			if (stModuleFullName.empty() || (stModuleName != stSecondName && stModuleFullName != stSecondName))
			{
				APP_TRACE_LOG(LL_WARN, L"Module name mismatch! %s (%s) | %s", stModuleName.c_str(), stModuleFullName.c_str(), stSecondName.c_str());
				return true;
			}

			return false;
		};


		const auto currentModule = GetTargetModule();
		const auto wstModuleName = stdext::to_wide(std::get<1>(currentModule));
		m_vecTempModules.emplace_back(wstModuleName);

		// TODO: firstly try to get copy from secureloadlibrary
		const auto dllBase = g_winAPIs->LoadLibraryExW(wstModuleName.c_str(), 0, DONT_RESOLVE_DLL_REFERENCES);
		if (dllBase)
		{
			m_mapTempModules.insert(m_mapTempModules.begin(), std::pair <HMODULE, std::wstring>(dllBase, wstModuleName));

			DWORD_PTR getRVA = (base - (DWORD_PTR)std::get<0>(currentModule));
			DWORD_PTR mappedPrologue = ((DWORD_PTR)dllBase + getRVA);
			
			PROLOGUE_INSTRUCTION mappedInstruction;
			GetInstruction(mappedPrologue, &mappedInstruction);
			
			PROLOGUE_INSTRUCTION memoryInstruction;
			GetInstruction(base, &memoryInstruction);

			if (SameDeltaDestination(&mappedInstruction, &memoryInstruction))
				return true;
		}
		else
		{
			APP_TRACE_LOG(LL_WARN, L"LoadLibraryExW (%s) failed with error: %u", wstModuleName.c_str(), g_winAPIs->GetLastError());
			stdext::remove_vector_object(m_vecTempModules, wstModuleName);
		}

		return false;
	}

	bool CHookScanner::__ScanForHooks()
	{
		auto GetHookTypeName = [](EHookScannerTypes type) -> std::string {
			switch (type)
			{
			case EHookScannerTypes::INLINE:
				return xorstr_("INLINE");
			case EHookScannerTypes::EAT:
				return xorstr_("EAT");
			case EHookScannerTypes::IAT:
				return xorstr_("IAT");
			case EHookScannerTypes::VEH:
				return xorstr_("VEH");
			default:
				return "";
			}
		};
		auto IsTargetExcepted = [&](PVOID currAddr) -> bool {
			if (!m_vecExceptionRules.empty())
			{
				for (const auto& eRule : m_vecExceptionRules)
				{
					if (eRule.bFindByAddr)
					{
						if (currAddr == eRule.pvProcedureAddr)
							return true;
					}
					else
					{
						auto wstFuncName = L""s;
						const auto bNameQueryRet = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetFunctionNameFromAddress(
							NtCurrentProcess(), nullptr, currAddr, wstFuncName
						);

						if (bNameQueryRet)
						{
							if (!eRule.bFindSubstr)
							{
								if (wstFuncName == eRule.wstFuncName)
									return true;
							}
							else
							{
								if (wstFuncName.find(eRule.wstFuncName) != std::wstring::npos)
									return true;
							}
						}
					}
				}
			}
			return false;
		};
		auto SendDetectionReport = [&](PVOID base, EHookScannerTypes type) {
			for (const auto& it : m_mmExportsList)
			{
				if (type == EHookScannerTypes::VEH)
					base = m_pvLastVEH;

				if (IsTargetExcepted(base))
					return;

				HOOK_INFO hook;
				hook.pvFunc = base;
				hook.nType = type;
				hook.stTypeName = GetHookTypeName(type);

				if (!stdext::in_vector(m_vecDetectedInlineHooks, hook.pvFunc) && type == EHookScannerTypes::INLINE)
				{
					m_vecDetectedInlineHooks.push_back(hook.pvFunc);
					m_pvCallback(&hook);
				}
				else if (!stdext::in_vector(m_vecDetectedEatHooks, hook.pvFunc) && type == EHookScannerTypes::EAT)
				{
					m_vecDetectedEatHooks.push_back(hook.pvFunc);
					m_pvCallback(&hook);
				}
				else if (!stdext::in_vector(m_vecDetectedIatHooks, hook.pvFunc) && type == EHookScannerTypes::IAT)
				{
					m_vecDetectedIatHooks.push_back(hook.pvFunc);
					m_pvCallback(&hook);
				}
				else if (!stdext::in_vector(m_vecDetectedVehHooks, hook.pvFunc) && type == EHookScannerTypes::VEH)
				{
					m_vecDetectedVehHooks.push_back(hook.pvFunc);
					m_pvCallback(&hook);
				}

				g_winAPIs->Sleep(10);
			}
		};

		for (const auto& it : m_mmExportsList)
		{
			// safe variation w try except
			auto FindedHook = [&, it](const DWORD_PTR scan, EHookScannerTypes type) -> bool {
				if (scan)
				{
					switch (type)
					{
						case EHookScannerTypes::INLINE:
						{
							if (__IsPrologueWhole(scan))
								return true;
							break;
						}

						case EHookScannerTypes::EAT:
						{
							auto IsExportMissed = [&, it]() -> bool {
								const auto stModuleName = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)it.first, false);
								if (stModuleName.empty())
								{
									APP_TRACE_LOG(LL_ERR, L"Ptr %p is missed in exports list", it.first);
									return true;
								}
								
								const auto hModule = g_winAPIs->GetModuleHandleW_o(stModuleName.c_str());
								if (!hModule)
								{
									APP_TRACE_LOG(LL_ERR, L"Module %s is missed in exports list", stModuleName.c_str());
									return true;
								}
								
								const auto pkExportAddr = (DWORD_PTR)CPEFunctions::GetExportEntry(hModule, it.second);
								if (!pkExportAddr)
								{
									APP_TRACE_LOG(LL_ERR, L"Export %s is missed in module: %s exports list", it.second.c_str(), stModuleName.c_str());
									return true;
								}
								
								if ((DWORD_PTR)it.first != pkExportAddr)
								{
									APP_TRACE_LOG(LL_ERR, L"Mem ptr: %p is not same as export ptr: %p", it.first, pkExportAddr);
									return true;
								}

								if (memcmp(it.first, (LPCVOID)pkExportAddr, 5))
								{
									APP_TRACE_LOG(LL_ERR, L"Mem ptr: %p copy is not same as export ptr: %p", it.first, pkExportAddr);
									return true;
								}
								
								return false;
							};

							if (IsExportMissed())
								return true;
							break;
						}

						case EHookScannerTypes::IAT:
						{
							m_mmImportsList.clear();
							CPEFunctions::DumpImportsSection(L"", m_mmImportsList);

							auto IsImportValid = [&]() -> bool {
								for (const auto& imp : m_mmImportsList)
								{
									if (!strcmp(std::get<0>(imp.second).c_str(), it.second.c_str()))
									{
										auto itName = stdext::to_ansi(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)it.first, false));
										// APP_TRACE_LOG(LL_SYS, L"1-Import %s from %s", std::get<0>(imp.second).c_str(), itName.c_str());
										
										if (itName.empty())
											return false;

										if (imp.first != it.first && std::get<1>(imp.second).find(itName) != std::wstring::npos)
										{
											std::wstring impName = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)imp.first, false);
											APP_TRACE_LOG(LL_WARN, L"2-Import %s from %s", impName.c_str(), itName.c_str());
											
											if (itName.empty())
												return false;

											if (impName.find(xorstr_(L"kernelbase.dll")) != std::wstring::npos ||
												impName.find(xorstr_(L"ntdll.dll")) != std::wstring::npos)
												return true;

											return false;
										}
									}

									g_winAPIs->Sleep(10);
								}
								return true;
							};
							if (!IsImportValid())
								return true;
							break;
						}
						case EHookScannerTypes::VEH:
						{
							if (!m_vecVehList.empty())
							{
								for (const auto& veh : m_vecVehList)
								{
									MEMORY_BASIC_INFORMATION mbi{ 0 };
									g_winAPIs->VirtualQuery(veh, &mbi, sizeof(mbi));

									if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
									{
										m_pvLastVEH = veh;
										return true;
									}

									g_winAPIs->Sleep(10);
								}
							}
							break;
						}
					}
				}
				return false;
			};

			PVOID exportPtr = it.first;
			if (m_pvSpecificAddr)
				exportPtr = m_pvSpecificAddr;

			if (m_nTypeOfScan == EHookScannerTypes::INLINE || m_nTypeOfScan == EHookScannerTypes::ALL)
			{
				if (FindedHook((DWORD_PTR)exportPtr, EHookScannerTypes::INLINE))
					SendDetectionReport(exportPtr, EHookScannerTypes::INLINE);
			}
			if (m_nTypeOfScan == EHookScannerTypes::EAT || m_nTypeOfScan == EHookScannerTypes::ALL)
			{
				if (FindedHook((DWORD_PTR)exportPtr, EHookScannerTypes::EAT))
					SendDetectionReport(exportPtr, EHookScannerTypes::EAT);
			}
			if (m_nTypeOfScan == EHookScannerTypes::IAT || m_nTypeOfScan == EHookScannerTypes::ALL)
			{
				if (FindedHook((DWORD_PTR)exportPtr, EHookScannerTypes::IAT))
					SendDetectionReport(exportPtr, EHookScannerTypes::IAT);
			}
			if (m_nTypeOfScan == EHookScannerTypes::VEH || m_nTypeOfScan == EHookScannerTypes::ALL)
			{
				if (FindedHook((DWORD_PTR)exportPtr, EHookScannerTypes::VEH))
					SendDetectionReport(exportPtr, EHookScannerTypes::VEH);
			}

			g_winAPIs->Sleep(10);

		}
		return true;
	}
	
	void CHookScanner::__ClearFields()
	{
		m_pvCallback = nullptr;
		m_nTypeOfScan = EHookScannerTypes::NONE;
		m_pvSpecificAddr = nullptr;
		m_VecTargetModules.clear();
		m_mmImportsList.clear();
		m_mmExportsList.clear();
		m_vecVehList.clear();
		m_vecDetectedEatHooks.clear();
		m_vecDetectedIatHooks.clear();
		m_vecDetectedInlineHooks.clear();
		m_vecDetectedVehHooks.clear();
//		m_vecExceptionRules.clear();
		m_pvLastVEH = nullptr;
	}
	bool CHookScanner::__SetFields(EHookScannerTypes scanType, THookScanCallback callback, PVOID addr, std::vector <std::wstring> moduleList, std::vector <PVOID>& vehs)
	{
		__ClearFields();
		
		for (const auto& vehIter : vehs)
		{
			this->m_vecVehList.push_back(vehIter);
		}

		for (const auto& moduleIter : moduleList)
		{
			this->m_VecTargetModules.push_back(moduleIter);
		}

		for (const auto& c_stModuleName : m_VecTargetModules)
		{
			if (CPEFunctions::DumpExportsSection(c_stModuleName.c_str(), m_mmExportsList) == false)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to dump exports section of %s", c_stModuleName.c_str());
				continue;
			}
		}
		
		m_pvSpecificAddr = addr;
		m_pvCallback = callback;
		m_nTypeOfScan = scanType;
		return true;
	}

	bool CHookScanner::IsKnownTempModuleName(const std::wstring& wstName)
	{
		for (const auto& wstCurrModuleName : m_vecTempModules)
		{
			const auto wstLowerCurrModuleName = stdext::to_lower_wide(wstCurrModuleName);
			if (wstLowerCurrModuleName.find(wstName) != std::wstring::npos)
				return true;
		}
		return false;
	}

	bool CHookScanner::AddExceptionRule(const ExceptionRule& pkRefRule)
	{
//		if (!m_bIsActive)
//			return false;

		m_vecExceptionRules.push_back(pkRefRule);
		return true;
	}
	bool CHookScanner::AddExceptionRules(const std::vector <ExceptionRule>& Rules)
	{
		if (Rules.empty())
			return false;

//		if (!m_bIsActive)
//			return false;

		for (const auto& pkRefRule : Rules)
			m_vecExceptionRules.push_back(pkRefRule);

		return true;
	}
	DWORD CHookScanner::HookScannerThreadRoutine(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"Hook scanner thread event has been started!");
		this->__ScanForHooks();
		this->StopScanner();
		return 0;
	}

	DWORD WINAPI CHookScanner::StartHookScannerThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CHookScanner*>(lpParam);
		return This->HookScannerThreadRoutine();
	}

	bool CHookScanner::StartScanner(EHookScannerTypes scanType, THookScanCallback callback, PVOID addr, std::vector <std::wstring> moduleList, std::vector <PVOID>& vehList)
	{
		if (scanType == EHookScannerTypes::NONE || !callback)
			return false;
		
		if (m_bIsActive)
			return false;

		if (!this->__SetFields(scanType, callback, addr, moduleList, vehList))
			return false;

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_HOOK_SCANNER, StartHookScannerThreadRoutine, (void*)this, 0, true);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
		);

		m_bIsActive = true;
		return true;
	}
	bool CHookScanner::IsScannerActive()
	{
		return m_bIsActive;
	}
	void CHookScanner::StopScanner()
	{
		if (!m_bIsActive)
			return;
		m_bIsActive = false;

		for (const auto& it : m_mapTempModules)
		{
			const auto bUnloadRet = g_winAPIs->FreeLibrary(it.first);
			const auto dwUnloadErr = g_winAPIs->GetLastError();

			const auto bDeleteRet = g_winAPIs->DeleteFileW(it.second.c_str());
			const auto dwDeleteErr = g_winAPIs->GetLastError();

			APP_TRACE_LOG(LL_SYS, L"Temporary module: %s (%p) cleaning result: %d(%u)/%d(%u)", it.second.c_str(), it.first, bUnloadRet, dwUnloadErr, bDeleteRet, dwDeleteErr);
		}
		m_mapTempModules.clear();

		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_HOOK_SCANNER);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
};
