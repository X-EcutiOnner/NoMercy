#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Analyser.hpp"
#include "../Common/ExceptionHandlers.hpp"
#include "../Thread/ThreadStackWalker.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/Pe.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ThreadFunctions.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include "../../EngineR3_Core/include/AutoFSRedirection.hpp"
#include "../../../Common/StdExtended.hpp"
#include "../../../Common/FilePtr.hpp"

namespace NoMercy
{
	bool ValidateAddressInImage(LPVOID lpAddress, LPVOID& lpRefBaseAddress)
	{
		bool bRet = false;

		auto fnValidateAddressInImageExImpl = [&]() {
			DWORD_PTR dwBase = 0;
			if (CPEFunctions::IsInModule(lpAddress, 1, dwBase))
			{
				lpRefBaseAddress = (LPVOID)dwBase;
				bRet = true;
			}
		};
		auto fnValidateAddressInImageEx = [&]() {
			__try
			{
				fnValidateAddressInImageExImpl();
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
		};
		fnValidateAddressInImageEx();

		return bRet;
	}
	bool ValidateTextExecution(LPVOID lpAddress, LPVOID lpBaseAddress)
	{
		if (!lpBaseAddress)
		{
			HOOK_LOG(LL_ERR, L"lpBaseAddress is null");
			return false;
		}
		
		DWORD_PTR dwBase = 0;
		if (!CPEFunctions::IsInModule(lpAddress, 0, dwBase))
		{
			HOOK_LOG(LL_ERR, L"%p is not in any module range", lpAddress);
			return false;
		}

		if (dwBase != (DWORD_PTR)lpBaseAddress)
		{
			HOOK_LOG(LL_ERR, L"%p owner module mismatch! Current: %p Expected: %p", lpAddress, dwBase, lpBaseAddress);
			return false;
		}

		wchar_t wszMappedName[MAX_PATH]{ L'\0' };
		g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpBaseAddress, wszMappedName, MAX_PATH);

		auto bHasTextSection = false;
		auto pe = Pe::PeNative::fromModule(lpBaseAddress);
		if (pe.valid())
		{
			for (auto& section : pe.sections())
			{
				std::string name(reinterpret_cast<const char*>(section.Name), sizeof(section.Name));
				while (!name.empty() && !name.back()) name.pop_back();

				if (name == xorstr_(".text"))
				{
					bHasTextSection = true;

					const auto dwStartAddr = (DWORD_PTR)(uint8_t*)((DWORD_PTR)lpBaseAddress + section.VirtualAddress);
					const auto dwEndAddr = (DWORD_PTR)dwStartAddr + section.Misc.VirtualSize;

					if (!((DWORD_PTR)lpAddress >= dwStartAddr && (DWORD_PTR)lpAddress <= dwEndAddr))
					{
						HOOK_LOG(LL_ERR, L"Address %p (%s) is not in .text section. text range: %p/%p", lpAddress, wszMappedName, dwStartAddr, dwEndAddr);
						return false;
					}
				}
			}
		}
		else
		{
			HOOK_LOG(LL_CRI, L"Failed to get PE header for module %p (%s)", lpBaseAddress, wszMappedName);
		}

		if (!bHasTextSection)
		{
			HOOK_LOG(LL_ERR, L"Failed to find .text section in module %p (%s)", lpBaseAddress, wszMappedName);
			// return false;
		}

		return true;
	}
	bool ValidateImageSection(LPVOID lpBaseAddress, PHANDLE phFile)
	{
		if (!phFile)
		{
			HOOK_LOG(LL_ERR, L"ValidateImageSection: phFile is null");
			return false;
		}
		
		wchar_t wszMappedName[MAX_PATH]{ L'\0' };
		if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpBaseAddress, wszMappedName, MAX_PATH))
		{
			HOOK_LOG(LL_ERR, L"Failed to get mapped file name for module %p Error: %u", lpBaseAddress, g_winAPIs->GetLastError());
			return false;
		}
#ifdef _DEBUG
		HOOK_LOG(LL_SYS, L"Mapped file name for module %p is %s", lpBaseAddress, wszMappedName);
#endif

		const auto c_stNormalizedName = CProcessFunctions::DosDevicePath2LogicalPath(wszMappedName);
		if (!c_stNormalizedName.length())
		{
			HOOK_LOG(LL_ERR, L"Failed to get normalized file name for module %p", lpBaseAddress);
			return false;
		}
#ifdef _DEBUG
		HOOK_LOG(LL_SYS, L"Normalized file name for module %p is %s", lpBaseAddress, c_stNormalizedName.c_str());
#endif

		PVOID OldValue = nullptr;
		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
		{
			HOOK_LOG(LL_ERR, L"Disable FS redirection failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		auto bSuccessed = true;
		*phFile = g_winAPIs->CreateFileW(c_stNormalizedName.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!IS_VALID_HANDLE(*phFile))
		{
			HOOK_LOG(LL_ERR, L"Failed to open file %s Error: %u", c_stNormalizedName.c_str(), g_winAPIs->GetLastError());
			bSuccessed = false;
		}

		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);
		return bSuccessed;
	}
	bool ValidateMatchesFile(HANDLE hFile, LPVOID lpBaseAddress)
	{
		if (!hFile)
		{
			HOOK_LOG(LL_ERR, L"ValidateMatchesFile: hFile is null");
			return false;
		}
		if (!lpBaseAddress)
		{
			HOOK_LOG(LL_ERR, L"ValidateMatchesFile: lpBaseAddress is null");
			return false;
		}

		auto pe_mem = Pe::PeNative::fromModule(lpBaseAddress);
		if (!pe_mem.valid())
		{
			HOOK_LOG(LL_ERR, L"Failed to get PE header for module %p", lpBaseAddress);
			return false;
		}

		const auto dwFileSize = g_winAPIs->GetFileSize(hFile, nullptr);
		if (!dwFileSize || dwFileSize == INVALID_FILE_SIZE)
		{
			HOOK_LOG(LL_ERR, L"Failed to get file size for module %p Error: %u", lpBaseAddress, g_winAPIs->GetLastError());
			return false;
		}

		auto lpFileBuffer = std::make_unique<BYTE[]>(dwFileSize);
		if (!IS_VALID_SMART_PTR(lpFileBuffer))
		{
			HOOK_LOG(LL_ERR, L"Failed to allocate memory for file buffer with size: %u", dwFileSize);
			return false;
		}

		DWORD dwReadSize = 0;
		if (!g_winAPIs->ReadFile(hFile, lpFileBuffer.get(), dwFileSize, &dwReadSize, nullptr))
		{
			HOOK_LOG(LL_ERR, L"Failed to read file %p Error: %u", hFile, g_winAPIs->GetLastError());
			return true; // ignore
		}
		else if (dwReadSize != dwFileSize)
		{
			HOOK_LOG(LL_ERR, L"Failed to read file %p, read size: %u, file size: %u", hFile, dwReadSize, dwFileSize);
			return false;
		}
		
		auto pe_file = Pe::PeNative::fromFile(lpFileBuffer.get());
		if (!pe_file.valid())
		{
			HOOK_LOG(LL_ERR, L"Failed to get PE header for file %p", lpBaseAddress);
			return false;
		}

		if (pe_file.headers().nt()->Signature != IMAGE_NT_SIGNATURE)
		{
			HOOK_LOG(LL_ERR, L"File %p is not a valid PE file", lpBaseAddress);
			return false;
		}

		if (pe_file.headers().nt()->OptionalHeader.SizeOfImage != pe_mem.headers().nt()->OptionalHeader.SizeOfImage)
		{
			HOOK_LOG(LL_ERR, L"File %p is not the same size as module %p", lpBaseAddress, hFile);
			return false;
		}

		if (pe_file.headers().nt()->OptionalHeader.CheckSum != pe_mem.headers().nt()->OptionalHeader.CheckSum)
		{
			HOOK_LOG(LL_ERR, L"File %p has a different checksum than module %p", lpBaseAddress, hFile);
			return false;
		}

#if 0
		// FIXME
		for (const auto& file_section : pe_file.sections())
		{
			const auto c_szFileSectionName = reinterpret_cast<const char*>(file_section.Name);
			if (!strcmp(c_szFileSectionName, xorstr_(L".text")))
			{
				for (const auto& mem_section : pe_mem.sections())
				{
					const auto c_szMemSectionName = reinterpret_cast<const char*>(mem_section.Name);
					if (!strcmp(c_szMemSectionName, xorstr_(L".text")))
					{
						const auto lpFileTextSection = (LPVOID)((LPBYTE)lpFileBuffer.get() + file_section.PointerToRawData);
						const auto lpMemTextSection = (LPVOID)((LPBYTE)lpBaseAddress + mem_section.VirtualAddress);

#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"File %p text section %p", lpBaseAddress, lpFileTextSection);
						HOOK_LOG(LL_SYS, L"Module %p text section %p", hFile, lpMemTextSection);
#endif

						if ((file_section.PointerToRawData + file_section.Misc.VirtualSize) > dwFileSize)
						{
							HOOK_LOG(LL_ERR, L"File %p text section %p is outside of file", lpBaseAddress, lpFileTextSection);
							return false;
						}

						if (memcmp(lpFileTextSection, lpMemTextSection, file_section.Misc.VirtualSize))
						{
							HOOK_LOG(LL_ERR, L"File %p has a different text section than module %p", lpBaseAddress, hFile);
							return false;
						}
					}
				}
			}
		}
#endif
		return true;
	}
	bool ValidateFile(HANDLE hFile)
	{
		wchar_t wszFileName[MAX_PATH]{ L'\0' };
		const auto dwFileNameLength = g_winAPIs->GetFinalPathNameByHandleW(hFile, wszFileName, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
		if (!dwFileNameLength)
		{
			HOOK_LOG(LL_ERR, L"Failed to get final path name for file %p Error: %u", hFile, g_winAPIs->GetLastError());
			return true; // ignore error statements
		}

		std::wstring wstFileName = wszFileName;

		// Remove \\?\ from beginning of path
		if (wstFileName.substr(0, 4) == xorstr_(L"\\\\?\\"))
		{
			wstFileName = wstFileName.substr(4);
		}

#ifdef _DEBUG
		HOOK_LOG(LL_SYS, L"File %p is %s (%s)", hFile, wszFileName, wstFileName.c_str());
#endif

		const auto obHasCert = PeSignatureVerifier::HasValidFileCertificate(wstFileName);
		if (!obHasCert.has_value())
		{
			HOOK_LOG(LL_ERR, L"Failed to query certificate informations for file %p (%ls)", hFile, wstFileName.c_str());
			return true; // ignore error statements
		}
#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
		else if (!obHasCert.value())
		{
			HOOK_LOG(LL_ERR, L"File %p (%ls) is not signed", hFile, wstFileName.c_str());
			return false;
		}

		const auto dwSignCheck = PeSignatureVerifier::CheckFileSignature(wstFileName, true);  // TODO: convertSignInfo(lRetVal)
#ifdef _DEBUG
		HOOK_LOG(LL_SYS, L"Sign check ret: %u (%ls) for: %ls", dwSignCheck, wstProvider.c_str(), wstFileName.c_str());
#endif

		if (dwSignCheck != 0)
		{
			HOOK_LOG(LL_ERR, L"File %ls has not valid signature", wstFileName.c_str());
			return false;
		}
#endif

		return true;
	}
	bool ValidateLoader(LPVOID lpBaseAddress, HANDLE hFile)
	{
		if (!lpBaseAddress)
		{
			HOOK_LOG(LL_ERR, L"Invalid module base address");
			return false;
		}
		if (!hFile)
		{
			HOOK_LOG(LL_ERR, L"Invalid file handle");
			return false;
		}
		
		const auto stModuleName = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleNameFromAddress((DWORD_PTR)lpBaseAddress);
		if (stModuleName.empty())
		{
			HOOK_LOG(LL_ERR, L"Failed to get module name for module %p", lpBaseAddress);
			return false;
		}
		auto wstModuleName = stdext::to_lower_wide(stModuleName);
		
#ifdef _DEBUG
		HOOK_LOG(LL_SYS, L"Module %p is %ls", lpBaseAddress, wstModuleName.c_str());
#endif

		wchar_t wszFileName[MAX_PATH]{ L'\0' };
		const auto dwFileNameLength = g_winAPIs->GetFinalPathNameByHandleW(hFile, wszFileName, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
		if (!dwFileNameLength)
		{
			HOOK_LOG(LL_ERR, L"Failed to get final path name for file %p Error: %u", hFile, g_winAPIs->GetLastError());
			return true; // ignore error statements
		}

		auto wstFileName = stdext::to_lower_wide(wszFileName);

		// Remove \\?\ from beginning of path
		if (wstFileName.substr(0, 4) == xorstr_(L"\\\\?\\"))
		{
			wstFileName = wstFileName.substr(4);
		}

		// Fix WoW64 path
		if (stdext::is_wow64())
		{
			if (wstModuleName.find(xorstr_(L"syswow64\\")) != std::wstring::npos)
				wstModuleName = stdext::replace<std::wstring>(wstModuleName, xorstr_(L"syswow64"), xorstr_(L"system32"));
			if (wstFileName.find(xorstr_(L"syswow64\\")) != std::wstring::npos)
				wstFileName = stdext::replace<std::wstring>(wstFileName, xorstr_(L"syswow64"), xorstr_(L"system32"));
		}

#ifdef _DEBUG
		HOOK_LOG(LL_SYS, L"File %p is %ls", hFile, wstFileName.c_str());
#endif

		// Whitelist (unknown stuff from win7 VM)
		if (wstModuleName.find(xorstr_(L"kernel32.dll")) != std::wstring::npos && wstFileName.find(xorstr_(L"gdi32.dll")) != std::wstring::npos)
			return true;

		// Check name
		if (wstModuleName != wstFileName)
		{
			HOOK_LOG(LL_ERR, L"Module %ls is not the same as file %ls", wstModuleName.c_str(), wstFileName.c_str());
#ifdef __EXPERIMENTAL__
			return false;
#else
			return true;
#endif
		}

		// Validate PE signatures
		const auto pIDH = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBaseAddress);
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			HOOK_LOG(LL_ERR, L"Module: %p has not valid DOS signature!", lpBaseAddress);
			return false;
		}
		const auto pINH = reinterpret_cast<IMAGE_NT_HEADERS*>((LPBYTE)lpBaseAddress + pIDH->e_lfanew);
		if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
		{
			HOOK_LOG(LL_ERR, L"Module: %p has not valid NT signature!", lpBaseAddress);
			return false;
		}

		// Validate memory sanity
		MODULEINFO currentModInfo{ 0 };
		if (!g_winAPIs->GetModuleInformation(NtCurrentProcess(), (HMODULE)lpBaseAddress, &currentModInfo, sizeof(currentModInfo)))
		{
			HOOK_LOG(LL_ERR, L"GetModuleInformation failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto bSizeMismatch = currentModInfo.SizeOfImage != pINH->OptionalHeader.SizeOfImage;
		if (bSizeMismatch)
		{
			HOOK_LOG(LL_ERR, L"Module %p has a different size than file %p", lpBaseAddress, hFile);
			return false;
		}

		return true;
	}
	bool ValidateThreadAddress(LPVOID lpAddress)
	{
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		const auto ntStatus = g_winAPIs->NtQueryVirtualMemory(NtCurrentProcess(), lpAddress, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
		if (NT_SUCCESS(ntStatus))
		{
			if (mbi.AllocationBase && mbi.Type != MEM_IMAGE)
			{
				if (mbi.AllocationProtect & PAGE_EXECUTE || mbi.AllocationProtect & PAGE_EXECUTE_READ ||
					mbi.AllocationProtect & PAGE_EXECUTE_READWRITE || mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
				{
					HOOK_LOG(LL_ERR, L"Unknown memory area for: %p Type: %u AllocationBase: %p AllocationProtect: %u",
						lpAddress, mbi.Type, mbi.AllocationBase, mbi.AllocationProtect
					);
					
					if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsBadReadPtr(mbi.BaseAddress, 2))
					{
						BYTE byBuffer[0x2]{ 0 };
						memcpy(&byBuffer, mbi.BaseAddress, sizeof(byBuffer));

						if (byBuffer[0] == 'M' && byBuffer[1] == 'Z')
						{
							HOOK_LOG(LL_ERR, L"Module: %p loaded memory!", mbi.BaseAddress);
						}
					}
					return false;
				}
				else if (mbi.AllocationProtect & PAGE_READONLY && mbi.AllocationProtect & PAGE_NOACCESS)
				{
					HOOK_LOG(LL_ERR, L"Executed from readonly memory area for: %p Type: %u AllocationBase: %p AllocationProtect: %u",
						lpAddress, mbi.Type, mbi.AllocationBase, mbi.AllocationProtect
					);
					return false;
				}
			}
		}
		else
		{
			HOOK_LOG(LL_ERR, L"Failed to query memory information for: %p Error: %p", lpAddress, ntStatus);
			return false;
		}
		return true;
	}
	bool ValidateInstructionPointer(LPVOID lpInstrPtr)
	{
		MEMORY_BASIC_INFORMATION mbi{ 0 };
		const auto ntStatus = g_winAPIs->NtQueryVirtualMemory(NtCurrentProcess(), lpInstrPtr, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
		if (NT_SUCCESS(ntStatus))
		{			
			if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE && mbi.RegionSize > 0x2000)
			{
				HOOK_LOG(LL_ERR, L"Illegal instruction ptr: %p State: %u Type: %u RegionSize: %u",
					lpInstrPtr, mbi.State, mbi.Type, mbi.RegionSize
				);
				return false;
			}
		}
		else
		{
			HOOK_LOG(LL_ERR, L"Failed to query memory information for: %p Error: %p", lpInstrPtr, ntStatus);
			return false;
		}
		return true;
	}
	bool ValidateThradeFrames()
	{
#if _DEBUG
		auto nIdx = 0;
		
		auto Frame = g_winAPIs->RtlGetFrame();
		while (Frame)
		{
			nIdx++;
			
			if (Frame)
			{
				APP_TRACE_LOG(LL_CRI,
					L"#%d Frame: %p ctx: %p(name: %s flags: %u) Flags: %u",
					nIdx, Frame, Frame->Context, Frame->Context->FrameName, Frame->Context->Flags, Frame->Flags
				);
			}
			Frame = Frame->Previous;
		}
#endif
		
		return true;
	}
	bool ValidateWow32ReservedIntegrity(HANDLE hThread)
	{
		auto __GetTEB = [&]() -> PTEB {
			THREAD_BASIC_INFORMATION tbi{ 0 };
			const auto ntStatus = g_winAPIs->NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"NtQueryInformationThread fail! Thread: %p Status: %p", hThread, ntStatus);
				return {};
			}

			return tbi.TebBaseAddress;
		};
		
		if (!IS_VALID_HANDLE(hThread))
		{
			APP_TRACE_LOG(LL_ERR, L"Invalid thread handle: %p", hThread);
			return true; // ignore
		}
		
		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hThread))
		{
			DWORD dwExitCode = 0;
			const auto bExitCodeRet = g_winAPIs->GetExitCodeThread(hThread, &dwExitCode);
			
			APP_TRACE_LOG(LL_WARN, L"Corrupted thread handle: %p Exit code: %u (%d)", hThread, dwExitCode, bExitCodeRet);
			return true; // ignore
		}

		const auto dwThreadID = g_winAPIs->GetThreadId(hThread);
		if (!dwThreadID)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get thread id for: %p", hThread);
			return true; // ignore
		}

		const auto dwOwnerPID = CThreadFunctions::GetThreadOwnerProcessId(dwThreadID);
		if (!dwOwnerPID)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get thread owner process id for: %p", hThread);
			return true; // ignore
		}

		if (dwOwnerPID != g_winAPIs->GetCurrentProcessId())
		{
			APP_TRACE_LOG(LL_ERR, L"Thread owner process id mismatch for: %p", hThread);
			return true; // ignore
		}

		const auto pTEB = __GetTEB();
		if (!pTEB)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get TEB for thread: %p", hThread);
			return true; // ignore
		}

		auto fnGetWow32ReservedSafe = [&]() -> PVOID {
			__try
			{
				return pTEB->WOW32Reserved;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return {};
			}
		};

		const auto pWOW32Reserved = fnGetWow32ReservedSafe();
		if (pWOW32Reserved)
		{
			auto bFixFSRedirection = false;
			if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->IsFsRedirectionDisabled())
				bFixFSRedirection = true;

			// Disables file system redirection for the calling thread.
			PVOID OldValue = nullptr;
			if (bFixFSRedirection && !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
			{
				HOOK_LOG(LL_ERR, L"Disable FS redirection failed! Last error: %u", g_winAPIs->GetLastError());
				return true;
			}

			wchar_t wszSystemDirectory[MAX_PATH]{ L'\0' };
			g_winAPIs->GetSystemDirectoryW(wszSystemDirectory, MAX_PATH);

			const auto stWow64Cpu = stdext::to_lower_wide(wszSystemDirectory) + xorstr_(L"\\wow64cpu.dll");
			if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(stWow64Cpu))
			{
				const auto stWow32Owner = CApplication::Instance().FunctionsInstance()->GetModuleOwnerName(NtCurrentProcess(), pWOW32Reserved);
				APP_TRACE_LOG(LL_TRACE, L"stWow32Owner: %s --- stWow64Cpu: %s", stWow32Owner.c_str(), stWow64Cpu.c_str());

				if (stWow64Cpu != stWow32Owner)
				{
					APP_TRACE_LOG(LL_ERR, L"WOW32Reserved hook detected in: %p to: %s", hThread, stWow32Owner.c_str());
					return false;
				}
			}

			// Restore file system redirection for the calling thread.
			if (bFixFSRedirection)
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);

			// Check opcode of the callgate
			const auto pOpcode = reinterpret_cast<const BYTE*>(pWOW32Reserved);
			if (pOpcode && pOpcode[0] != 0xEA)
			{
				APP_TRACE_LOG(LL_ERR, L"Wow32Reserved callgate check failed, Opcode: 0x%X", pOpcode[0]);
				return false;
			}
		}
		
		return true;
	}
	
	bool CAnalyser::__CanAnalyseThread(DWORD dwThreadID)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxThread);

		if (std::find(m_analysed_threads.begin(), m_analysed_threads.end(), dwThreadID) == m_analysed_threads.end())
		{
			m_analysed_threads.emplace_back(dwThreadID);
			return true;
		}
		return false;
	}
	bool CAnalyser::__CanAnalyseModule(const std::wstring& c_wstModuleName)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxModule);

		if (std::find(m_analysed_modules.begin(), m_analysed_modules.end(), c_wstModuleName) == m_analysed_modules.end())
		{
			m_analysed_modules.emplace_back(c_wstModuleName);
			return true;
		}
		return false;
	}
	bool CAnalyser::__CanAnalyseSection(const HANDLE c_hFile)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxSection);

		if (std::find(m_analysed_sections.begin(), m_analysed_sections.end(), c_hFile) == m_analysed_sections.end())
		{
			m_analysed_sections.emplace_back(c_hFile);
			return true;
		}
		return false;
	}
	bool CAnalyser::__CanAnalyseMappedSection(const LPVOID c_lpMemory)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxMappedSection);

		if (std::find(m_analysed_section_mems.begin(), m_analysed_section_mems.end(), c_lpMemory) == m_analysed_section_mems.end())
		{
			m_analysed_section_mems.emplace_back(c_lpMemory);
			return true;
		}
		return false;
	}
	bool CAnalyser::__CanAnalyseException(const PEXCEPTION_RECORD c_pExceptionInfo)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxException);

		if (std::find(m_analysed_exceptions.begin(), m_analysed_exceptions.end(), c_pExceptionInfo) == m_analysed_exceptions.end())
		{
			m_analysed_exceptions.emplace_back(c_pExceptionInfo);
			return true;
		}
		return false;
	}
	bool CAnalyser::__CanAnalyseConnection(const std::wstring& c_stAddress)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxConnection);

		if (std::find(m_analysed_connections.begin(), m_analysed_connections.end(), c_stAddress) == m_analysed_connections.end())
		{
			m_analysed_connections.emplace_back(c_stAddress);
			return true;
		}
		return false;
	}
	bool CAnalyser::__CanAnalyseWindow(const HWND c_hWnd)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxWindow);

		if (std::find(m_analysed_windows.begin(), m_analysed_windows.end(), c_hWnd) == m_analysed_windows.end())
		{
			m_analysed_windows.emplace_back(c_hWnd);
			return true;
		}
		return false;
	}
	bool CAnalyser::__CanAnalyseModuleRequest(const std::wstring& c_wstName)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxModuleRequest);

		if (std::find(m_analysed_module_requests.begin(), m_analysed_module_requests.end(), c_wstName) == m_analysed_module_requests.end())
		{
			m_analysed_module_requests.emplace_back(c_wstName);
			return true;
		}
		return false;
	}
	bool CAnalyser::__CanAnalyseDelayExecution(const LPVOID c_lpCallerFunc)
	{
		std::lock_guard <std::recursive_mutex> lock(m_mtxDelayExecution);

		if (std::find(m_analysed_delayed_executions.begin(), m_analysed_delayed_executions.end(), c_lpCallerFunc) == m_analysed_delayed_executions.end())
		{
			m_analysed_delayed_executions.emplace_back(c_lpCallerFunc);
			return true;
		}
		return false;
	}

	bool CAnalyser::OnThreadCreated(DWORD dwThreadID, HANDLE hThread, PCONTEXT lpRegisters, bool& bSuspicious)
	{
		HOOK_LOG(LL_SYS, L"Thread: %u analyse started! HasRegisters: %d", dwThreadID, lpRegisters ? 1 : 0);

		bSuspicious = false;
		auto ret = false;
		auto step = 0;

		if (__CanAnalyseThread(dwThreadID))
		{
			auto timer = CStopWatch <std::chrono::milliseconds>();

			do
			{
				HOOK_LOG(LL_SYS, L"Thread analyse starting...");

				/*
				// Self thread identify
				if (CApplication::Instance().ThreadManagerInstance()->GetThreadFromId(dwThreadID))
				{
					HOOK_LOG(LL_SYS, L"Thread: %u is created by anticheat", dwThreadID);
					ret = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 1
				*/

				// Sanity
				const auto thread = stdext::make_unique_nothrow<CThread>(hThread);
				if (!IS_VALID_SMART_PTR(thread) || !thread->IsValid())
				{
					HOOK_LOG(LL_ERR, L"Not valid thread");
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 2

				if (thread->IsItAlive() == false)
				{
					HOOK_LOG(LL_ERR, L"Not alive thread");
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 3

				const auto start_address = thread->GetStartAddress();
				if (!start_address)
				{
					HOOK_LOG(LL_ERR, L"Not valid start address");
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 4

				MEMORY_BASIC_INFORMATION mbi{ 0 };
				if (!g_winAPIs->VirtualQuery(start_address, &mbi, sizeof(mbi)))
				{
					HOOK_LOG(LL_ERR, L"VirtualQuery failed. Error: %u Address: %p", g_winAPIs->GetLastError(), start_address);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 6

				HOOK_LOG(LL_SYS,
					L"MBI; BaseAddress: %p AllocationBase: %p AllocationProtect: %u Protect: %u State: %u Type: %u",
					mbi.BaseAddress, mbi.AllocationBase, mbi.AllocationProtect, mbi.Protect, mbi.State, mbi.Type
				);

				const auto owner_module = CApplication::Instance().FunctionsInstance()->GetModuleOwnerName(NtCurrentProcess(), start_address);
				const auto lower_owner_module_a = stdext::to_lower_ansi(owner_module);
				const auto lower_owner_module_w = stdext::to_lower_wide(owner_module);
				HOOK_LOG(LL_SYS, L"Thread: %u Start address: %p Owner module: %s", dwThreadID, start_address, owner_module.c_str());

				const auto anti_module = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiFullName();
				const auto lower_anti_module = stdext::to_lower_ansi(anti_module);

				HOOK_LOG(LL_SYS, L"Anti module name: %s", anti_module.c_str());

				auto context = lpRegisters ? stdext::make_shared_nothrow<CONTEXT>(*lpRegisters) : thread->GetContext();
				HOOK_LOG(LL_SYS, L"Thread context: %p", context.get());

				if (!IS_VALID_SMART_PTR(context))
				{
					HOOK_LOG(LL_ERR, L"Not valid context");
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 7

				/// Check routines
				
		// FIXME memory leak - abnormal program termination
#ifdef __EXPERIMENTAL__
				// Stack scan
				std::vector <std::shared_ptr <SStackFrame>> vecStackData;
				const auto bStackRet = GetThreadCallStack(NtCurrentProcess(), hThread, vecStackData);
#endif

				if (CApplication::Instance().ScannerInstance() && !CApplication::Instance().ScannerInstance()->CheckStackTrace())
				{
					HOOK_LOG(LL_ERR, L"Thread stack malformed!");

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_malformed, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 8
				
				// Out of bound user memory
#ifdef _M_IX86
				if (context->Edx >= 0x70000000)
#else
				if (context->Rdx > 0x7FFFFFFEFFFF)
#endif
				{
					const auto param = (void*)
#ifdef _M_IX86
						context->Edx;
#else
						context->Rdx;
#endif
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_outofbound_memory, fmt::format(xorstr_(L"{0}"), fmt::ptr(param)));

					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 9

				// RWX memory
#ifdef __EXPERIMENTAL__
				if (!stdext::is_debug_env())
				{
#ifdef _M_IX86
					if (!IsBadWritePtr((LPVOID)context->Edx, 1))
#else
					if (!IsBadWritePtr((LPVOID)context->Rdx, 1))
#endif
					{
						const auto param = (void*)
#ifdef _M_IX86
							context->Edx;
#else
							context->Rdx;
#endif
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_rwx_memory, fmt::format(xorstr_(L"{0}"), fmt::ptr(param)));
						bSuspicious = true;
						break;
					}
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 10
#endif
				
				// Shellcode analyser
				const auto shellcode_type = AnalyseShellcode(start_address, EAnalyseTypes::ANALYSE_THREAD, L"");
				if (shellcode_type)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_suspicious_shellcode, std::to_wstring(shellcode_type));
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 111

				/*
				// FIXME: Worker threads (TppWorkerThread)
				// Startaddress compare (spoofed address)
#ifdef _M_IX86
				const auto start_address_reg = (PVOID)context->Eax;
#else
				const auto start_address_reg = (PVOID)context->Rcx;
#endif
				if (start_address_reg && start_address_reg != start_address)
				{
					const auto owner_module_reg = CApplication::Instance().FunctionsInstance()->GetModuleOwnerName(NtCurrentProcess(), start_address_reg);
					HOOK_LOG(LL_ERR, L"Start address mismatch. Thread: %u Addr: %p/%p Owner module: %s/%s", dwThreadID, start_address, start_address_reg, owner_module.c_str(), owner_module_reg.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_suspicious_startaddress, owner_module);
					bSuspicious = true;
					break;
				}
				*/
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 12

				// Remote thread
				if (thread->IsRemoteThread())
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_remotethread, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 13

				/*
				// FIXME: False positive
				// Suspended thread
				if (!stdext::is_debug_env() && thread->HasSuspend())
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_suspendedthread, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 14
				*/

				// Unlinked/Manual mapped memory
				if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsLoadedModuleBase((DWORD_PTR)start_address))
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_already_loaded_module_base, owner_module);;
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 15

				// Debug injection
				const auto pvDbgUiRemoteBreakin = (PVOID)g_winAPIs->GetProcAddress(g_winModules->hNtdll, xorstr_("DbgUiRemoteBreakin"));
#ifdef _M_IX86
				const auto ins_ptr_reg = (PVOID)context->Eip;
#else
				const auto ins_ptr_reg = (PVOID)context->Rip;
#endif
				if (ins_ptr_reg && pvDbgUiRemoteBreakin && ins_ptr_reg == pvDbgUiRemoteBreakin)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_debug_injection, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 16

				/* // CHECKME: Mostly likely incompatible with HWBP trap
				// Debug registers
				if (thread->HasDebugRegisters())
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_has_debug_register, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 17
				*/

				// Thread started in memory page's allocated base(entry point)
				if (mbi.AllocationBase && mbi.AllocationBase == start_address)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_memory_ep_base, owner_module);
					bSuspicious = true;
					break;
				}
				else if (mbi.AllocationBase && mbi.AllocationBase == mbi.BaseAddress)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_memory_ep_base_2, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 18

				// Unknown module owner
				const auto hOwnerModule = g_winAPIs->GetModuleHandleW_o(owner_module.c_str());
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 19
				if (!hOwnerModule)
				{
					// Just anti-cheat can be unlinked
					if (lower_owner_module_a != lower_anti_module)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_unknown_module, owner_module);
						bSuspicious = true;
						break;
					}
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 20

				// Unknown module owner by memory
				HMODULE hOwnerByMemory = nullptr;
				g_winAPIs->GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)start_address, &hOwnerByMemory);
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 21

				if (!hOwnerByMemory && mbi.Type == MEM_IMAGE)
				{
					// Just anti-cheat can be unlinked
					if (lower_owner_module_a != lower_anti_module)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_unknown_module_memory, owner_module);
						bSuspicious = true;
						break;
					}
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 22

				// Get module informations
				MODULEINFO currentModInfo = { 0 };
				if (hOwnerModule && !g_winAPIs->GetModuleInformation(NtCurrentProcess(), hOwnerModule, &currentModInfo, sizeof(currentModInfo)))
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_module_info_fail, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 23

				// Out of bound module area
				const auto dwModuleLow = (DWORD_PTR)currentModInfo.lpBaseOfDll;
				const auto dwModuleHi = (DWORD_PTR)currentModInfo.lpBaseOfDll + currentModInfo.SizeOfImage;
				if ((DWORD_PTR)start_address < dwModuleLow || (DWORD_PTR)start_address > dwModuleHi)
				{
					// Just anti-cheat can be spoofed
					if (lower_owner_module_a != lower_anti_module)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_outofbound_module, owner_module);
						bSuspicious = true;
						break;
					}
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 24

				/*
				// Digital signature validation
				auto bSkipSignCheck = false;
				if (stdext::is_debug_build() && lower_owner_module_w.find(xorstr_(L"nomercy")) != std::wstring::npos)
					bSkipSignCheck = true;

				if (!bSkipSignCheck)
				{
					const auto obHasCert = PeSignatureVerifier::HasValidFileCertificate(lower_owner_module_w);
					if (obHasCert.has_value())
					{
						HOOK_LOG(LL_TRACE, L"Cert query completed with result: %d", obHasCert.value());

						if (!obHasCert.value())
						{
							HOOK_LOG(LL_ERR, L"Cert query for: %s completed with result: %d", lower_owner_module_w.c_str(), obHasCert.value());
							
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_module_not_signed, owner_module);
							bSuspicious = true;
							break;
						}
					}
				}
				else
				{
					HOOK_LOG(LL_ERR, L"Failed to query certificate informations for file %ls", lower_owner_module_w.c_str());
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 25

				if (!bSkipSignCheck)
				{
					std::wstring wstProvider;
					const auto dwSignCheck = PeSignatureVerifier::CheckFileSignature(lower_owner_module_w, true); // TODO: convertSignInfo(lRetVal)
					HOOK_LOG(LL_SYS, L"Sign check ret: %u (%ls) for: %ls", dwSignCheck, wstProvider.c_str(), lower_owner_module_w.c_str());

					if (dwSignCheck != 0)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_module_sign_not_valid, owner_module);
						bSuspicious = true;
						break;
					}
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 26
				*/

				// Already allocated/registered module
				if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->ModuleCountByAddress((HMODULE)mbi.AllocationBase))
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_module_already_allocated, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 27

#ifdef __EXPERIMENTAL__
				// Start address not in any module's .text section range
				DWORD_PTR dwBase = 0;
				if (!CPEFunctions::IsInModule(start_address, 0, dwBase))
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_not_in_module, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 28
#endif
				
				// Unllowed memory attributes
				if (mbi.State == MEM_COMMIT &&
					mbi.Type != MEM_IMAGE &&
					(mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.AllocationProtect == PAGE_EXECUTE_READWRITE))
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_unallowed_memory, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 30

				// Unaccesible or trap memory protection
				if (mbi.Protect & PAGE_GUARD || mbi.Protect == PAGE_NOACCESS)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_unallowed_memory_protection, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 31				

				// Mapped module?
				if (mbi.Type == MEM_PRIVATE && mbi.BaseAddress != g_winModules->hNtdll && mbi.AllocationBase != g_winModules->hNtdll)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_unallowed_memory_type, owner_module);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 32			

#ifdef __EXPERIMENTAL__
				/// Forward to other scanners
				step = 100;

				// Thread owner module's file scan
				if (CApplication::Instance().ScannerInstance()->FileScanner())
					CApplication::Instance().ScannerInstance()->FileScanner()->Scan(lower_owner_module_w, FILE_SCAN_TYPE_HOOK);
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 101

				// Thread owner module's memory scan
				if (CApplication::Instance().ScannerInstance()->SectionScanner())
				{
					auto ctx = stdext::make_shared_nothrow<SSectionScanContext>();
					if (IS_VALID_SMART_PTR(ctx))
					{
						ctx->dwBase = (ptr_t)mbi.BaseAddress;
						ctx->dwProcessId = g_winAPIs->GetCurrentProcessId();
						ctx->dwSize = mbi.RegionSize;
						ctx->hProcess = NtCurrentProcess();

						CApplication::Instance().ScannerInstance()->SectionScanner()->ScanSync(ctx);
					}
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 102

				// Thread owner module scan
				if (CApplication::Instance().ScannerInstance()->ModuleScanner())
				{
					CApplication::Instance().ScannerInstance()->ModuleScanner()->ScanSync(
						lower_owner_module_w
					);
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 103

				// Thread arbitrary user pointer module file scan
				if (dwThreadID == HandleToULong(NtCurrentThreadId()))
				{
					const auto teb = NtCurrentTeb();
					if (teb)
					{
						const auto user_ptr = teb->NtTib.ArbitraryUserPointer;
						if (user_ptr)
						{
							std::wstring w_user_ptr{ static_cast<PCWSTR>(user_ptr) };
							if (!w_user_ptr.empty())
								CApplication::Instance().ScannerInstance()->FileScanner()->Scan(w_user_ptr, FILE_SCAN_TYPE_HOOK);
						}
					}
				}
				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 104
#endif

				// FIXME memory leak - abnormal program termination
#ifdef __EXPERIMENTAL__
				// Stack check
				step = 200;

				if (bStackRet)
				{
					static constexpr auto STACK_CHECK_LIMIT = 6;
					
					auto nIdx = 0;
					for (const auto& spStackCtx : vecStackData)
					{
						if (nIdx++ >= STACK_CHECK_LIMIT)
							break;

						const auto lpAddress = Ptr64ToPtr((ptr_t)spStackCtx->qwFrameAddress);
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"#%d Stack frame address: %p", nIdx, lpAddress);
#endif
						if (!lpAddress)
							continue;

						if (CMemHelper::IsBadReadPtr(lpAddress))
						{
							APP_TRACE_LOG(LL_SYS, L"Bad read pointer: %p", lpAddress);
							continue;
						}
						
						LPVOID lpBaseAddress = nullptr;
						if (!ValidateAddressInImage(lpAddress, lpBaseAddress))
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalid_address);
							bSuspicious = true;
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Stack frame: %p is executed from image: %p", lpAddress, lpBaseAddress);
#endif

						if (!ValidateTextExecution(lpAddress, lpBaseAddress))
						{							
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalid_text_execution, owner_module);
							bSuspicious = true;
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Stack frame is in text section!");
#endif

						HANDLE hFile{};
						if (!ValidateImageSection(lpBaseAddress, &hFile))
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalid_image_section, owner_module);
							bSuspicious = true;
							if (IS_VALID_HANDLE(hFile)) { g_winAPIs->CloseHandle(hFile); };
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Stack frame is in image section: %p", hFile);
#endif

						if (!ValidateMatchesFile(hFile, lpBaseAddress))
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalid_matched_file, owner_module);
							bSuspicious = true;
							if (IS_VALID_HANDLE(hFile)) { g_winAPIs->CloseHandle(hFile); };
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Stack frame memory is matched with their file!");
#endif

						if (!ValidateFile(hFile))
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalidated_file, owner_module);
							bSuspicious = true;
							if (IS_VALID_HANDLE(hFile)) { g_winAPIs->CloseHandle(hFile); };
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Stack frame file is valid!");
#endif

						if (!ValidateLoader(lpBaseAddress, hFile))
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalid_loader, owner_module);
							bSuspicious = true;
							if (IS_VALID_HANDLE(hFile)) { g_winAPIs->CloseHandle(hFile); };
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Stack frame is in loader!");
#endif

						if (IS_VALID_HANDLE(hFile))
						{
							g_winAPIs->CloseHandle(hFile);
							hFile = nullptr;
						}

						if (!ValidateThreadAddress(lpBaseAddress))
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalid_thread_address, owner_module);
							bSuspicious = true;
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Thread address validated!");
#endif
						
						LPVOID lpInstrPtrBaseAddress = nullptr;
						if (!ValidateAddressInImage((LPVOID)spStackCtx->qwInstrPtr, lpInstrPtrBaseAddress))
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalid_instruction_pointer_address, owner_module);
							bSuspicious = true;
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Stack frame instruction ptr: %p is executed from image: %p", (LPVOID)spStackCtx->qwInstrPtr, lpInstrPtrBaseAddress);
#endif
						
						if (!ValidateInstructionPointer((LPVOID)spStackCtx->qwInstrPtr))
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalid_instruction_pointer, owner_module);
							bSuspicious = true;
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Instruction pointer validated!");
#endif

						if (spStackCtx->bHasDebugRegister)
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_has_debug_register, owner_module);
							bSuspicious = true;
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Stack frame has no debug register!");
#endif				

						if (!ValidateThradeFrames())
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_invalid_thread_frames, owner_module);
							bSuspicious = true;
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Thread frames validated!");
#endif				

						if (!ValidateWow32ReservedIntegrity(hThread))
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Thread_stack_wow32reserved_hook, owner_module);
							bSuspicious = true;
							break;
						}
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Wow32Reserved integrity validated!");
#endif				

#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"#%d Stack check completed!", nIdx);
#endif
					}
				}
#endif

				HOOK_LOG(LL_SYS, L"Thread analyse step: %d completed!", step++); // 201

				// Everything seems fine
				ret = true;
			} while (false);

			HOOK_LOG(LL_SYS, L"Thread: %u analysed in %u ms ret: %d suspicious: %d", dwThreadID, timer.diff(), ret ? 1 : 0, bSuspicious ? 1 : 0);
			return ret;
		}

#ifdef _DEBUG
		if (bSuspicious && g_winAPIs->IsDebuggerPresent())
			g_winAPIs->DebugBreak();
#endif

		HOOK_LOG(LL_SYS, L"Thread: %u already analysed.", dwThreadID);
		return true;
	}
	bool CAnalyser::OnModuleLoaded(const std::wstring& wstName, HANDLE hThread, uint8_t nCheckType, bool& bSuspicious)
	{
		const auto dwThreadId = g_winAPIs->GetThreadId(hThread);
		HOOK_LOG(LL_TRACE, L"Module: %ls analyse started! Check type: %u TID: %p(%u)", wstName.c_str(), nCheckType, hThread, dwThreadId);

		bSuspicious = false;
		auto ret = false;

		if (__CanAnalyseModule(wstName))
		{
			auto timer = CStopWatch <std::chrono::milliseconds>();

			do
			{
				const auto lower_name = stdext::to_lower_wide(wstName);

				// NoMercy module
				const auto anti_module = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiFullName();
				const auto lower_anti_module = stdext::to_lower_wide(anti_module);
				if (lower_anti_module == lower_name)
				{
					HOOK_LOG(LL_SYS, L"File is NoMercy module, skipped.");
					ret = true;
					break;
				}

				// If the string equals to main executable name(w/ path), skip it. (windows xp and vista generic problem).
				const auto main_executable = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath();
				const auto lower_main_executable = stdext::to_lower_wide(main_executable);
				if (lower_name == lower_main_executable)
				{
					HOOK_LOG(LL_SYS, L"File is main executable, skipped.");
					ret = true;
					break;
				}

				// Skip OS modules
				if (IsWindows10OrGreater() && g_winAPIs->SfcIsFileProtected(nullptr, wstName.c_str()))
				{
					HOOK_LOG(LL_SYS, L"OS module file: %ls, skipped.", wstName.c_str());
					ret = true;
					break;
				}

				// Stack scan
				if (CApplication::Instance().ScannerInstance() && !CApplication::Instance().ScannerInstance()->CheckStackTrace())
				{
					HOOK_LOG(LL_ERR, L"Thread stack malformed!");

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Stack_is_malformed, lower_name);
					bSuspicious = true;
					break;
				}

				// Check file exist in disk
				if (!std::filesystem::exists(lower_name))
				{
					HOOK_LOG(LL_ERR, L"File: %s does not exist", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_file_not_exist, lower_name);
					bSuspicious = true;
					break;
				}

				// disabled due than new exception
				/*
				// Open file
				auto fp = msl::file_ptr(lower_name, xorstr_(L"rb"));
				if (!fp)
				{
					HOOK_LOG(LL_ERR, L"File: %s could not open", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_file_open_fail, lower_name);
					bSuspicious = true;
					break;
				}

				// Read file
				const auto file_data = fp.string_read();
				if (file_data.empty())
				{
					HOOK_LOG(LL_ERR, L"File: %s could not read", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_file_read_fail, lower_name);
					bSuspicious = true;
					break;
				}

				// Create file MD5
				const auto file_hash = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetMd5(file_data.data());
				if (file_hash.empty())
				{
					HOOK_LOG(LL_ERR, L"File: %s hash could not created", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_file_create_hash_fail, lower_name);
					bSuspicious = true;
					break;
				}
				*/

				// Whitelisted file name/hash
				auto bWhiteListedName = false;
				const auto vecNameWhiteList = CApplication::Instance().QuarentineInstance()->FileQuarentine()->GetWhitelist();
				for (const auto& pkFile : vecNameWhiteList)
				{
					/*
					if (pkFile.md5 == file_hash)
					{
						HOOK_LOG(LL_SYS, L"File: %s has whitelisted hash", lower_name.c_str());
						ret = true;
						break;
					}
					*/

					if (lower_name.find(pkFile.name) != std::wstring::npos)
					{
						HOOK_LOG(LL_SYS, L"File: %s has whitelisted name", lower_name.c_str());
						bWhiteListedName = true;
						break;
					}
				}

				/*
				* MOVED TO AFTER OF PATH CHECK DUE THAN CAUSE DELAY/FREEZE
				// Certificate
				if (!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromCurrentPath(lower_name))
				{
					const auto obHasCert = PeSignatureVerifier::HasValidFileCertificate(wstName);
					if (obHasCert.has_value())
					{
						HOOK_LOG(LL_SYS, L"Cert query completed with result: %d", obHasCert.value());

						if (obHasCert.value())
						{
							HOOK_LOG(LL_SYS, L"File: %s has valid certificate", lower_name.c_str());

							// TODO: Check blacklisted certs w/ 	CApplication::Instance().QuarentineInstance()->IsAllowedFileCertificate

							ret = true;
							break;
						}
					}
					else
					{
						HOOK_LOG(LL_ERR, L"Failed to query certificate informations for file %ls", wstName.c_str());
					}
				}
				*/

				// Get module address
				const auto stName = stdext::to_ansi(wstName);
				const auto start_address = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetModuleAddressFromName(wstName.c_str());
				if (!start_address)
				{
					HOOK_LOG(LL_WARN, L"File: %s could not get module address", lower_name.c_str());
					break;
				}

				// Query module
				MEMORY_BASIC_INFORMATION mbi{ 0 };
				if (!g_winAPIs->VirtualQuery(start_address, &mbi, sizeof(mbi)))
				{
					HOOK_LOG(LL_ERR, L"VirtualQuery failed. Error: %u Address: %p", g_winAPIs->GetLastError(), start_address);
					bSuspicious = true;
					break;
				}
				
				std::vector <std::wstring> vecKnownMappedModule;
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SecureLibraryHelper()->GetLoadedModuleList(vecKnownMappedModule);
				const auto vecSelfLoadedModules = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->GetSelfModuleList();
				
				const auto bIsFromWinPath =
					(lower_name.find(L"\\", 0) != std::wstring::npos || lower_name.find(L"/", 0) != std::wstring::npos) &&
					NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(lower_name);

				if (bIsFromWinPath)
				{
					HOOK_LOG(LL_SYS, L"File is from windows path: %s, skipped.", lower_name.c_str());
					ret = true;
					break;
				}

				// Check module loading from unknown path
				if (lower_name.find(L"\\", 0) != std::wstring::npos && // contains path // TODO ADD SLASH AS WELL
					!bIsFromWinPath && // not from windows path
					!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromCurrentPath(lower_name) && // not from current path
					!bWhiteListedName &&
					!stdext::in_vector(vecSelfLoadedModules, (HMODULE)start_address) &&
					!stdext::in_vector(vecKnownMappedModule, lower_name) &&
					!CApplication::Instance().HookScannerInstance()->IsKnownTempModuleName(lower_name))
				{
					HOOK_LOG(LL_ERR, L"Module: '%s' Is not from windows or current path", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_file_unknown_path, lower_name);
					bSuspicious = true;
					break;
				}

				// Certificate
				if (!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromCurrentPath(lower_name))
				{
					const auto obHasCert = PeSignatureVerifier::HasValidFileCertificate(wstName);
					if (obHasCert.has_value())
					{
						HOOK_LOG(LL_SYS, L"Cert query completed with result: %d", obHasCert.value());

						if (obHasCert.value())
						{
							HOOK_LOG(LL_SYS, L"File: %s has valid certificate", lower_name.c_str());

							// TODO: Check blacklisted certs w/ 	CApplication::Instance().QuarentineInstance()->IsAllowedFileCertificate

							ret = true;
							break;
						}
					}
					else
					{
						HOOK_LOG(LL_ERR, L"Failed to query certificate informations for file %ls", wstName.c_str());
					}
				}

				// Manually mapped module?
				if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsLoadedModuleBase((DWORD_PTR)mbi.AllocationBase))
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_not_linked, lower_name);
					bSuspicious = true;
					break;
				}

				/*
				// TODO Check module file hijacked
				DWORD dwHeaderSum = 0, dwCheckSum = 0;
				if (!mbi.AllocationBase ||
					!g_winAPIs->CheckSumMappedFile(mbi.AllocationBase, file_data.size(), &dwHeaderSum, &dwCheckSum))
				{
					HOOK_LOG(LL_ERR, L"CheckSumMappedFile failed. Error: %u Address: %p", g_winAPIs->GetLastError(), start_address);
				}
				else if (dwHeaderSum != dwCheckSum)
				{
					HOOK_LOG(LL_ERR, L"Module: '%s' file is hijacked", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_file_hijacked, lower_name);
					bSuspicious = true;
					break;
				}
				*/

				// Check module PE, do NOT allow images that have writable and executable sections(dynamic code).
				const auto PIDH = (PIMAGE_DOS_HEADER)mbi.AllocationBase;
				if (!PIDH || PIDH->e_magic != IMAGE_DOS_SIGNATURE)
				{
					HOOK_LOG(LL_ERR, L"Module: '%s' has invalid PE header", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_PE_DOS_header_invalid, lower_name);
					bSuspicious = true;
					break;
				}

				const auto pINH = (PIMAGE_NT_HEADERS)((PBYTE)mbi.AllocationBase + PIDH->e_lfanew);
				if (!pINH || pINH->Signature != IMAGE_NT_SIGNATURE)
				{
					HOOK_LOG(LL_ERR, L"Module: '%s' has invalid PE DOS header", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_PE_NT_header_invalid, lower_name);
					bSuspicious = true;
					break;
				}

				const auto pIFH = (PIMAGE_FILE_HEADER)&pINH->FileHeader;
				if (!pIFH)
				{
					HOOK_LOG(LL_ERR, L"Module: '%s' has invalid PE NT header", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_PE_file_header_invalid, lower_name);
					bSuspicious = true;
					break;
				}
				
				const auto nSectionNumber = pIFH->NumberOfSections;
#ifdef _DEBUG
				APP_TRACE_LOG(LL_SYS, L"%u section found!", nSectionNumber);
#endif
			
				if (!nSectionNumber)
				{
					HOOK_LOG(LL_ERR, L"Module: '%s' has invalid PE section count", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_PE_section_count_invalid, lower_name);
					bSuspicious = true;
					break;
				}
				
				const auto pISH = IMAGE_FIRST_SECTION(pINH);
				if (!pISH)
				{
					HOOK_LOG(LL_ERR, L"Module: '%s' has invalid PE first section", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_PE_first_section_invalid, lower_name);
					bSuspicious = true;
					break;
				}
				
				for (std::size_t i = 0; i < nSectionNumber; ++i)
				{
					auto pCurrSection = pISH[i];
#ifdef _DEBUG
					APP_TRACE_LOG(LL_SYS, L"Current section: %hs Base: %p Size: %u",
						(char*)pCurrSection.Name, (DWORD_PTR)mbi.AllocationBase + pCurrSection.VirtualAddress, pCurrSection.Misc.VirtualSize
					);
#endif

					const auto IsMonitored =
						(pCurrSection.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pCurrSection.Characteristics & IMAGE_SCN_MEM_WRITE)
					/* && (pCurrSection.Characteristics & IMAGE_SCN_CNT_CODE) && !(pCurrSection.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) */ ;

					if (IsMonitored)
					{
						HOOK_LOG(LL_ERR, L"Module: '%s' has contain executable&writable section aka. dynamic code, Section index: %u Characteristics: %p",
							lower_name.c_str(), i, pCurrSection.Characteristics
						);

						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_2, Module_PE_dynamic_code, lower_name);
						bSuspicious = true;
						break;
					}
				}
				
				// Module file scan
				auto spFSScanner = CApplication::Instance().ScannerInstance()->FileScanner();
				if (IS_VALID_SMART_PTR(spFSScanner))
				{
					spFSScanner->Scan(lower_name, FILE_SCAN_TYPE_HOOK);
				}

				// Module memory scan
				auto ctx = stdext::make_shared_nothrow<SSectionScanContext>();
				if (IS_VALID_SMART_PTR(ctx))
				{
					ctx->dwBase = (ptr_t)mbi.BaseAddress;
					ctx->dwProcessId = g_winAPIs->GetCurrentProcessId();
					ctx->dwSize = mbi.RegionSize;
					ctx->hProcess = NtCurrentProcess();

					auto spSectionScanner = CApplication::Instance().ScannerInstance()->SectionScanner();
					if (IS_VALID_SMART_PTR(spSectionScanner))
					{
						spSectionScanner->ScanSync(ctx);
					}
				}

				// Module scan
				auto spModuleScanner = CApplication::Instance().ScannerInstance()->ModuleScanner();
				if (IS_VALID_SMART_PTR(spModuleScanner))
				{
					spModuleScanner->ScanSync(lower_name);
				}

				// Scan current thread
				auto dummy = false;
				OnThreadCreated(dwThreadId, hThread, nullptr, dummy);

				// Everything seems fine
				ret = true;
			} while (false);

			HOOK_LOG(LL_SYS, L"Module: %ls analysed in %u ms ret: %d suspicious: %d", wstName.c_str(), timer.diff(), ret ? 1 : 0, bSuspicious ? 1 : 0);
			return ret;
		}

#ifdef _DEBUG
		if (bSuspicious && g_winAPIs->IsDebuggerPresent())
			g_winAPIs->DebugBreak();
#endif

		HOOK_LOG(LL_TRACE, L"Module: %ls already analysed.", wstName.c_str());
		return true;
	}
	bool CAnalyser::OnSectionCreated(HANDLE hFile, ULONG ulSectionAttributes, bool& bSuspicious)
	{
		HOOK_LOG(LL_TRACE, L"Section: %p analyse started!", hFile);

		bSuspicious = false;
		auto ret = false;

		if (__CanAnalyseSection(hFile))
		{
			auto object_name = reinterpret_cast<OBJECT_NAME_INFORMATION*>(CMemHelper::Allocate(4096));
			if (object_name)
			{
				auto timer = CStopWatch <std::chrono::milliseconds>();

				do
				{
					if (!IS_VALID_HANDLE(hFile) || !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hFile))
					{
						HOOK_LOG(LL_ERR, L"Not valid handle: %p", hFile);
						bSuspicious = true;
						break;
					}

					if (ulSectionAttributes != SEC_IMAGE)
					{
#ifdef _DEBUG
						HOOK_LOG(LL_SYS, L"Unallowed attribute: %p", ulSectionAttributes);
#endif
						break;
					}

					auto ulReturnLength = 0UL;
					auto ntStat = g_winAPIs->NtQueryObject(hFile, ObjectNameInformation, object_name, 4096, &ulReturnLength);
					if (!NT_SUCCESS(ntStat))
					{
						HOOK_LOG(LL_ERR, L"NtQueryObject failed with status: %p", ntStat);
						bSuspicious = true;
						break;
					}

					if (!object_name || !object_name->Name.Buffer || !object_name->Name.Length)
					{
						HOOK_LOG(LL_ERR, L"Sanity failed");
						bSuspicious = true;
						break;
					}

					const auto name_dos = std::wstring(object_name->Name.Buffer, object_name->Name.Length);
					if (name_dos.empty())
					{
						HOOK_LOG(LL_ERR, L"Name type conv failed");
						bSuspicious = true;
						break;
					}

					const auto name = CProcessFunctions::DosDevicePath2LogicalPath(name_dos.c_str());
					if (name.empty())
					{
						HOOK_LOG(LL_ERR, L"Path normalize failed");
						bSuspicious = true;
						break;
					}

					HOOK_LOG(LL_SYS, L"Section: %p informations: File: %s IsImage: %d", hFile, name.c_str(), ulSectionAttributes == SEC_IMAGE);

					if (!std::filesystem::exists(name))
					{
						HOOK_LOG(LL_ERR, L"File: %s does not exist", name.c_str());

						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_1, Section_file_not_exist, name);
						bSuspicious = true;
						break;
					}

					// Module scan
					bool dummy;
					OnModuleLoaded(name, NtCurrentThread(), CHECK_TYPE_NtCreateSection, dummy);

					// Everything seems fine
					ret = true;
				} while (false);

				HOOK_LOG(LL_SYS, L"Section: %p analysed in %u ms ret: %d suspicious: %d", hFile, timer.diff(), ret ? 1 : 0, bSuspicious ? 1 : 0);
				
				if (object_name)
				{
					CMemHelper::Free(object_name);
					object_name = nullptr;
				}
				return ret;
			}
		}

#ifdef _DEBUG
		if (bSuspicious && g_winAPIs->IsDebuggerPresent())
			g_winAPIs->DebugBreak();
#endif

		HOOK_LOG(LL_TRACE, L"Section: %p already analysed.", hFile);
		return true;
	}
	bool CAnalyser::OnSectionMapped(LPVOID lpBase, LPVOID lpArbitraryUserPointer, bool& bSuspicious)
	{
		auto ret = false;

		if (!lpBase || !lpArbitraryUserPointer)
			return ret;

		HOOK_LOG(LL_TRACE, L"Section mem: %p analyse started! Arbitrary ptr: %p", lpBase, lpArbitraryUserPointer);

		bSuspicious = false;

		if (__CanAnalyseMappedSection(lpBase))
		{
			auto timer = CStopWatch <std::chrono::milliseconds>();

			do
			{
				MEMORY_BASIC_INFORMATION mbi{ 0 };
				if (!g_winAPIs->VirtualQuery(lpBase, &mbi, sizeof(mbi)))
				{
					HOOK_LOG(LL_ERR, L"VirtualQuery failed. Error: %u Address: %p", g_winAPIs->GetLastError(), lpBase);
					bSuspicious = true;
					break;
				}

				std::wstring w_name{ static_cast<PCWSTR>(lpArbitraryUserPointer) };
				auto lower_name = stdext::to_lower_wide(w_name);
				if (lower_name.empty())
				{
					HOOK_LOG(LL_ERR, L"lpArbitraryUserPointer null name");
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Section mem: %p arbitrary_user_pointer path: %s(%p)", lpBase, lower_name.c_str(), lpArbitraryUserPointer);

				if (!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(lower_name))
				{
					HOOK_LOG(LL_ERR, L"File: %s does not exist", lower_name.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_4, Section_file_not_exist, lower_name);
					bSuspicious = true;
					break;
				}

				// Module scan
				bool dummy;
				OnModuleLoaded(w_name, NtCurrentThread(), CHECK_TYPE_NtMapViewOfSection, dummy);

				// Memory scan
				auto ctx = stdext::make_shared_nothrow<SSectionScanContext>();
				if (IS_VALID_SMART_PTR(ctx))
				{
					ctx->dwBase = (ptr_t)mbi.BaseAddress;
					ctx->dwProcessId = g_winAPIs->GetCurrentProcessId();
					ctx->dwSize = mbi.RegionSize;
					ctx->hProcess = NtCurrentProcess();

					CApplication::Instance().ScannerInstance()->SectionScanner()->ScanSync(ctx);
				}

				// Everything seems fine
				ret = true;
			} while (false);

			HOOK_LOG(LL_SYS, L"Section mem: %p analysed in %u ms ret: %d suspicious: %d", lpBase, timer.diff(), ret ? 1 : 0, bSuspicious ? 1 : 0);
			return ret;
		}

#ifdef _DEBUG
		if (bSuspicious && g_winAPIs->IsDebuggerPresent())
			g_winAPIs->DebugBreak();
#endif

		HOOK_LOG(LL_TRACE, L"Section mem: %p already analysed.", lpBase);
		return true;
	}
	bool CAnalyser::OnExceptionThrowed(PEXCEPTION_RECORD ExceptionInfo, bool& bSuspicious)
	{
		HOOK_LOG(LL_SYS, L"Exception: %p analyse started!", ExceptionInfo);

		bSuspicious = false;
		auto ret = false;

		if (__CanAnalyseException(ExceptionInfo))
		{
			auto timer = CStopWatch <std::chrono::milliseconds>();

			do
			{
				if (!ExceptionInfo || !ExceptionInfo->ExceptionRecord)
				{
					HOOK_LOG(LL_ERR, L"Sanity failed");
					break;
				}

				if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_5, Exception_single_step);
					bSuspicious = true;
					break;
				}

				if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_5, Exception_guard_page);
					bSuspicious = true;
					break;
				}

				if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_5, Exception_breakpoint);
					bSuspicious = true;
					break;
				}

				if (ExceptionInfo->ExceptionRecord->ExceptionAddress)
				{
					if (*(BYTE*)ExceptionInfo->ExceptionAddress == 0xCC)
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_5, Exception_breakpoint_mem);
						bSuspicious = true;
						break;
					}

					DWORD_PTR dwBase = 0;
					if (!CPEFunctions::IsInModule(ExceptionInfo->ExceptionAddress, 1, dwBase))
					{
						CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_5, Exception_not_in_module);
						bSuspicious = true;
						break;
					}

					MEMORY_BASIC_INFORMATION mbi{ 0 };
					if (!g_winAPIs->VirtualQuery(ExceptionInfo->ExceptionAddress, &mbi, sizeof(mbi)))
					{
						HOOK_LOG(LL_ERR, L"VirtualQuery failed. Error: %u Address: %p", g_winAPIs->GetLastError(), ExceptionInfo->ExceptionAddress);
					}
					else
					{
						HOOK_LOG(LL_SYS,
							L"Exception mem: %p base: %p size: %p state: %u protect: %u allocation: %u type: %u",
							ExceptionInfo->ExceptionAddress, mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.AllocationProtect, mbi.Type
						);

						if (mbi.State != MEM_COMMIT)
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_5, Exception_not_committed_mem);
							bSuspicious = true;
							break;
						}

						if (mbi.Protect != mbi.AllocationProtect)
						{
							CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_5, Exception_changed_protection);
							bSuspicious = true;
							break;
						}
					}
				}

				// Everything seems fine
				ret = true;
			} while (false);

			HOOK_LOG(LL_SYS, L"Exception: %p analysed in %u ms ret: %d suspicious: %d", ExceptionInfo, timer.diff(), ret ? 1 : 0, bSuspicious ? 1 : 0);
			return ret;
		}

#ifdef _DEBUG
		if (bSuspicious && g_winAPIs->IsDebuggerPresent())
			g_winAPIs->DebugBreak();
#endif

		HOOK_LOG(LL_SYS, L"Exception: %p already analysed.", ExceptionInfo);
		return true;
	}
	bool CAnalyser::OnConnected(const std::wstring& stTargetAddress, uint16_t wPort, bool& bSuspicious)
	{
		HOOK_LOG(LL_TRACE, L"Connect: %s analyse started!", stTargetAddress.c_str());

		bSuspicious = false;
		auto ret = false;

		if (__CanAnalyseConnection(stTargetAddress))
		{
			auto timer = CStopWatch<std::chrono::milliseconds>();

			do
			{
				if (stTargetAddress == xorstr_(L"127.0.0.1") || stTargetAddress == xorstr_(L"localhost") || stTargetAddress == xorstr_(L"0.0.0.0"))
				{
					HOOK_LOG(LL_SYS, L"localhost connection check skipped");
					ret = true;
					break;
				}

				if (NoMercyCore::CApplication::Instance().DataInstance()->IsLicensedIp(stTargetAddress) == false)
				{
					HOOK_LOG(LL_WARN, L"Unknown connection to: %hs", stTargetAddress.c_str());

					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_6, Connection_unknown_target, stTargetAddress);
					bSuspicious = true;
					break;
				}

				// Everything seems fine
				ret = true;
			} while (false);

			HOOK_LOG(LL_SYS, L"Connect: %s analysed in %u ms ret: %d suspicious: %d", stTargetAddress.c_str(), timer.diff(), ret ? 1 : 0, bSuspicious ? 1 : 0);
			return ret;
		}

#ifdef _DEBUG
		if (bSuspicious && g_winAPIs->IsDebuggerPresent())
			g_winAPIs->DebugBreak();
#endif

		HOOK_LOG(LL_TRACE, L"Connect: %s already analysed.", stTargetAddress.c_str());
		return true;
	}
	bool CAnalyser::OnWndProcHooked(HWND hWnd, int nIndex, LONG dwNewLong, bool& bSuspicious)
	{
		HOOK_LOG(LL_SYS, L"Window long: %p analyse started! Index: %d NewValue: %p", hWnd, nIndex, dwNewLong);

		bSuspicious = false;
		auto ret = false;

		if (__CanAnalyseWindow(hWnd))
		{
			auto timer = CStopWatch<std::chrono::milliseconds>();

			do
			{
				if (!dwNewLong || nIndex != GWL_WNDPROC || !CApplication::Instance().WatchdogInstance()->IsWatchdogWindow(hWnd))
					break;

				wchar_t wszFileName[2048]{ L'\0' };
				if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), (LPVOID)dwNewLong, wszFileName, 2048 || !wcslen(wszFileName)))
				{
					HOOK_LOG(LL_ERR, L"GetMappedFileNameA failed. Error: %u Address: %p", g_winAPIs->GetLastError(), dwNewLong);
					bSuspicious = true;
					break;
				}
				const auto stLowerFilename = stdext::to_lower_wide(wszFileName);

				HOOK_LOG(LL_SYS, L"Window hook owner module: %s", wszFileName);

				const auto stAntiFilename = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiFullName();
				const auto stLowerAntiFilename = stdext::to_lower_wide(stAntiFilename);

				if (stLowerFilename != stLowerAntiFilename.c_str())
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_7, Window_long_unknown_module, stLowerFilename);
					bSuspicious = true;
					break;
				}
				
				// Everything seems fine
				ret = true;
			} while (false);

			HOOK_LOG(LL_SYS, L"Window long: %p analysed in %u ms ret: %d suspicious: %d", hWnd, timer.diff(), ret ? 1 : 0, bSuspicious ? 1 : 0);
			return ret;
		}

#ifdef _DEBUG
		if (bSuspicious && g_winAPIs->IsDebuggerPresent())
			g_winAPIs->DebugBreak();
#endif

		HOOK_LOG(LL_SYS, L"Window long: %p already analysed.", hWnd);
		return true;
	}
	bool CAnalyser::OnModuleRequested(const std::wstring& wstName, bool& bSuspicious)
	{
		// HOOK_LOG(LL_SYS, L"Module request: %ls analyse started!", wstName.c_str());

		bSuspicious = false;
		auto ret = true;

		if (__CanAnalyseModuleRequest(wstName))
		{
			auto timer = CStopWatch<std::chrono::milliseconds>();

			const auto stLowerName = stdext::to_lower_wide(wstName);
			const auto szAntiFilename = NoMercyCore::CApplication::Instance().DataInstance()->GetAntiFileName();
			const auto szLowerAntiFilename = stdext::to_lower_wide(szAntiFilename);

			/*
			if (wcsstr(stLowerName.c_str(), szLowerAntiFilename.c_str()))
			{
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_8, Modulerequest_anticheat);
				bSuspicious = true;
				ret = false;
			}
			*/
			if (wcsstr(stLowerName.c_str(), xorstr_(L"python2")))
			{
				CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_8, Modulerequest_python);
				bSuspicious = true;
				ret = false;
			}

#ifdef _DEBUG
			if (bSuspicious && g_winAPIs->IsDebuggerPresent())
				g_winAPIs->DebugBreak();
#endif
			
			HOOK_LOG(LL_SYS, L"Module request: %s analysed in %u ms ret: %d suspicious: %d", wstName.c_str(), timer.diff(), ret ? 1 : 0, bSuspicious ? 1 : 0);
		}

		return ret;
	}
	bool CAnalyser::OnDelayExecution(bool bAlertable, LONGLONG llDelay, DWORD dwCurrentTID, LPVOID lpCaller, bool& bSuspicious)
	{
		bSuspicious = false;
		auto ret = false;

		if (__CanAnalyseDelayExecution(lpCaller))
		{
			HOOK_LOG(LL_SYS, L"Delay execution: %p analyse started! Interval: %lld Alertable: %d TID: %u", lpCaller, llDelay / -10000, bAlertable ? 1 : 0, dwCurrentTID);
			
			auto timer = CStopWatch<std::chrono::milliseconds>();

			do
			{
				if (llDelay == INFINITE)
				{
					HOOK_LOG(LL_CRI, L"INFINITE sleep detected for: %u", dwCurrentTID);
				}

				wchar_t wszFileName[2048]{ L'\0' };
				if (!g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), lpCaller, wszFileName, 2048))
				{
					HOOK_LOG(LL_ERR, L"GetMappedFileNameA failed. Error: %u Address: %p", g_winAPIs->GetLastError(), lpCaller);
					bSuspicious = true;
					break;
				}
				HOOK_LOG(LL_SYS, L"Delay execution owner module: %s", wszFileName);

				if (bAlertable)
				{
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_HOOK_9, Delayexecution_alertable, wszFileName);
					bSuspicious = true;
					break;
				}

				auto dwCaller = (DWORD_PTR)lpCaller;

				auto sleep_ptr = (DWORD_PTR)g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("SleepEx"));
				auto addr_dif = dwCaller - sleep_ptr;
				if (sleep_ptr && addr_dif < 0xFF)
				{
					HOOK_LOG(LL_SYS, L"Delay execution from kernel32!SleepEx");
					break;
				}

				sleep_ptr = (DWORD_PTR)g_winAPIs->GetProcAddress(g_winModules->hKernel32, xorstr_("Sleep"));
				addr_dif = dwCaller - sleep_ptr;
				if (sleep_ptr && addr_dif < 0xFF)
				{
					HOOK_LOG(LL_SYS, L"Delay execution from kernel32!Sleep");
					break;
				}

				if (g_winModules->hKernelbase)
				{
					sleep_ptr = (DWORD_PTR)g_winAPIs->GetProcAddress(g_winModules->hKernelbase, xorstr_("SleepEx"));
					addr_dif = dwCaller - sleep_ptr;
					if (sleep_ptr && addr_dif < 0xFF)
					{
						HOOK_LOG(LL_SYS, L"Delay execution from kernelbase!SleepEx");
						break;
					}

					sleep_ptr = (DWORD_PTR)g_winAPIs->GetProcAddress(g_winModules->hKernelbase, xorstr_("Sleep"));
					addr_dif = dwCaller - sleep_ptr;
					if (sleep_ptr && addr_dif < 0xFF)
					{
						HOOK_LOG(LL_SYS, L"Delay execution from kernelbase!Sleep");
						break;
					}
				}

				if (NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFromWindowsPath(wszFileName))
				{
					if (wcsstr(wszFileName, xorstr_(L"kernel32.dll")) || wcsstr(wszFileName, xorstr_(L"kernelbase.dll")))
					{
						HOOK_LOG(LL_SYS, L"Delay execution from trusted source module: %s", wszFileName);
						break;
					}
				}

				// Everything seems fine
				ret = true;
			} while (false);

			// HOOK_LOG(LL_SYS, L"Delay execution: %p analysed in %u ms ret: %d suspicious: %d", lpCaller, timer.diff(), ret ? 1 : 0, bSuspicious ? 1 : 0);
			return ret;
		}

#ifdef _DEBUG
		if (bSuspicious && g_winAPIs->IsDebuggerPresent())
			g_winAPIs->DebugBreak();
#endif
		
		// HOOK_LOG(LL_SYS, L"Delay execution: %p already analysed.", lpCaller);
		return true;
	}
	bool CAnalyser::IsApcAllowed(PVOID ApcRoutine)
	{
		if (CApcRoutinesStorage::Instance().IsAllowed(ApcRoutine))
			return true;

		if (CApcRoutinesStorage::Instance().IsDenied(ApcRoutine))
			return false;

		if (CApplication::Instance().FilterMgrInstance()->IsAddressInKnownModule((DWORD_PTR)ApcRoutine))
			return true;

		if (CApplication::Instance().FilterMgrInstance()->IsKnownMemory((DWORD_PTR)ApcRoutine))
			return true;
		
		return false;
	}
};
