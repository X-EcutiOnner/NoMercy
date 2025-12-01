#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ScannerInterface.hpp"
#include "../Common/Quarentine.hpp"
#include "../Helper/PatternScanner.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/Pe.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/FileVersion.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include "../../../Common/FilePtr.hpp"
#include <tlsh/tlsh.h>



namespace NoMercy
{
	std::vector <std::wstring> ExtractStrings(uint8_t* lpFileBuffer, std::size_t cbFileBufferSize, DWORD dwMinLength = 6)
	{
		std::vector <std::wstring> strings{};
		auto fnAddStringToVec = [&strings](const std::wstring& wstString) {
//			if (!stdext::in_vector(strings, wstString)) // rip cpu
				strings.push_back(wstString);
		};

		DWORD dwStringStart = 0;
		for (DWORD idx = 0; idx < cbFileBufferSize; idx++)
		{
			if (!(lpFileBuffer[idx] >= 0x20 && lpFileBuffer[idx] <= 0x7F))
			{
				DWORD dwStringLength = idx - dwStringStart;
				if (dwStringLength >= dwMinLength)
				{
					fnAddStringToVec(
						stdext::to_wide(std::string{ PCHAR(LPVOID(lpFileBuffer)) + dwStringStart, dwStringLength })
					);
				}

				dwStringStart = idx + 1;
			}
		}

		auto dwStringLength = cbFileBufferSize - dwStringStart;
		if (dwStringLength >= dwMinLength)
		{
			fnAddStringToVec(
				stdext::to_wide(std::string{ PCHAR(LPVOID(lpFileBuffer)) + dwStringStart, dwStringLength })
			);
		}

		dwStringStart = 0;
		auto mem{ reinterpret_cast<PWCHAR>(LPVOID(lpFileBuffer)) };
		for (DWORD idx = 0; 2 * idx < cbFileBufferSize; idx++)
		{
			if (!(mem[idx] >= 0x20 && mem[idx] < 0x7E))
			{
				dwStringLength = idx - dwStringStart;
				if (dwStringLength >= dwMinLength)
				{
					fnAddStringToVec(
						std::wstring{ PWCHAR(LPVOID(lpFileBuffer)) + dwStringStart, dwStringLength }
					);
				}

				dwStringStart = idx + 1;
			}
		}

		dwStringLength = cbFileBufferSize / 2 - dwStringStart;
		if (dwStringLength >= dwMinLength && cbFileBufferSize / 2 > dwStringStart)
		{
			fnAddStringToVec(
				std::wstring{ mem + dwStringStart, dwStringLength }
			);
		}

		return strings;
	}

	static inline std::vector <std::wstring> ExtractFilePaths(const std::vector <std::wstring>& strings)
	{
		std::vector <std::wstring> filepaths{};
		std::wregex regex{ xorstr_(L"[a-zA-Z]:([/\\\\][a-zA-Z0-9(). @_-]+)+") };
		
		for (const auto& string : strings)
		{
			std::wsmatch match{};
			if (std::regex_search(string, match, regex))
			{
				for (const auto& filename : match)
				{
					if (std::filesystem::exists(filename.str()))
					{
						filepaths.emplace_back(filename.str());
					}
				}
			}
		}
		
		return filepaths;
	}
	static inline std::vector <std::wstring> ExtractRegistryKeys(const std::vector <std::wstring>& strings)
	{
		static auto CheckKeyExists = [](HKEY hive, const std::wstring& name) {
			auto wLowerPath = stdext::to_lower_wide(name);

			HKEY hKey{};
			const auto bWoW64 = stdext::is_wow64() || wLowerPath.find(xorstr_(L"wow6432node")) != std::wstring::npos;
			const auto lStatus = g_winAPIs->RegOpenKeyExW(hive, name.c_str(), 0, KEY_READ | KEY_NOTIFY | (bWoW64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &hKey);
			if (lStatus == ERROR_ACCESS_DENIED)
				return true;

			if (lStatus == ERROR_SUCCESS)
			{
				g_winAPIs->RegCloseKey(hKey);
				return true;
			}

			return false;
		};
		
		static std::map <HKEY, std::wstring> vHives{
			{HKEY_LOCAL_MACHINE, L"HKEY_LOCAL_MACHINE"},
			{HKEY_CLASSES_ROOT, L"HKEY_CLASSES_ROOT"},
			{HKEY_CURRENT_USER, L"HKEY_CURRENT_USER"},
			{HKEY_USERS, L"HKEY_USERS"},
			{HKEY_CURRENT_CONFIG, L"HKEY_CURRENT_CONFIG"},
		};

		std::vector <std::wstring> keys{};
		std::wregex regex{ xorstr_(L"(system|software)([/\\\\][a-zA-Z0-9\\. @_-]+)+") };
		
		for (const auto& string : strings)
		{
			std::wsmatch match{};
			const auto lower = stdext::to_lower_wide(string);
			if (std::regex_search(lower, match, regex))
			{
				for (const auto& keyname : match)
				{
					for (auto hive : vHives)
					{
						if (CheckKeyExists(hive.first, keyname.str()))
						{
							keys.emplace_back(hive.second + xorstr_(L"\\") + keyname.str());
						}
					}
				}
			}
		}
		return keys;
	}


	static bool CheckFilePatterns(const std::wstring& stFileName, LPVOID lpFileBuffer, std::size_t cbFileBufferSize)
	{
		auto upPatternScanner = stdext::make_unique_nothrow<CPatternScanner>();
		if (!IS_VALID_SMART_PTR(upPatternScanner))
		{
			APP_TRACE_LOG(LL_ERR, L"Pattern scanner allocation failed!");
			return false;
		}

		const auto vecFileBlacklist = CApplication::Instance().QuarentineInstance()->FileQuarentine()->GetBlacklist();
		for (const auto& [obj, opts] : vecFileBlacklist)
		{
			if (!obj.blacklisted_pattern.empty())
			{
				const auto pattern = Pattern(obj.blacklisted_pattern, PatternType::Address);
				if (upPatternScanner->findPatternSafe(lpFileBuffer, cbFileBufferSize, pattern))
				{
					SCANNER_LOG(LL_ERR, L"Found file pattern: %s", obj.blacklisted_pattern.c_str());

					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(EFileScanCheatEvents::FILE_SCAN_PATTERN_CHECK), obj.blacklisted_pattern
					);
					return false;
				}
			}
		}

		return true;
	}
	
	static bool CheckFileRegionHashes(const std::wstring& stFileName, const uint8_t* lpFileBuffer)
	{
		auto pIDH = (IMAGE_DOS_HEADER*)(&lpFileBuffer[0]);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto pINH = (IMAGE_NT_HEADERS*)(&lpFileBuffer[pIDH->e_lfanew]);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;

		std::vector <IMAGE_SECTION_HEADER*> sections;
		sections.reserve(pINH->FileHeader.NumberOfSections);

		auto pSection = (IMAGE_SECTION_HEADER*)(&lpFileBuffer[pIDH->e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(uint32_t) + pINH->FileHeader.SizeOfOptionalHeader]);
		for (uint16_t i = 0; i < pINH->FileHeader.NumberOfSections; ++i, ++pSection)
		{
			if ((pSection->Characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE)) == 0 && pSection->NumberOfRelocations == 0)
			{
				sections.push_back(pSection);
			}
		}

		uint32_t BytesPerBlock = 1024 * 512;
		for (auto iter : sections)
		{
			uint32_t offset = 0;
			while (offset < iter->SizeOfRawData)
			{
				uint32_t len = BytesPerBlock;
				if (offset + len > iter->SizeOfRawData)
					len = iter->SizeOfRawData - offset;

				wchar_t wszMappedFileName[2048]{ L'\0' };
				g_winAPIs->GetMappedFileNameW(NtCurrentProcess(), (LPVOID)&lpFileBuffer[iter->PointerToRawData + offset], wszMappedFileName, 2048);

				const auto stBuffer = std::string((const char*)&lpFileBuffer[iter->PointerToRawData + offset], len);
				const auto stCurrSectionHash = stdext::to_wide(NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetSHA256(stBuffer));

#ifdef _DEBUG
				SCANNER_LOG(LL_SYS, L"Current region base: %p Size: %u Checksum: %s Characteristics: %p",
					iter->PointerToRawData + offset, len, stCurrSectionHash.c_str(), iter->Characteristics
				);
#endif
				
				const auto vecMemBlacklist = CApplication::Instance().QuarentineInstance()->MemoryQuarentine()->GetBlacklist();
				for (const auto& [obj, opts] : vecMemBlacklist)
				{
					if (obj.region_hash == stCurrSectionHash /* && obj.region_charecteristics == iter->Characteristics */)
					{
						SCANNER_LOG(LL_ERR, L"Found blacklisted region: %s", obj.region_hash.c_str());
						
						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(EFileScanCheatEvents::FILE_SCAN_BLACKLISTED_REGION_HASH), obj.region_hash
						);
						return false;
					}
				}

				offset += len;
			}
		}

		return true;
	}

	static bool CheckFilePEInformations(const std::wstring& stFileName, LPVOID lpFileBuffer, std::size_t cbFileBufferSize)
	{
		SCANNER_LOG(LL_SYS, L"PE information scanner has been started! Target: %s", stFileName.c_str());

		const auto pe32 = Pe::Pe32::fromFile(lpFileBuffer);
		const auto pe64 = Pe::Pe64::fromFile(lpFileBuffer);
		if (!pe32.valid() && !pe64.valid())
		{
#ifdef _DEBUG
			SCANNER_LOG(LL_ERR, L"Target file: %s is not valid PE file", stFileName.c_str());
#endif
			return false;
		}

#ifdef _DEBUG
		SCANNER_LOG(LL_SYS, L"Target file: %s succesfully parsed! Base: %p Size: %p", stFileName.c_str(), lpFileBuffer, cbFileBufferSize);
#endif

		const auto vecMemBlacklist = CApplication::Instance().QuarentineInstance()->MemoryQuarentine()->GetBlacklist();

		auto bHasTextSection = false;
		auto iVMPCounter = 0;
		auto iEnigmaCounter = 0;
		auto iMpressCounter = 0;
		auto iUpxCounter = 0;
		auto iThemidaCounter = 0;
		auto iMoleboxCounter = 0;
		auto iYodaCounter = 0;
		auto iShieldenCounter = 0;

		auto nIndex = 0u;
		for (const auto& section : pe64.valid() ? pe64.sections() : pe32.sections())
		{
			nIndex++;
			
			std::string stName(reinterpret_cast<const char*>(section.Name), sizeof(section.Name));
			while (!stName.empty() && !stName.back()) stName.pop_back();
			
			const auto dwBase = (DWORD_PTR)lpFileBuffer + section.VirtualAddress;
			const auto dwSize = section.SizeOfRawData;
			
#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Current section: %hs Base: %p Size: %u Raw size: %u",
				stName.c_str(), dwBase, section.Misc.VirtualSize, section.SizeOfRawData
			);
#endif
			
			auto dwOldProtect = 0UL;
			if (!g_winAPIs->VirtualProtect((LPVOID)dwBase, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			{
#ifdef _DEBUG
				SCANNER_LOG(LL_WARN, L"Failed to change memory protection for section: %s Error: %u", stName.c_str(), g_winAPIs->GetLastError());
#endif
				continue;
			}

			const auto dwChecksum = CPEFunctions::CalculateMemChecksumFast((LPVOID)dwBase, dwSize);
			const auto stSectionName = std::string((char*)dwBase, dwSize);
			const auto fEntropy = CApplication::Instance().FunctionsInstance()->GetShannonEntropy(stSectionName);

#ifdef _DEBUG
			SCANNER_LOG(LL_SYS, L"Section misc informations; Checksum: %p Entropy: %.2f", dwChecksum, fEntropy);
#endif

			auto stRevSectionName = stName;
			if (!stRevSectionName.empty())
				std::reverse(stRevSectionName.begin(), stRevSectionName.end());

			if (!stRevSectionName.empty() && (stRevSectionName.at(0) == '0' || stRevSectionName.at(0) == '1'))
				iVMPCounter++;

			if (stName.empty())
				iEnigmaCounter++;

			if (stName == xorstr_("MPRESS"))
				iMpressCounter++;

			if (stName.find(xorstr_("UPX")) != std::string::npos)
				iUpxCounter++;

			if (stName == xorstr_(".yP"))
				iYodaCounter++;

			if (stName == xorstr_(".sedata"))
				iShieldenCounter++;

			if (stName.size() == 1 && std::to_string(nIndex) == stRevSectionName)
				iMoleboxCounter++;

			if (stName.find(xorstr_("themida")) != std::string::npos)
				iThemidaCounter++;

			// Entropy check
			if (fEntropy >= 8.0f)
			{
				SCANNER_LOG(LL_ERR, L"Found suspicious section: %s Entropy: %.2f", stName.c_str(), fEntropy);

				const auto lstWhitelist = std::vector <std::wstring>{
					xorstr_(L"atieah32.exe"),
					xorstr_(L"cmd.exe"),
				};
				auto bIsWhitelisted = false;
				for (const auto& stWhitelisted : lstWhitelist)
				{
					if (stFileName.find(stWhitelisted) != std::wstring::npos)
					{
						bIsWhitelisted = true;
						break;
					}
				}
				if (!bIsWhitelisted)
				{
					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(EFileScanCheatEvents::FILE_SCAN_SUSPICIOUS_SECTION_ENTROPY), stFileName
					);
				}
			}

			// OEP check
			const auto stLowerName = stdext::to_lower_ansi(stName);
			if (stLowerName == xorstr_(".text"))
			{
				bHasTextSection = true;

				/*
				auto bOEPInsideText = false;
				if (pe64.valid())
				{
					if (pe64.headers().nt()->OptionalHeader.AddressOfEntryPoint >= section.VirtualAddress &&
						pe64.headers().nt()->OptionalHeader.AddressOfEntryPoint <= (section.VirtualAddress + section.Misc.VirtualSize))
					{
						bOEPInsideText = true;
					}
				}
				else
				{
					if (pe32.headers().nt()->OptionalHeader.AddressOfEntryPoint >= section.VirtualAddress &&
						pe32.headers().nt()->OptionalHeader.AddressOfEntryPoint <= (section.VirtualAddress + section.Misc.VirtualSize))
					{
						bOEPInsideText = true;
					}
				}
				
				if (!bOEPInsideText)
				{
					SCANNER_LOG(LL_ERR, L"OEP is not in .text section!");
					
					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_OEP_NOT_IN_TEXT_SECTION), stFileName
					);
					return false;
				}
				*/
			}

			// Characteristic check
			if (section.Characteristics == 0x60000060 || section.Characteristics == 0xE0000060 ||
				section.Characteristics == 0xE0000040 || section.Characteristics == 0x68000060 ||
				section.Characteristics == 0xe2000060)
			{
				auto bSkip = false;
				if (stFileName.find(xorstr_(L"git.exe")) != std::wstring::npos)
					bSkip = true;

				if (!bSkip)
				{
					SCANNER_LOG(LL_ERR, L"Blacklisted section characteristic: %p detected (VMProtect) for section: %s", section.Characteristics, stName.c_str());

					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_BLACKLISTED_SECTION_CHARACTERISTIC),
						fmt::format(xorstr_(L"c:{0}|s:{1}|f:{2}"), section.Characteristics, stdext::to_wide(stName), stFileName)
					);
					return false;
				}
			}

			// Blacklisted section check
			for (const auto& [obj, opts] : vecMemBlacklist)
			{
				if (obj.region_size == dwSize && obj.region_checksum == dwChecksum && obj.region_charecteristics == section.Characteristics)
				{
					SCANNER_LOG(LL_ERR, L"Blacklisted section: %s detected", stName.c_str());
					
					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_BLACKLISTED_SECTION),
						fmt::format(xorstr_(L"s:{0}|f:{1}"), stdext::to_wide(stName), stFileName)
					);
					return false;
				}
			}
			
			g_winAPIs->VirtualProtect((LPVOID)dwBase, dwSize, dwOldProtect, &dwOldProtect);
		}

		if (!bHasTextSection)
		{
			std::vector <std::wstring> vecWhitelist{
				xorstr_(L"hal.dll"),
				xorstr_(L"nvcameraallowlisting32.dll"),
				xorstr_(L"igd12um32xel.dll"),
				xorstr_(L"igdumdim32.dll")
			};
			
			if (!stdext::in_vector(vecWhitelist, stFileName))
			{
				SCANNER_LOG(LL_ERR, L"No .text section found!");

				CApplication::Instance().OnCheatDetect(
					CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_NO_TEXT_SECTION), stFileName
				);
				return false;
			}
		}

		if (iVMPCounter == 2)
		{
			SCANNER_LOG(LL_ERR, L"VMProtect detected!");
			
			CApplication::Instance().OnCheatDetect(
				CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_VMPROTECT), stFileName
			);
			return false;
		}
		if (iEnigmaCounter >= 3)
		{
			SCANNER_LOG(LL_ERR, L"Enigma detected!");
			
			CApplication::Instance().OnCheatDetect(
				CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_ENIGMA), stFileName
			);
			return false;
		}
		if (iMpressCounter)
		{
			SCANNER_LOG(LL_ERR, L"Mpress detected!");
			
			CApplication::Instance().OnCheatDetect(
				CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_MPRESS), stFileName
			);
			return false;
		}
		if (iUpxCounter)
		{
			SCANNER_LOG(LL_ERR, L"UPX detected!");
			
			CApplication::Instance().OnCheatDetect(
				CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_UPX), stFileName
			);
			return false;
		}
		if (iYodaCounter)
		{
			SCANNER_LOG(LL_ERR, L"Yoda detected!");
			
			CApplication::Instance().OnCheatDetect(
				CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_YODA), stFileName
			);
			return false;
		}
		if (iShieldenCounter)
		{
			SCANNER_LOG(LL_ERR, L"Shielden detected!");
			
			CApplication::Instance().OnCheatDetect(
				CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_SHIELDEN), stFileName
			);
			return false;
		}
		if (iMoleboxCounter)
		{
			SCANNER_LOG(LL_ERR, L"Molebox detected!");
			
			CApplication::Instance().OnCheatDetect(
				CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_MOLEBOX), stFileName
			);
			return false;
		}
		if (iThemidaCounter)
		{
			SCANNER_LOG(LL_ERR, L"Themida detected!");
			
			CApplication::Instance().OnCheatDetect(
				CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_THEMIDA), stFileName
			);
			return false;
		}

		// Export Directory parsing
		if (pe64.valid())
		{
			for (const auto& exp : pe64.exports())
			{
				if (!exp.valid() || !exp.hasName())
					continue;

				for (const auto& [obj, opts] : vecMemBlacklist)
				{
					if (obj.eat_base == (DWORD_PTR)exp.address() && obj.eat_ordinal == exp.ordinal())
					{
						SCANNER_LOG(LL_ERR, L"Blacklisted export(1): %s detected", exp.name());

						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_BLACKLISTED_EXPORT),
							fmt::format(xorstr_(L"e:{0}|f:{1}"), stdext::to_wide(exp.name()), stFileName)
						);
						return false;
					}

					const auto stExportName = stdext::to_ansi(obj.export_name);
					if (stExportName == exp.name())
					{
						SCANNER_LOG(LL_ERR, L"Blacklisted export(2): %s detected", exp.name());

						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_BLACKLISTED_EXPORT),
							fmt::format(xorstr_(L"e:{0}|f:{1}"), stdext::to_wide(exp.name()), stFileName)
						);
						return false;
					}
				}
			}
		}
		else
		{
			for (const auto& exp : pe32.exports())
			{
				if (!exp.valid() || !exp.hasName())
					continue;

				for (const auto& [obj, opts] : vecMemBlacklist)
				{
					if (obj.eat_base == (DWORD_PTR)exp.address() && obj.eat_ordinal == exp.ordinal())
					{
						SCANNER_LOG(LL_ERR, L"Blacklisted export(1): %s detected", exp.name());

						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_BLACKLISTED_EXPORT),
							fmt::format(xorstr_(L"e:{0}|f:{1}"), stdext::to_wide(exp.name()), stFileName)
						);
						return false;
					}

					const auto stExportName = stdext::to_ansi(obj.export_name);
					if (stExportName == exp.name())
					{
						SCANNER_LOG(LL_ERR, L"Blacklisted export(2): %s detected", exp.name());

						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_BLACKLISTED_EXPORT),
							fmt::format(xorstr_(L"e:{0}|f:{1}"), stdext::to_wide(exp.name()), stFileName)
						);
						return false;
					}
				}
			}
		}
		
		const auto dwFileChecksum = CPEFunctions::CalculateMemChecksumFast(lpFileBuffer, cbFileBufferSize);
#ifdef _DEBUG
		SCANNER_LOG(LL_SYS, L"File: %s checksum generated: %p", stFileName.c_str(), dwFileChecksum);
#endif
		
		if (dwFileChecksum)
		{
			for (const auto& [obj, opts] : vecMemBlacklist)
			{
				if (obj.mapped_file_checksum == dwFileChecksum)
				{
					SCANNER_LOG(LL_ERR, L"File: %s checksum detected: %p", stFileName.c_str(), dwFileChecksum);

					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_CHECKSUM), stFileName
					);
					return false;
				}
			}
		}
		return false;
	}

	static bool CheckFileCertificates(const std::wstring& wstFileName, EFileScanTypes fileType, LPVOID lpFileBuffer)
	{
		auto bRet = false;
//		PVOID OldValue = nullptr;
		
		do
		{
//			// Disables file system redirection for the calling thread.
//			if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
//			{
//				SCANNER_LOG(LL_ERR, L"Failed to disable file system redirection!");
//				break;
//			}
			
			if (stdext::is_debug_env())
			{
				if (wstFileName.find(xorstr_(L"nomercy")) != std::wstring::npos)
				{
					SCANNER_LOG(LL_SYS, L"Skipping NoMercy file: %s", wstFileName.c_str());
					break;
				}
			}

			const auto obHasCert = PeSignatureVerifier::HasValidFileCertificate(wstFileName);
			if (obHasCert.has_value())
			{
				SCANNER_LOG(LL_SYS, L"Cert query completed for: %ls with result: %d", wstFileName.c_str(), obHasCert.value());
				if (!obHasCert.value())
				{
					SCANNER_LOG(LL_WARN, L"File: %ls does not exist any certificate", wstFileName.c_str());
					if (fileType == FILE_SCAN_TYPE_MODULE)
					{
						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_CERTIFICATE_EXIST), wstFileName
						);
						break;
					}
				}
			}
			else
			{
				SCANNER_LOG(LL_ERR, L"Could NOT check certificate for file: %ls Error: %u", wstFileName.c_str(), g_winAPIs->GetLastError());
				break;
			}

			std::vector <SCertContext> vecCerts;
			const auto obHasEmbeddedSign = FileVerifier::GetEmbeddedCertificates(wstFileName, vecCerts);
			if (obHasEmbeddedSign.has_value())
			{
				if (!obHasEmbeddedSign.value())
				{
					SCANNER_LOG(LL_ERR, L"File: %s any certificate does not exist", wstFileName.c_str());

					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_CERTIFICATE_QUERY), wstFileName
					);
					break;
				}
			}
			else
			{
				SCANNER_LOG(LL_WARN, L"File: %s certificate query failed", wstFileName.c_str());
				break;
			}
		
			std::wstring wstProvider;
			const auto dwSignCheck = PeSignatureVerifier::CheckFileSignature(wstFileName, false); // TODO: convertSignInfo(lRetVal)
			if (dwSignCheck != 0)
			{
				SCANNER_LOG(LL_ERR, L"File: %s certificate verifaction failed: %u/%u", wstFileName.c_str(), dwSignCheck, g_winAPIs->GetLastError());
				CApplication::Instance().OnCheatDetect(
					CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_CERTIFICATE_VERIFACTION), wstFileName
				);
				break;
			}
				
			for (const auto& pkCert : vecCerts)
			{
				const auto vecBlacklist = CApplication::Instance().QuarentineInstance()->FileQuarentine()->GetBlacklist();
				for (const auto& [obj, opts] : vecBlacklist)
				{
					if (obj.cert_serial == pkCert.wstSerialNum)
					{
						SCANNER_LOG(LL_ERR, L"File: %s certificate detected: %s", wstFileName.c_str(), pkCert.wstSerialNum.c_str());

						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_CERTIFICATE_CHECK),
							fmt::format(xorstr_(L"t:1|f:{0}"), wstFileName)
						);
						break;
					}

					if (obj.cert_issuer == pkCert.wstIssuer)
					{
						SCANNER_LOG(LL_ERR, L"File: %s certificate detected: %ls", wstFileName.c_str(), pkCert.wstIssuer.c_str());

						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_CERTIFICATE_CHECK),
							fmt::format(xorstr_(L"t:2|f:{0}"), wstFileName)
						);
						break;
					}

					if (obj.cert_subject == pkCert.wstSubject)
					{
						SCANNER_LOG(LL_ERR, L"File: %s certificate detected: %ls", wstFileName.c_str(), pkCert.wstSubject.c_str());

						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_CERTIFICATE_CHECK),
							fmt::format(xorstr_(L"t:3|f:{0}"), wstFileName)
						);
						break;
					}

					if (obj.cert_provider == wstProvider)
					{
						SCANNER_LOG(LL_ERR, L"File: %s certificate detected: %ls", wstFileName.c_str(), wstProvider.c_str());

						CApplication::Instance().OnCheatDetect(
							CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_CERTIFICATE_CHECK),
							fmt::format(xorstr_(L"t:4|f:{0}"), wstFileName)
						);
						break;
					}
				}
			}

			bRet = true;
		} while (FALSE);

//		if (OldValue)
//		{
//			// Restore file system redirection for the calling thread.
//			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);
//		}
		
		return bRet;
	}

	static bool CheckFileBasicInformations(const std::wstring& stFileName, LPVOID lpFileBuffer, std::size_t cbFileBufferSize)
	{
		SCANNER_LOG(LL_SYS, L"File basic information scan started! File: %s", stFileName.c_str());

		const auto stTLSH = stdext::to_ansi(NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileTLSH(stFileName));
		if (stTLSH.empty())
		{
			SCANNER_LOG(LL_ERR, L"TLSH hash generation failed!");
			return false;
		}
		else
		{
			const auto spFileTLSH = stdext::make_shared_nothrow<Tlsh>();
			if (!IS_VALID_SMART_PTR(spFileTLSH))
			{
				SCANNER_LOG(LL_ERR, L"TLSH allocation failed!");
				return false;
			}

			const auto ret = spFileTLSH->fromTlshStr(stTLSH.c_str());
			if (ret != 0)
			{
				SCANNER_LOG(LL_ERR, L"TLSH parsing failed! Ret: %d", ret);
			}
			else
			{
				if (!spFileTLSH->isValid())
				{
					SCANNER_LOG(LL_ERR, L"Current TLSH is not valid!");
				}
				else
				{
					const auto vecBlacklist = CApplication::Instance().QuarentineInstance()->FileQuarentine()->GetBlacklist();
					for (const auto& [obj, opts] : vecBlacklist)
					{
						if (!obj.tlsh.empty())
						{
							const auto upTLSH = stdext::make_unique_nothrow<Tlsh>();
							if (!IS_VALID_SMART_PTR(upTLSH))
							{
								SCANNER_LOG(LL_ERR, L"TLSH allocation failed!");
								return false;
							}

							const auto tlsh = stdext::to_ansi(obj.tlsh);
							const auto hash_ret = upTLSH->fromTlshStr(tlsh.c_str());
							if (hash_ret != 0)
							{
								SCANNER_LOG(LL_ERR, L"TLSH parsing failed! Ret: %d", hash_ret);
								continue;
							}

							if (!upTLSH->isValid())
							{
								SCANNER_LOG(LL_ERR, L"Current TLSH is not valid!");
								continue;
							}

							const auto diff = upTLSH->totalDiff(spFileTLSH.get());
							SCANNER_LOG(LL_SYS, L"TLSH diff: %d", diff);

							if (diff < 30)
							{
								SCANNER_LOG(LL_ERR, L"TLSH: %s similarity detected: %d with: %s", obj.tlsh.c_str(), diff, stTLSH.c_str());
								
								CApplication::Instance().OnCheatDetect(
									CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_TLSH_DIFF),
									fmt::format(xorstr_(L"t:{0}|t2:{1}|d:{2}|f:{3}"), obj.tlsh, stdext::to_wide(stTLSH), diff, stFileName)
								);
								return false;
							}
						}
					}
				}
			}
		}

		CFileVersion ver;
		const auto bVerQueryRet = ver.QueryFile(stFileName);
	
		const auto stMD5 = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetMd5(stFileName);
		const auto stSHA1 = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(stFileName);

		const auto vecBlacklist = CApplication::Instance().QuarentineInstance()->FileQuarentine()->GetBlacklist();
		for (const auto& [obj, opts] : vecBlacklist)
		{
			if (obj.name == stFileName)
			{
				SCANNER_LOG(LL_ERR, L"File: %s detected by name", stFileName.c_str());
				
				CApplication::Instance().OnCheatDetect(
					CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_FILE_NAME_BLACKLIST),
					fmt::format(xorstr_(L"t:1|f:{0}"), stFileName)
				);
				return false;
			}

			if (!stMD5.empty() && obj.md5 == stMD5)
			{
				SCANNER_LOG(LL_ERR, L"File: %s detected by MD5", stFileName.c_str());
				
				CApplication::Instance().OnCheatDetect(
					CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_FILE_MD5_BLACKLIST),
					fmt::format(xorstr_(L"t:2|f:{0}"), stFileName)
				);
				return false;
			}

			if (!stSHA1.empty() && obj.sha1 == stSHA1)
			{
				SCANNER_LOG(LL_ERR, L"File: %s detected by SHA2", stFileName.c_str());
				
				CApplication::Instance().OnCheatDetect(
					CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_FILE_SHA2_BLACKLIST),
					fmt::format(xorstr_(L"t:3|f:{0}"), stFileName)
				);
				return false;
			}

			if (bVerQueryRet)
			{
				if (obj.version_company_name == ver.GetCompanyName())
				{
					SCANNER_LOG(LL_ERR, L"File: %s detected by version company name", stFileName.c_str());
					
					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_VERSION_FILE_COMPANY_NAME_BLACKLIST),
						fmt::format(xorstr_(L"t:4|f:{0}"), stFileName)
					);
					return false;
				}

				if (obj.version_product_name == ver.GetProductName())
				{
					SCANNER_LOG(LL_ERR, L"File: %s detected by version product name", stFileName.c_str());
					
					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_VERSION_FILE_PRODUCT_NAME_BLACKLIST),
						fmt::format(xorstr_(L"t:5|f:{0}"), stFileName)
					);
					return false;
				}

				if (obj.version_internal_name == ver.GetInternalName())
				{
					SCANNER_LOG(LL_ERR, L"File: %s detected by version internal name", stFileName.c_str());
					
					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_VERSION_FILE_INTERNAL_NAME_BLACKLIST),
						fmt::format(xorstr_(L"t:6|f:{0}"), stFileName)
					);
					return false;
				}

				if (obj.version_file_description == ver.GetFileDescription())
				{
					SCANNER_LOG(LL_ERR, L"File: %s detected by version file description", stFileName.c_str());
					
					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_VERSION_FILE_DESCRIPTION_BLACKLIST),
						fmt::format(xorstr_(L"t:7|f:{0}"), stFileName)
					);
					return false;
				}

				if (obj.version_file_name == ver.GetOriginalFilename())
				{
					SCANNER_LOG(LL_ERR, L"File: %s detected by version file name", stFileName.c_str());
					
					CApplication::Instance().OnCheatDetect(
						CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_VERSION_FILE_NAME_BLACKLIST),
						fmt::format(xorstr_(L"t:8|f:{0}"), stFileName)
					);
					return false;
				}
			}

			const auto pe = Pe::Pe32::fromFile(lpFileBuffer);
			if (pe.valid())
			{
				const auto pINH = pe.headers().nt();
				if (pINH->Signature == IMAGE_NT_SIGNATURE)
				{
					const auto pIFH = pINH->FileHeader;
					if (pIFH.TimeDateStamp && pINH->OptionalHeader.SizeOfCode && pINH->OptionalHeader.SizeOfInitializedData)
					{
						if (pIFH.TimeDateStamp == obj.pe_timestamp &&
							pINH->OptionalHeader.SizeOfCode == obj.pe_sizeofcode &&
							pINH->OptionalHeader.SizeOfInitializedData == obj.pe_sizeofinitdata)
						{
							SCANNER_LOG(LL_ERR, L"File: %s detected by PE", stFileName.c_str());
							
							CApplication::Instance().OnCheatDetect(
								CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_PE_BLACKLIST),
								fmt::format(xorstr_(L"t:9|f:{0}"), stFileName)
							);
							return false;
						}
					}
				}
			}

		}
		
		return true;
	}

	static bool CheckFileInformations(const std::wstring& stFileName, LPVOID lpFileBuffer)
	{
		SCANNER_LOG(LL_SYS, L"File information scan started! File: %s", stFileName.c_str());

		SafeHandle hFile(g_winAPIs->CreateFileW(stFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL));
		if (!IS_VALID_HANDLE(hFile.get()))
		{
			SCANNER_LOG(LL_ERR, L"CreateFileA fail! Error code: %u", g_winAPIs->GetLastError());
			return false;
		}

		BY_HANDLE_FILE_INFORMATION hfi{ 0 };
		if (!g_winAPIs->GetFileInformationByHandle(hFile.get(), &hfi))
		{
			SCANNER_LOG(LL_ERR, L"GetFileInformationByHandle fail! Error code: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto vecBlacklist = CApplication::Instance().QuarentineInstance()->FileQuarentine()->GetBlacklist();
		for (const auto& [obj, opts] : vecBlacklist)
		{
			if (obj.metadata_idx_low == hfi.nFileIndexLow && obj.metadata_idx_high == hfi.nFileIndexHigh && obj.metadata_volume_serial == hfi.dwVolumeSerialNumber)
			{
				SCANNER_LOG(LL_ERR, L"File: %s detected by metadata", stFileName.c_str());
				
				CApplication::Instance().OnCheatDetect(
					CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_METADATA_BLACKLIST), stFileName
				);
				return false;
			}
		}

		return true;
	}

	static bool CheckFileExist(const std::wstring& stFileName)
	{
		auto bRet = true;

		const auto bExist = g_winAPIs->PathFileExistsW(stFileName.c_str());
		if (!bExist)
		{
			SCANNER_LOG(LL_ERR, L"Target file: '%s' is NOT visible or deleted! Last error: %u",
				stFileName.c_str(), g_winAPIs->GetLastError()
			);

			/*
			* FIXME: wow64 redirection not works correctly
			CApplication::Instance().OnCheatDetect(
				CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(FILE_SCAN_FILE_NOT_EXIST), stFileName
			);
			*/

			bRet = false;
		}
		
		return bRet;
	}


	std::optional <bool> QueryFileAccess(const std::wstring& stFilename)
	{
		auto GetAccessMaskString = [](ACCESS_MASK Mask) -> std::wstring {
			if (((Mask & GENERIC_ALL) == GENERIC_ALL) || ((Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS))
				return xorstr_(L"Full Control");

			if (((Mask & GENERIC_READ) == GENERIC_READ) || ((Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ))
				return xorstr_(L"Read");

			if (((Mask & GENERIC_WRITE) == GENERIC_WRITE) || ((Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE))
				return xorstr_(L"Write");

			if (((Mask & GENERIC_EXECUTE) == GENERIC_EXECUTE) || ((Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE))
				return xorstr_(L"Execute");

			return xorstr_(L"Unknown");
		};

		SafeHandle hFile = g_winAPIs->CreateFileW(stFilename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!IS_VALID_HANDLE(hFile.get()))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileA(%s) failed with error %u", stFilename.c_str(), g_winAPIs->GetLastError());
			return std::nullopt;
		}

		PSID pSidOwner = NULL;
		PSECURITY_DESCRIPTOR pSD = NULL;
		auto pDACL = new(std::nothrow) ACL();
		if (pDACL == nullptr)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for DACL");
			return std::nullopt;
		}
		
		auto dwRtnCode = g_winAPIs->GetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &pSidOwner, NULL, &pDACL, NULL, &pSD);
		if (dwRtnCode != ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"GetSecurityInfo(%s) failed with error %u", stFilename.c_str(), dwRtnCode);
			if (pDACL)
				delete pDACL;
			return std::nullopt;
		}
		/*
		else if (dwRtnCode == ERROR_SUCCESS)
		{
			APP_TRACE_LOG(LL_SYS, L"GetSecurityInfo(%s) succeeded, ACE count: %u", stFilename.c_str(), pDACL->AceCount);
		}
		*/

		// Query required size
		LPTSTR AcctName = NULL;
		LPTSTR DomainName = NULL;
		DWORD dwAcctName = 1, dwDomainName = 1;
		SID_NAME_USE eUse = SidTypeUnknown;
		g_winAPIs->LookupAccountSidW(NULL, pSidOwner, AcctName, (LPDWORD)&dwAcctName, DomainName, (LPDWORD)&dwDomainName, &eUse);

		// Reallocate memory for the buffers.
		AcctName = (LPTSTR)g_winAPIs->GlobalAlloc(GMEM_FIXED, dwAcctName);
		DomainName = (LPTSTR)g_winAPIs->GlobalAlloc(GMEM_FIXED, dwDomainName);

		if (!AcctName || !DomainName)
		{
			APP_TRACE_LOG(LL_ERR, L"GlobalAlloc failed with error %u", g_winAPIs->GetLastError());
			if (pDACL)
				delete pDACL;
			if (AcctName)
				g_winAPIs->GlobalFree(AcctName);
			if (DomainName)
				g_winAPIs->GlobalFree(DomainName);
			return std::nullopt;
		}

		// Get the account name.
		auto bRtnBool = g_winAPIs->LookupAccountSidW(NULL, pSidOwner, AcctName, (LPDWORD)&dwAcctName, DomainName, (LPDWORD)&dwDomainName, &eUse);
		if (!bRtnBool)
		{
			APP_TRACE_LOG(LL_ERR, L"LookupAccountSidA(%s) failed with error %u", stFilename.c_str(), g_winAPIs->GetLastError());
			if (pDACL)
				delete pDACL;
			g_winAPIs->GlobalFree(AcctName);
			g_winAPIs->GlobalFree(DomainName);
			return std::nullopt;
		}

		// Print the account name.
		APP_TRACE_LOG(LL_SYS, L"Account name: %s", AcctName);

		bool canaccess = false;
		PACL pAcl = pDACL;
		const auto dwAceCount = pDACL->AceCount;
		APP_TRACE_LOG(LL_SYS, L"Ace count: %u, Access:", dwAceCount);
		for (auto i = 0u; i < dwAceCount; i++)
		{
			PACCESS_ALLOWED_ACE AceItem;
			ACE_HEADER* aceAddr = NULL;
			if (g_winAPIs->GetAce(pDACL, i, (LPVOID*)&AceItem) && g_winAPIs->GetAce(pDACL, i, (LPVOID*)&aceAddr))
			{
				LPTSTR AccountBuff = NULL;
				LPTSTR DomainBuff = NULL;
				DWORD AccountBufflength = 1, DomainBufflength = 1;
				auto peUse = std::make_unique<SID_NAME_USE>();
				PSID Sid = &AceItem->SidStart;
				g_winAPIs->LookupAccountSidW(NULL, Sid, AccountBuff, (LPDWORD)&AccountBufflength, DomainBuff, (LPDWORD)&DomainBufflength, peUse.get());

				AccountBuff = (LPTSTR)g_winAPIs->GlobalAlloc(GMEM_FIXED, AccountBufflength);
				DomainBuff = (LPTSTR)g_winAPIs->GlobalAlloc(GMEM_FIXED, DomainBufflength);

				if (!AccountBuff || !DomainBuff)
				{
					APP_TRACE_LOG(LL_ERR, L"GlobalAlloc failed with error %u", g_winAPIs->GetLastError());
					if (AccountBuff)
						g_winAPIs->GlobalFree(AccountBuff);
					if (DomainBuff)
						g_winAPIs->GlobalFree(DomainBuff);
					continue;
				}

				if (!g_winAPIs->LookupAccountSidW(NULL, Sid, AccountBuff, &AccountBufflength, DomainBuff, &DomainBufflength, peUse.get()))
				{
					APP_TRACE_LOG(LL_ERR, L"LookupAccountSidA failed with error %u", g_winAPIs->GetLastError());
					g_winAPIs->GlobalFree(AccountBuff);
					g_winAPIs->GlobalFree(DomainBuff);
					continue;
				}

				const auto stAccessMask = GetAccessMaskString(AceItem->Mask);
#ifdef _DEBUG
				APP_TRACE_LOG(LL_SYS, L"ACE %d: %s\\%s, access mask: %x (%s)", i, DomainBuff, AccountBuff, AceItem->Mask, stAccessMask.c_str());
#endif
				
				if (stAccessMask == xorstr_(L"Full Control") || stAccessMask == xorstr_(L"Read"))
					canaccess = true;

				g_winAPIs->GlobalFree(AccountBuff);
				g_winAPIs->GlobalFree(DomainBuff);
			}
		}

		if (pDACL)
			delete pDACL;
		g_winAPIs->GlobalFree(AcctName);
		g_winAPIs->GlobalFree(DomainName);
		return std::make_optional<bool>(canaccess);
	}

	IFileScanner::IFileScanner()
	{
	}
	IFileScanner::~IFileScanner()
	{
	}

	bool IFileScanner::IsScanned(std::wstring stFileName)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_FILE, stFileName);
	}
	void IFileScanner::AddScanned(std::wstring stFileName)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_FILE, stFileName);
	}

	std::wstring IScanner::PatchFileName(const std::wstring& stInFileName)
	{
		// Fix filename
		auto stFileName = stdext::to_lower_wide(stInFileName);

		if (stFileName.find(xorstr_(L"\\Device\\LanmanRedirector\\")) != std::wstring::npos)
		{
			stFileName = fmt::format(xorstr_(L"\\\\{0}"), stFileName.substr(25, stFileName.size()));

			SCANNER_LOG(LL_SYS, L"[1] Fixed file path: %s", stFileName.c_str());
		}
		if (stFileName.find(xorstr_(L"\\Device\\Mup\\")) != std::wstring::npos)
		{
			stFileName = fmt::format(xorstr_(L"\\\\{0}"), stFileName.substr(12, stFileName.size()));

			SCANNER_LOG(LL_SYS, L"[2] Fixed file path: %s", stFileName.c_str());
		}
		if (stFileName.find(xorstr_(L"\\Device\\Hgfs\\")) != std::wstring::npos)
		{
			stFileName = fmt::format(xorstr_(L"\\\\{0}"), stFileName.substr(13, stFileName.size()));

			SCANNER_LOG(LL_SYS, L"[3] Fixed file path: %s", stFileName.c_str());
		}
		if (stFileName.substr(0, 4) == xorstr_(L"\\??\\"))
		{
			stFileName = stFileName.substr(4, stFileName.size());

			SCANNER_LOG(LL_SYS, L"[4] Fixed file path: %s", stFileName.c_str());
		}
		if (stFileName.substr(0, 12) == xorstr_(L"\\systemroot\\"))
		{
			const auto stWinPath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->WinPath();
			stFileName = stdext::replace<std::wstring>(stFileName, xorstr_(L"\\systemroot"), stWinPath);

			SCANNER_LOG(LL_SYS, L"[5] Fixed file path: %s", stFileName.c_str());
		}
		if (stFileName.substr(0, 9) == xorstr_(L"\\windows\\"))
		{
			const auto stWinPath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->WinPath();
			stFileName = stdext::replace<std::wstring>(stFileName, xorstr_(L"\\windows"), stWinPath);

			SCANNER_LOG(LL_SYS, L"[6] Fixed file path: %s", stFileName.c_str());
		}
		else if (stFileName.substr(0, 9) == xorstr_(L"syswow64\\") ||
				 stFileName.substr(0, 9) == xorstr_(L"system32\\"))
		{
			const auto stWinPath = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->WinPath();
			stFileName = fmt::format(xorstr_(L"{0}\\{1}"), stWinPath, stFileName);

			SCANNER_LOG(LL_SYS, L"[7] Fixed file path: %s", stFileName.c_str());
		}

		return stFileName;
	}

	void IFileScanner::Scan(std::wstring stFileName, EFileScanTypes fileType)
	{
		if (stFileName.empty())
			return;

		SCANNER_LOG(LL_SYS, L"File scanner has been started! Target file: %s Type: %u", stFileName.c_str(), static_cast<uint8_t>(fileType));

		stFileName = CApplication::Instance().ScannerInstance()->PatchFileName(stFileName);

		SCANNER_LOG(LL_SYS, L"Fixed file name: %s", stFileName.c_str());

		// Check scan twice
		if (IsScanned(stFileName))
		{
			SCANNER_LOG(LL_SYS, L"File already scanned!");
			return;
		}

		// Add to checked list
		AddScanned(stFileName);

		// Scan routine

		// Enable FS redirection
		PVOID OldValue = nullptr;
		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
		{
			SCANNER_LOG(LL_SYS, L"FS redirection enable failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		/* FIXME: delete exception >> "File access permission" use
		// Query access
		const auto obCanAccess = QueryFileAccess(stFileName);
		if (obCanAccess.has_value() && obCanAccess.value())
		{
			SCANNER_LOG(LL_SYS, L"File: %s can be accessed!", stFileName.c_str());
		}
		else
		{
			SCANNER_LOG(LL_ERR, L"File: %s can't be accessed!", stFileName.c_str());
			return;
		}
		*/

		// Read file
		LPVOID lpFileBuffer = nullptr;
		std::size_t cbFileBufferSize = 0;

		FILE* fp = nullptr;
		const auto err = _wfopen_s(&fp, stFileName.c_str(), xorstr_(L"rb"));
		if (err || !fp)
		{
			SCANNER_LOG(LL_ERR, L"File: %s can't be opened! Error: %u", stFileName.c_str(), err);
		}
		else
		{
			std::error_code ec;
			cbFileBufferSize = std::filesystem::file_size(stFileName, ec);
			if (!cbFileBufferSize || ec)
			{
				SCANNER_LOG(LL_ERR, L"File size: %lu is invalid! Error: %u (%hs)", cbFileBufferSize, ec.value(), ec.message().c_str());
				fclose(fp);
				return;
			}

			if (cbFileBufferSize < 0x200)
			{
				SCANNER_LOG(LL_ERR, L"File size is too smol!");
				fclose(fp);
				return;
			}

			// Read file
			lpFileBuffer = CMemHelper::Allocate(cbFileBufferSize);
			if (!lpFileBuffer)
			{
				SCANNER_LOG(LL_ERR, L"Can't allocate memory for file buffer!");
				fclose(fp);
				return;
			}

			const auto cbReadSize = fread_s(lpFileBuffer, cbFileBufferSize, 1, cbFileBufferSize, fp);
			if (cbReadSize != cbFileBufferSize)
			{
				SCANNER_LOG(LL_ERR, L"File could NOT read! Error: %u (%hs) Size: %u/%u", errno, std::strerror(errno), cbReadSize, cbFileBufferSize);
				fclose(fp);
				CMemHelper::Free(lpFileBuffer);
				return;
			}

			fclose(fp);
		}
		
		// Exist check
		auto bRet = CheckFileExist(stFileName);
		SCANNER_LOG(LL_WARN, L"File exist check completed! Result: %d", bRet);

		if (bRet)
		{
			// File name + file size + Entropy + Hash
			bRet = CheckFileBasicInformations(stFileName, lpFileBuffer, cbFileBufferSize);
			SCANNER_LOG(LL_WARN, L"File basic information scan completed! Result: %d", bRet);

			// nFileIndexLow, nFileIndexHigh, dwVolumeSerialNumber
			bRet = CheckFileInformations(stFileName, lpFileBuffer);
			SCANNER_LOG(LL_WARN, L"File information scan completed! Result: %d", bRet);

			// PE Informations
			bRet = CheckFilePEInformations(stFileName, lpFileBuffer, cbFileBufferSize);
			SCANNER_LOG(LL_WARN, L"File PE information scan completed! Result: %d", bRet);

			// Region hash Informations
			bRet = CheckFileRegionHashes(stFileName, (uint8_t*)lpFileBuffer);
			SCANNER_LOG(LL_WARN, L"File region hashes scan completed! Result: %d", bRet);

			// Digital signature informations
			bRet = CheckFileCertificates(stFileName, fileType, lpFileBuffer);
			SCANNER_LOG(LL_WARN, L"File digital certificate scan completed! Result: %d", bRet);

			// Pattern check
			bRet = CheckFilePatterns(stFileName, lpFileBuffer, cbFileBufferSize);
			SCANNER_LOG(LL_WARN, L"File pattern scan completed! Result: %d", bRet);

			// If file extension is .dll check for contained strings
			if (stFileName.size() > 4 && stFileName.substr(stFileName.size() - 4, 4) == xorstr_(L".dll"))
			{
				// Extract strings
				auto vecStrings = ExtractStrings((uint8_t*)lpFileBuffer, cbFileBufferSize);
				SCANNER_LOG(LL_WARN, L"File strings extraction completed! Result size: %u", vecStrings.size());

				if (!vecStrings.empty())
				{
					// Check strings
					auto vecFilePaths = ExtractFilePaths(vecStrings);
					SCANNER_LOG(LL_WARN, L"Strings processing completed! Result size: %u", vecFilePaths.size());

					const auto vecBlacklist = CApplication::Instance().QuarentineInstance()->FileQuarentine()->GetBlacklist();
					for (const auto& [obj, opts] : vecBlacklist)
					{
						for (const auto& str : vecStrings)
						{
							if (obj.contained_string == str)
							{
								SCANNER_LOG(LL_ERR, L"String found in blacklist! %ls", str.c_str());
								
								CApplication::Instance().OnCheatDetect(
									CHEAT_VIOLATION_FILE_SCAN, static_cast<uint8_t>(EFileScanCheatEvents::FILE_SCAN_BLACKLISTED_STRING),
									fmt::format(xorstr_(L"f:{0}|s:{1}"), stFileName, str)
								);
							}
						}
					}

					vecStrings.clear();
					vecFilePaths.clear();
				}
			}
		}
		
		// Disable FS redirection
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);

		// Clear file buffer
		CMemHelper::Free(lpFileBuffer);
	}

	void IFileScanner::ScanSync(std::wstring stFileName)
	{
		return;
	}
	bool IFileScanner::ScanAll()
	{
		return true;
	}

	bool IFileScanner::ScanProcessFile(HANDLE hProcess, EFileScanTypes fileType)
	{		
		SCANNER_LOG(LL_SYS, L"Process file scanner has been started! Target process: %u(%p) Type: %u",
			g_winAPIs->GetProcessId(hProcess), hProcess, static_cast<uint8_t>(fileType)
		);

		if (!IS_VALID_HANDLE(hProcess))
		{
			SCANNER_LOG(LL_ERR, L"Target handle is NOT valid!");
			return true;
		}

		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
		{
			SCANNER_LOG(LL_ERR, L"Target process is NOT active!");
			return true;
		}

		const auto stProcessName = CProcessFunctions::GetProcessName(hProcess);
		if (stProcessName.empty())
		{
			SCANNER_LOG(LL_ERR, L"Process name read fail! Target process: %p Error: %u", hProcess, g_winAPIs->GetLastError());
			return false;
		}

		SCANNER_LOG(LL_SYS, L"Process image name: %s", stProcessName.c_str());

		Scan(stProcessName, fileType);
		return true;
	}
};
