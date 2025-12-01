#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "CheatQueueManager.hpp"
#include "../Helper/PatternScanner.hpp"
#include "../../EngineR3_Core/include/FileVersion.hpp"

namespace NoMercy
{
	static void TriggerBlockedToolAction(std::shared_ptr <SBlockedToolNode> spNode)
	{
		// TODO: Implement all actions
		if (IS_VALID_SMART_PTR(spNode))
		{
			switch (spNode->action)
			{
				case BLOCKED_TOOL_ACTION_WARNING:
				{

				} break;
				case BLOCKED_TOOL_ACTION_CLOSE_GAME:
				{
					auto fnWorker = [](LPVOID lpParam) -> DWORD {
						auto pNode = (SBlockedToolNode*)lpParam;

						g_winAPIs->Sleep(15000); // Wait 15 seconds before closing the game for cheat log to be sending
						CApplication::Instance().OnCloseRequest(EXIT_ERR_UNALLOWED_TOOL_DETECTED, pNode->idx, (void*)pNode->detection_name.c_str());
						return 0;
					};

					auto pNodeDetails = new (std::nothrow) SBlockedToolNode();
					if (!pNodeDetails)
					{
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_QUEUE_PROC_FAIL, 1);
						return;
					}
					memcpy(pNodeDetails, spNode.get(), sizeof(SBlockedToolNode));

					SafeHandle pkThread = g_winAPIs->CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)fnWorker, pNodeDetails, 0, nullptr);
				} break;
				case BLOCKED_TOOL_ACTION_CLOSE_PROCESS:
				{

				} break;
				case BLOCKED_TOOL_ACTION_LOG:
				{

				} break;
				case BLOCKED_TOOL_ACTION_KICK:
				{

				} break;
				case BLOCKED_TOOL_ACTION_TEMP_BAN:
				{

				} break;
				case BLOCKED_TOOL_ACTION_PERMA_BAN:
				{

				} break;
				case BLOCKED_TOOL_ACTION_FORCE_MINIMIZE:
				{

				} break;
				case BLOCKED_TOOL_ACTION_TROLL:
				{

				} break;
				default:
				{
					APP_TRACE_LOG(LL_ERR, L"Unknown action id: %u", spNode->action);
					break;
				};
			}
		}
		return;
	}

	bool CCheatQueueManager::ProcessBlockedToolNode(std::shared_ptr <SBlockedToolNode> spNode)
	{
		if (!spNode || spNode->method == BLOCKED_TOOL_SCAN_BASE || spNode->method >= BLOCKED_TOOL_SCAN_MAX)
			return false;

		APP_TRACE_LOG(LL_SYS, L"Processing blocked tool node. Index: %u(%s) Scan Type: %u", spNode->idx, spNode->id.c_str(), spNode->method);

		switch (spNode->method)
		{
			case BLOCKED_TOOL_SCAN_FILE_NAME:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				const auto c_bIsFullName = spNode->value.find(xorstr_(L":\\")) != std::wstring::npos;
				if (c_bIsFullName) // Full filename with specific path
				{
					if (g_winAPIs->PathFileExistsW(spNode->value.c_str()))
					{
						APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
						CApplication::Instance().ScannerInstance()->SendViolationNotification(spNode->idx, spNode->id, true);
						TriggerBlockedToolAction(spNode);
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"PathFileExistsW (%s) failed with error: %u", spNode->value.c_str(), g_winAPIs->GetLastError());
					}
				}
				else // Just filename w/o path (a process name)
				{
					if (CApplication::Instance().ScannerInstance()->CDB_IsProcessExistByName(
						{ spNode->idx, spNode->id, true, false }, c_wstValue
					))
					{
						TriggerBlockedToolAction(spNode);
					}
				}

				return true;
			} break;
			case BLOCKED_TOOL_SCAN_FILE_SHA1:
			{
				const auto vecSplittedData = stdext::split_string(spNode->value, std::wstring(xorstr_(L"~")));
				if (vecSplittedData.size() != 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing blocked tool node failed. Param count: %u is not correct. Scan Type: %u", vecSplittedData.size(), spNode->method);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->method);
					return false;
				}
				const auto wstFileName = stdext::to_lower_wide(vecSplittedData.at(0));
				const auto wstFileHash = stdext::to_lower_wide(vecSplittedData.at(1));

				const auto c_bIsFullName = wstFileName.find(xorstr_(L":\\")) != std::wstring::npos;
				if (c_bIsFullName) // Full filename with specific path
				{
					if (g_winAPIs->PathFileExistsW(wstFileName.c_str()))
					{
						auto wstCorrectHash = CApplication::Instance().CacheManagerInstance()->GetCachedFileSHA1(wstFileName);
						if (wstCorrectHash.empty())
							wstCorrectHash = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(wstFileName);

						wstCorrectHash = stdext::to_lower_wide(wstCorrectHash);
						if (wstCorrectHash == wstFileHash)
						{
							APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
							CApplication::Instance().ScannerInstance()->SendViolationNotification(spNode->idx, spNode->id, true);
							TriggerBlockedToolAction(spNode);
						}
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"PathFileExistsW (%s) failed with error: %u", spNode->value.c_str(), g_winAPIs->GetLastError());
					}
				}
				else // Just filename w/o path (a process name)
				{
					if (CApplication::Instance().ScannerInstance()->CDB_IsProcessExistByChecksum(
						{ spNode->idx, spNode->id, true, false }, wstFileHash
					))
					{
						TriggerBlockedToolAction(spNode);
					}
				}

				return true;
			} break;
			case BLOCKED_TOOL_SCAN_FILE_DESC:
			{
				const auto vecSplittedData = stdext::split_string(spNode->value, std::wstring(xorstr_(L"~")));
				if (vecSplittedData.size() != 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing blocked tool node failed. Param count: %u is not correct. Scan Type: %u", vecSplittedData.size(), spNode->method);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->method);
					return false;
				}
				const auto wstFileName = stdext::to_lower_wide(vecSplittedData.at(0));
				const auto wstFileDesc = stdext::to_lower_wide(vecSplittedData.at(1));

				const auto c_bIsFullName = wstFileName.find(xorstr_(L":\\")) != std::wstring::npos;
				if (c_bIsFullName) // Full filename with specific path
				{
					if (g_winAPIs->PathFileExistsW(wstFileName.c_str()))
					{
						CFileVersion verInfo{};
						if (verInfo.QueryFile(wstFileName))
						{
							const auto wstCorrectFileDesc = stdext::to_lower_wide(verInfo.GetFileDescription());
							if (!wstCorrectFileDesc.empty() && wstCorrectFileDesc == wstFileDesc)
							{
								APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
								CApplication::Instance().ScannerInstance()->SendViolationNotification(spNode->idx, spNode->id, true);
								TriggerBlockedToolAction(spNode);
							}
						}
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"PathFileExistsW (%s) failed with error: %u", spNode->value.c_str(), g_winAPIs->GetLastError());
					}
				}
				else // Just filename w/o path (a process name)
				{
					if (CApplication::Instance().ScannerInstance()->CDB_IsProcessExistByFileDesc(
						{ spNode->idx, spNode->id, true, false }, wstFileDesc
					))
					{
						TriggerBlockedToolAction(spNode);
					}
				}
				return true;
			} break;
			case BLOCKED_TOOL_SCAN_FILE_DESC_W_VER:
			{
				const auto vecSplittedData = stdext::split_string(spNode->value, std::wstring(xorstr_(L"~")));
				if (vecSplittedData.size() != 3)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing blocked tool node failed. Param count: %u is not correct. Scan Type: %u", vecSplittedData.size(), spNode->method);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->method);
					return false;
				}
				const auto wstFileName = stdext::to_lower_wide(vecSplittedData.at(0));
				const auto wstFileDesc = stdext::to_lower_wide(vecSplittedData.at(1));
				const auto wstFileVer = stdext::to_lower_wide(vecSplittedData.at(2));

				const auto c_bIsFullName = wstFileName.find(xorstr_(L":\\")) != std::wstring::npos;
				if (c_bIsFullName) // Full filename with specific path
				{
					if (g_winAPIs->PathFileExistsW(wstFileName.c_str()))
					{
						CFileVersion verInfo{};
						if (verInfo.QueryFile(wstFileName))
						{
							const auto wstCorrectFileDesc = stdext::to_lower_wide(verInfo.GetFileDescription());
							const auto wstCorrectFileVer = stdext::to_lower_wide(verInfo.GetFixedFileVersion());

							if (!wstCorrectFileDesc.empty() && !wstCorrectFileVer.empty() &&
								wstCorrectFileDesc == wstFileDesc && wstCorrectFileVer == wstFileVer)
							{
								APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
								CApplication::Instance().ScannerInstance()->SendViolationNotification(spNode->idx, spNode->id, true);
								TriggerBlockedToolAction(spNode);
							}
						}
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"PathFileExistsW (%s) failed with error: %u", spNode->value.c_str(), g_winAPIs->GetLastError());
					}
				}
				else // Just filename w/o path (a process name)
				{
					if (CApplication::Instance().ScannerInstance()->CDB_IsProcessExistByFileDesc(
						{ spNode->idx, spNode->id, true, false }, wstFileDesc, wstFileVer
					))
					{
						TriggerBlockedToolAction(spNode);
					}
				}
				return true;
			} break;
			case BLOCKED_TOOL_SCAN_FILE_PATTERN:
			{
				const auto vecSplittedData = stdext::split_string(spNode->value, std::wstring(xorstr_(L"~")));
				if (vecSplittedData.size() != 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing blocked tool node failed. Param count: %u is not correct. Scan Type: %u", vecSplittedData.size(), spNode->method);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->method);
					return false;
				}
				const auto wstFileName = stdext::to_lower_wide(vecSplittedData.at(0));
				const auto wstFilePattern = stdext::to_lower_wide(vecSplittedData.at(1));

				const auto c_bIsFullName = wstFileName.find(xorstr_(L":\\")) != std::wstring::npos;
				if (c_bIsFullName) // Full filename with specific path
				{
					if (g_winAPIs->PathFileExistsW(wstFileName.c_str()))
					{
						if (CApplication::Instance().ScannerInstance()->CDB_CheckFilePattern(
							{ spNode->idx, spNode->id, true, false }, wstFileName, wstFilePattern, L"", std::to_wstring((uint8_t)PatternType::Address)
						))
						{
							APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
							TriggerBlockedToolAction(spNode);
						}
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"PathFileExistsW (%s) failed with error: %u", spNode->value.c_str(), g_winAPIs->GetLastError());
					}
				}
				else // Just filename w/o path (a process name)
				{
					if (CApplication::Instance().ScannerInstance()->CDB_IsPatternExistInAllProcesses(
						{ spNode->idx, spNode->id, true, false }, wstFilePattern, L"", std::to_wstring((uint8_t)PatternType::Address), 0
					))
					{
						TriggerBlockedToolAction(spNode);
					}
				}
				return true;
			} break;
			case BLOCKED_TOOL_SCAN_FILE_PATTERN_W_ADDR:
			{
				const auto vecSplittedData = stdext::split_string(spNode->value, std::wstring(xorstr_(L"~")));
				if (vecSplittedData.size() != 3)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing blocked tool node failed. Param count: %u is not correct. Scan Type: %u", vecSplittedData.size(), spNode->method);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->method);
					return false;
				}
				const auto wstFileName = stdext::to_lower_wide(vecSplittedData.at(0));
				const auto wstFilePattern = stdext::to_lower_wide(vecSplittedData.at(1));
				const auto wstFilePatternAddr = stdext::to_lower_wide(vecSplittedData.at(2));

				const auto c_bIsFullName = wstFileName.find(xorstr_(L":\\")) != std::wstring::npos;
				if (c_bIsFullName) // Full filename with specific path
				{
					if (g_winAPIs->PathFileExistsW(wstFileName.c_str()))
					{
						if (CApplication::Instance().ScannerInstance()->CDB_CheckFilePattern(
							{ spNode->idx, spNode->id, true, false }, wstFileName, wstFilePattern, L"", std::to_wstring((uint8_t)PatternType::Address) // , wstFilePatternAddr
						))
						{
							APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
							TriggerBlockedToolAction(spNode);
						}
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"PathFileExistsW (%s) failed with error: %u", spNode->value.c_str(), g_winAPIs->GetLastError());
					}
				}
				else // Just filename w/o path (a process name)
				{
					if (CApplication::Instance().ScannerInstance()->CDB_IsMemDumpExist(
						{ spNode->idx, spNode->id, true, false }, wstFilePatternAddr, wstFilePattern
					))
					{
						TriggerBlockedToolAction(spNode);
					}
				}
				return true;
			} break;
			case BLOCKED_TOOL_SCAN_FILE_SECTION_SHA256:
			{
				const auto vecSplittedData = stdext::split_string(spNode->value, std::wstring(xorstr_(L"~")));
				if (vecSplittedData.size() != 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing blocked tool node failed. Param count: %u is not correct. Scan Type: %u", vecSplittedData.size(), spNode->method);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->method);
					return false;
				}
				const auto wstFileName = stdext::to_lower_wide(vecSplittedData.at(0));
				const auto wstFileSectionHash = stdext::to_lower_wide(vecSplittedData.at(1));

				const auto c_bIsFullName = wstFileName.find(xorstr_(L":\\")) != std::wstring::npos;
				if (c_bIsFullName) // Full filename with specific path
				{
					if (g_winAPIs->PathFileExistsW(wstFileName.c_str()))
					{
						if (CApplication::Instance().ScannerInstance()->CDB_CheckFileSectionHash(
							{ spNode->idx, spNode->id, true, false }, wstFileName, wstFileSectionHash
						))
						{
							APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
							TriggerBlockedToolAction(spNode);
						}
					}
					else
					{
						APP_TRACE_LOG(LL_ERR, L"PathFileExistsW (%s) failed with error: %u", spNode->value.c_str(), g_winAPIs->GetLastError());
					}
				}
				else // Just filename w/o path (a process name)
				{
					if (CApplication::Instance().ScannerInstance()->CDB_IsRegionExistInAllProcesses(
						{ spNode->idx, spNode->id, true, false }, L"", L"", wstFileSectionHash
					))
					{
						TriggerBlockedToolAction(spNode);
					}
				}
				return true;
			} break;
			case BLOCKED_TOOL_SCAN_SERVICE_NAME:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsServiceExist({ spNode->idx, spNode->id, true, false }, c_wstValue))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}

				return true;
			} break;
			case BLOCKED_TOOL_SCAN_SERVICE_SHA1:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsServiceExistByHash({ spNode->idx, spNode->id, true, false }, c_wstValue))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}

				return true;
			} break;
			case BLOCKED_TOOL_SCAN_DRIVER_NAME:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsDriverExist({ spNode->idx, spNode->id, true, false }, c_wstValue))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}

				return true;
			} break;
			case BLOCKED_TOOL_SCAN_DRIVER_SHA1:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsDriverExistByHash({ spNode->idx, spNode->id, true, false }, c_wstValue))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}

				return true;
			} break;
			case BLOCKED_TOOL_SCAN_CERT_PROVIDER_NAME:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsCertContextExist({ spNode->idx, spNode->id, true, false }, c_wstValue, L""))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}

				return true;
			} break;
			case BLOCKED_TOOL_SCAN_CERT_SERIAL:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsCertContextExist({ spNode->idx, spNode->id, true, false }, L"", c_wstValue))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}

				return true;
			} break;
			case BLOCKED_TOOL_SCAN_CERT_CTX:
			{
				const auto vecSplittedData = stdext::split_string(spNode->value, std::wstring(xorstr_(L"~")));
				if (vecSplittedData.size() < 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing blocked tool node failed. Param count: %u is not correct. Scan Type: %u", vecSplittedData.size(), spNode->method);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->method);
					return false;
				}
				const auto wstCertProvider = stdext::to_lower_wide(vecSplittedData.at(0));
				const auto wstCertSerial = stdext::to_lower_wide(vecSplittedData.at(1));

				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsCertContextExist({ spNode->idx, spNode->id, true, false }, wstCertProvider, wstCertSerial))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}

				return true;
			} break;
			case BLOCKED_TOOL_SCAN_MODULE_NAME:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsModuleExistByNameInAllProcesses({ spNode->idx, spNode->id, true, false }, c_wstValue))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}
				return true;
			} break;
			case BLOCKED_TOOL_SCAN_WINDOW_TITLE:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsWindowsExistByTitleClass({ spNode->idx, spNode->id, true, false }, c_wstValue, L""))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}
				return true;
			} break;
			case BLOCKED_TOOL_SCAN_WINDOW_CLASS:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsWindowsExistByTitleClass({ spNode->idx, spNode->id, true, false }, L"", c_wstValue))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}
				return true;
			} break;
			case BLOCKED_TOOL_SCAN_WINDOW_CTX:
			{
				const auto vecSplittedData = stdext::split_string(spNode->value, std::wstring(xorstr_(L"~")));
				if (vecSplittedData.size() < 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing blocked tool node failed. Param count: %u is not correct. Scan Type: %u", vecSplittedData.size(), spNode->method);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->method);
					return false;
				}
				const auto wstWindowTitle = stdext::to_lower_wide(vecSplittedData.at(0));
				const auto wstWindowClass = stdext::to_lower_wide(vecSplittedData.at(1));

				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_IsWindowsExistByTitleClass({ spNode->idx, spNode->id, true, false }, wstWindowTitle, wstWindowClass))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}
				return true;
			} break;
			case BLOCKED_TOOL_SCAN_WINDOW_HEURISTIC:
			{
				const auto c_wstValue = stdext::to_lower_wide(spNode->value);
				if (CApplication::Instance().ScannerInstance()->CDB_CheckWindowTextHeuristic({ spNode->idx, spNode->id, true, false }, c_wstValue))
				{
					APP_TRACE_LOG(LL_WARN, L"Blacklisted object: %u[%s] (%s) with method: %u found!", spNode->idx, spNode->id.c_str(), spNode->value.c_str(), spNode->method);
					TriggerBlockedToolAction(spNode);
				}
				return true;
			} break;
			default:
			{
				APP_TRACE_LOG(LL_ERR, L"Unknown scan type: %u", spNode->method);
				// CApplication::Instance().OnCloseRequest(EXIT_ERR_BLOCKED_TOOL_DB_NOT_IMPLEMENTED_SCAN_TYPE, spNode->method);
				return false;
			}
		}
	}
	void CCheatQueueManager::AppendToolToQueue(std::shared_ptr <SBlockedToolNode> spNode)
	{
		APP_TRACE_LOG(LL_SYS, L"Enqueued blocked tool node. Index: %u(%s) Scan Type: %u", spNode->idx, spNode->id.c_str(), spNode->method);
		m_kBlockedToolQueue.enqueue(spNode);
	}
	std::shared_ptr <SBlockedToolNode> CCheatQueueManager::DequeueToolNode()
	{
		std::shared_ptr <SBlockedToolNode> node;
		m_kBlockedToolQueue.try_dequeue(node);

		if (IS_VALID_SMART_PTR(node)) {
			APP_TRACE_LOG(LL_SYS, L"Dequeued blocked tool node: %p", node.get());
		}
		return node;
	}
};
