#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "CheatDBManager.hpp"
#include "../../../Common/FilePtr.hpp"
#include "../../../Common/Keys.hpp"
#include "../../../Utilities/CheatDBGenerator/include/vigenere.hpp"
#include <nameof.hpp>

namespace NoMercy
{
	struct SCheatDBHeader
	{
		uint32_t magic{ 0 };
		uint32_t version{ 0 };
		uint32_t raw_size{ 0 };
		uint32_t raw_hash{ 0 };
		uint32_t final_size{ 0 };
		uint32_t final_hash{ 0 };
	};

	CCheatDBManager::CCheatDBManager() :
		m_dwCheatDBVersion(0), m_dwCheatDBDate(0), m_dwBlockedToolDate(0)
	{
	}
	CCheatDBManager::~CCheatDBManager()
	{
	}

	bool CCheatDBManager::__ProcessCheatDBNode(std::shared_ptr <SCheatDBNode> spNode)
	{
		if (!spNode || spNode->type == CHEAT_DB_SCAN_NULL || spNode->type >= CHEAT_DB_SCAN_MAX)
			return false;

		APP_TRACE_LOG(LL_SYS, L"Processing cheat db node. Index: %u(%s) Scan Type: %u Param count: %u", spNode->idx, spNode->id.c_str(), spNode->type, spNode->params.size());

		CApplication::Instance().CheatQueueManagerInstance()->AppendCheatToQueue(spNode);
		return true;
	}

	bool CCheatDBManager::__ProcessBlockedToolNode(std::shared_ptr <SBlockedToolNode> spNode)
	{
		if (!spNode || spNode->method == BLOCKED_TOOL_SCAN_BASE || spNode->method >= BLOCKED_TOOL_SCAN_MAX)
			return false;

		APP_TRACE_LOG(LL_SYS, L"Processing blocked tool node. Index: %u(%s) Scan Type: %u", spNode->idx, spNode->id.c_str(), spNode->method);

		CApplication::Instance().CheatQueueManagerInstance()->AppendToolToQueue(spNode);
		return true;
	}

	bool CCheatDBManager::__ProcessWhitelistNode(std::shared_ptr <SCheatDBWhitelist> spNode)
	{
		if (!spNode || spNode->type == SCAN_WHITELIST_NULL || spNode->type >= SCAN_WHITELIST_MAX || spNode->params.size() == 0)
			return false;

		const auto stTypeName = stdext::to_wide(NAMEOF_ENUM(static_cast<ECheatWhitelistTypes>(spNode->type)).data());
		APP_TRACE_LOG(LL_SYS, L"Processing whitelist node. Index: %u Scan Type: %u(%s) Param count: %u", spNode->id, spNode->type, stTypeName.c_str(), spNode->params.size());

		// Append to whitelist
		uint32_t idx = 0;
		for (const auto& stParam : spNode->params)
		{
			idx++;
			APP_TRACE_LOG(LL_TRACE, L"Param#%u: %s", idx, stParam.c_str());

			switch (spNode->type)
			{
				case SCAN_WHITELIST_PROCESS_HOLLOWING:
				{
					CApplication::Instance().QuarentineInstance()->ProcessHollowingQuarentine()->SetWhitelisted({ idx, stParam });
				} break;
				
				case SCAN_WHITELIST_ARBITARY_USER_POINTER_MODULE:
				{
					CApplication::Instance().QuarentineInstance()->ArbitaryUserPointerQuarentine()->SetWhitelisted({ idx, stParam });
				} break;
				
				case SCAN_WHITELIST_DEBUG_PRIV_REMOVED_PROCESS:
				{
					CApplication::Instance().QuarentineInstance()->DebugPrivRemovedProcessQuarentine()->SetWhitelisted({ idx, stParam });
				} break;

				case SCAN_WHITELIST_WINDOW_SCAN_CLASS:
				{
					CApplication::Instance().QuarentineInstance()->WindowQuarentine()->SetWhitelisted({ idx, stParam });
				} break;
				
				default:
					APP_TRACE_LOG(LL_ERR, L"Unknown whitelist node type: %u", spNode->type);
#ifdef _DEBUG
					return false;
#else
					break;
#endif
			}
		}

		return true;
	}
	
	bool CCheatDBManager::__ProcessBlacklistNode(std::shared_ptr <SCheatDBBlacklist> spNode)
	{
		if (!spNode || spNode->type == SCAN_BLACKLIST_NULL || spNode->type >= SCAN_BLACKLIST_MAX || spNode->params.size() == 0)
			return false;

		const auto stTypeName = stdext::to_wide(NAMEOF_ENUM(static_cast<ECheatBlacklistTypes>(spNode->type)).data());
		APP_TRACE_LOG(LL_SYS, L"Processing blacklist node. Index: %u Scan Type: %u(%s) Version: %s Param count: %u",
			spNode->id, spNode->type, stTypeName.data(), spNode->version.c_str(), spNode->params.size()
		);

		// Append to blacklist
		uint32_t idx = 0;
		for (const auto& stParam : spNode->params)
		{
			idx++;
			APP_TRACE_LOG(LL_TRACE, L"Param#%u: %s", idx, stParam.c_str());

			switch (spNode->type)
			{
				case SCAN_BLACKLIST_SYMLINK:
				{
					CApplication::Instance().QuarentineInstance()->SymLinkQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_EVENT:
				{
					CApplication::Instance().QuarentineInstance()->EventNameQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_FILEMAPPING:
				{
					CApplication::Instance().QuarentineInstance()->FileMappingNameQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_WINDOW_TITLE:
				{
					CApplication::Instance().QuarentineInstance()->WindowQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_WINDOW_CLASS:
				{
					CApplication::Instance().QuarentineInstance()->WindowQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_MODULE_NAME:
				{
					CApplication::Instance().QuarentineInstance()->ModuleQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_PROCESS_NAME:
				{
					CApplication::Instance().QuarentineInstance()->ProcessQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_SERVICE_NAME:
				{
					CApplication::Instance().QuarentineInstance()->ServiceNameQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_HANDLE_OWNER_CLASS:
				{
					CApplication::Instance().QuarentineInstance()->HandleOwnerClassQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_DRIVER_FILENAME:
				{
					CApplication::Instance().QuarentineInstance()->DriverFileNameQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_MODULE_TIMESTAMP:
				{
					SModuleCheckObjects moduleObj{};
					moduleObj.idx = idx;
					moduleObj.timestamp = stdext::str_to_u32(stParam);
					
					CApplication::Instance().QuarentineInstance()->ModuleQuarentine()->SetBlacklisted(moduleObj, spNode->options);
				} break;
				
				case SCAN_BLACKLIST_MODULE_EXPORT_FUNC_NAME:
				{
					CApplication::Instance().QuarentineInstance()->ModuleQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;

				case SCAN_BLACKLIST_OUTPUT_DEBUG_STRINGS:
				{
					CApplication::Instance().QuarentineInstance()->DebugStringQuarentine()->SetBlacklisted({ idx, stParam }, spNode->options);
				} break;
				
				default:
					APP_TRACE_LOG(LL_ERR, L"Unknown blacklist node type: %u", spNode->type);
#ifdef _DEBUG
					return false;
#else
					break;
#endif
			}
		}

		return true;
	}

	void CCheatDBManager::ProcessCheatDB(const std::wstring& stData, bool bStreamed)
	{
		APP_TRACE_LOG(LL_SYS, L"Cheat DB processing started. Streamed: %d Data:\n'%s'", bStreamed ? 1 : 0, stData.c_str());
		std::size_t node_size = 0;

		// Sanity check
		if (stData.empty())
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_DATA_NULL), (void*)stData.c_str());
			return;
		}

		// Load as json
		auto document = rapidjson::GenericDocument<UTF16<>>{};
		document.Parse<kParseCommentsFlag, UTF16<> >(stData.c_str());
		if (document.HasParseError())
		{
			APP_TRACE_LOG(LL_ERR, L"Cheat DB stream could NOT parsed! Error: %hs offset: %u", GetParseError_En(document.GetParseError()), document.GetErrorOffset());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_JSON_PARSE_FAIL), (void*)stData.c_str());
			return;
		}	
		if (!document.IsObject())
		{
			APP_TRACE_LOG(LL_ERR, L"Cheat DB stream base is not an object! Type: %u", document.GetType());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_JSON_BASE_NOT_OBJECT), (void*)stData.c_str());
			return;
		}

		// Iterate over all nodes
		for (const auto& item : document.GetObject())
		{
			APP_TRACE_LOG(LL_SYS, L"Processing node. Key: %s", item.name.GetString());
			
			// Process blacklist node
			if (item.name == xorstr_(L"blacklist"))
			{
				if (!item.value.IsArray())
				{
					APP_TRACE_LOG(LL_ERR, L"Cheat DB stream blacklist is not an array! Type: %u", item.value.GetType());
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_BLACKLIST_BASE_NOT_ARRAY), (void*)stData.c_str());
					return;
				}
				
				auto idx = 0u;
				const auto& blacklist = item.value.GetArray();
				APP_TRACE_LOG(LL_SYS, L"Cheat DB stream blacklist size: %u", blacklist.Size());

				for (const auto& blacklist_item : blacklist)
				{
					idx++;

					if (!blacklist_item.IsObject())
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB stream blacklist item is not an object! Type: %u", blacklist_item.GetType());
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM,  static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_BLACKLIST_ITEM_NOT_OBJECT), (void*)stData.c_str());
						return;
					}

					const auto& blacklist_item_obj = blacklist_item.GetObject();

					// Sanity check
					if (!blacklist_item_obj.HasMember(xorstr_(L"description")) ||
						!blacklist_item_obj.HasMember(xorstr_(L"version")) ||
						!blacklist_item_obj.HasMember(xorstr_(L"type")) ||
						!blacklist_item_obj.HasMember(xorstr_(L"options")) ||
						!blacklist_item_obj.HasMember(xorstr_(L"params")))
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB blacklist node has missing members! Index: %u", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_BLACKLIST_ITEM_MISSING_STRUCTURE), (void*)stData.c_str());
						return;
					}
					
					// Check blacklist node type
					if (!blacklist_item_obj[xorstr_(L"description")].IsString() ||
						!blacklist_item_obj[xorstr_(L"version")].IsString() ||
						!blacklist_item_obj[xorstr_(L"type")].IsNumber() ||
						!blacklist_item_obj[xorstr_(L"options")].IsObject() ||
						!blacklist_item_obj[xorstr_(L"params")].IsArray())
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB blacklist node has invalid structure! Index: %u", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_BLACKLIST_ITEM_INVALID_STRUCTURE), (void*)stData.c_str());
						return;
					}

					// Get blacklist nodes
					const std::wstring description = blacklist_item_obj[xorstr_(L"description")].GetString();
					const std::wstring version = blacklist_item_obj[xorstr_(L"version")].GetString();
					const auto type = blacklist_item_obj[xorstr_(L"type")].GetUint();
					const auto& options = blacklist_item_obj[xorstr_(L"options")].GetObject();
					const auto& params = blacklist_item_obj[xorstr_(L"params")].GetArray();
					
					APP_TRACE_LOG(LL_SYS, L"Cheat DB blacklist node #%u: Type: %u, Version: %s Params: %u", idx, type, version.c_str(), params.Size());

					// Sanity check for nodes
					if (!description.empty() || // description should be cleared by DB builder
						version.empty() ||
						type <= SCAN_BLACKLIST_NULL ||
						type >= SCAN_BLACKLIST_MAX ||
						!options.MemberCount() ||
						params.Empty())
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB blacklist node has not valid values! Index: %u", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_BLACKLIST_ITEM_NOT_VALID_MEMBER), (void*)stData.c_str());
						return;
					}

					// Declare new blacklist node
					auto node_ctx = stdext::make_shared_nothrow<SCheatDBBlacklist>();
					
					// Set node values to container
					node_ctx->id = idx;
					node_ctx->type = type;
					node_ctx->version = version;

					// Iterate sub nodes, set values
					for (const auto& option : options)
					{
						if (!option.value.IsBool())
						{
							APP_TRACE_LOG(LL_ERR, L"Cheat DB blacklist node: %s has invalid option value! Index: %u", description.c_str(), idx);
							CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_BLACKLIST_ITEM_INVALID_OPTION_VALUE), (void*)stData.c_str());
							return;
						}
						
						if (option.name == xorstr_(L"disabled"))
						{
							node_ctx->options.disabled = option.value.GetBool();
						}
						else if (option.name == xorstr_(L"substr"))
						{
							node_ctx->options.substr = option.value.GetBool();
						}
						else if (option.name == xorstr_(L"case"))
						{
							node_ctx->options.case_sensitive = option.value.GetBool();
						}
						else if (option.name == xorstr_(L"fatal"))
						{
							node_ctx->options.fatal = option.value.GetBool();
						}
						else
						{
							APP_TRACE_LOG(LL_ERR, L"Cheat DB blacklist node has invalid option name! Index: %u", idx);
							CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_BLACKLIST_ITEM_INVALID_OPTION_NAME), (void*)stData.c_str());
							return;
						}
					}

					APP_TRACE_LOG(LL_SYS, L"Cheat DB blacklist node #%u: Options: %d/%d/%d/%d",
						idx, node_ctx->options.disabled, node_ctx->options.substr, node_ctx->options.case_sensitive, node_ctx->options.fatal
					);

					auto param_idx = 0u;
					for (const auto& param : params)
					{
						param_idx++;
						
						if (param.IsString())
						{
							const auto wstBlacklistValue = std::wstring(param.GetString(), param.GetStringLength());
							const auto stBlacklistValue = stdext::to_ansi(wstBlacklistValue);
							const auto stDecryptedValue = !bStreamed ? VigenereCrypt::decrypt(stBlacklistValue, VigenereCrypt::STRING_CRYPT_KEY) : stBlacklistValue;
							
							APP_TRACE_LOG(LL_TRACE, L"Blacklist value: %u -> %hs(%hs)", param_idx, stBlacklistValue.c_str(), stDecryptedValue.c_str());

							node_ctx->params.emplace_back(stdext::to_wide(stDecryptedValue));
						}
						else
						{
							APP_TRACE_LOG(LL_ERR, L"Blacklist param: %u is not valid type: %u", param_idx, param.GetType());
							CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_BLACKLIST_ITEM_INVALID_PARAM_TYPE), (void*)stData.c_str());
							return;
						}
					}

					// Forward node
					this->__ProcessBlacklistNode(node_ctx);
					++node_size;
				}
			}
			// Process whitelist node
			else if (item.name == xorstr_(L"whitelist"))
			{
				if (!item.value.IsArray())
				{
					APP_TRACE_LOG(LL_ERR, L"Cheat DB stream whitelist is not an array! Type: %u", item.value.GetType());
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_WHITELIST_NOT_ARRAY), (void*)stData.c_str());
					return;
				}

				auto idx = 0u;
				const auto& whitelist = item.value.GetArray();
				APP_TRACE_LOG(LL_SYS, L"Cheat DB whitelist size: %u", whitelist.Size());

				for (const auto& whitelist_item : whitelist)
				{
					idx++;

					if (!whitelist_item.IsObject())
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB whitelist node #%u is not an object!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_WHITELIST_ITEM_NOT_OBJECT), (void*)stData.c_str());
						return;
					}
					
					const auto& whitelist_item_obj = whitelist_item.GetObject();

					// Sanity check
					if (!whitelist_item_obj.HasMember(xorstr_(L"description")) ||
						!whitelist_item_obj.HasMember(xorstr_(L"type")) ||
						!whitelist_item_obj.HasMember(xorstr_(L"params")))
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB whitelist node #%u has missing members!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_WHITELIST_ITEM_MISSING_STRUCTURE), (void*)stData.c_str());
						return;
					}

					// Check whitelist node type
					if (!whitelist_item_obj[xorstr_(L"description")].IsString() ||
						!whitelist_item_obj[xorstr_(L"type")].IsNumber() ||
						!whitelist_item_obj[xorstr_(L"params")].IsArray())
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB whitelist node #%u has invalid structure!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_WHITELIST_ITEM_INVALID_STRUCTURE), (void*)stData.c_str());
						return;
					}

					// Get whitelist nodes
					const std::wstring description = whitelist_item_obj[xorstr_(L"description")].GetString();
					const auto type = whitelist_item_obj[xorstr_(L"type")].GetUint();
					const auto& params = whitelist_item_obj[xorstr_(L"params")].GetArray();
					
					APP_TRACE_LOG(LL_SYS, L"Cheat DB whitelist node #%u: Type: %u, Params: %u", idx, type, params.Size());

					// Sanity check for nodes
					if (!description.empty() || // description should be cleared by DB builder
						type <= SCAN_WHITELIST_NULL ||
						type >= SCAN_WHITELIST_MAX ||
						params.Empty())
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB whitelist node #%u has not valid values", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_WHITELIST_ITEM_NOT_VALID_MEMBER), (void*)stData.c_str());
						return;
					}

					// Declare new whitelist node
					auto node_ctx = stdext::make_shared_nothrow<SCheatDBWhitelist>();

					// Set node values to container
					node_ctx->id = idx;
					node_ctx->type = type;

					// Iterate sub nodes, set values
					auto param_idx = 0u;
					for (const auto& param : params)
					{
						param_idx++;

						if (param.IsString())
						{
							const auto wstWhitelistValue = std::wstring(param.GetString(), param.GetStringLength());
							const auto stWhitelistValue = stdext::to_ansi(wstWhitelistValue);
							const auto stDecryptedValue = !bStreamed ? VigenereCrypt::decrypt(stWhitelistValue, VigenereCrypt::STRING_CRYPT_KEY) : stWhitelistValue;

							APP_TRACE_LOG(LL_TRACE, L"Whitelist value: %u -> %hs(%hs)", param_idx, stWhitelistValue.c_str(), stDecryptedValue.c_str());

							node_ctx->params.emplace_back(stdext::to_wide(stDecryptedValue));
						}
						else
						{
							APP_TRACE_LOG(LL_ERR, L"Whitelist param: %u is not valid type: %u", param_idx, param.GetType());
							CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_WHITELIST_ITEM_INVALID_PARAM_TYPE), (void*)stData.c_str());
							return;
						}
					}

					this->__ProcessWhitelistNode(node_ctx);
					++node_size;
				}
			}
			// Process single object node
			else if (item.name == xorstr_(L"single"))
			{
				if (!item.value.IsArray())
				{
					APP_TRACE_LOG(LL_ERR, L"Cheat DB stream single is not an array! Type: %u", item.value.GetType());
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_BASE_NOT_ARRAY), (void*)stData.c_str());
					return;
				}

				auto idx = 0u;
				const auto& singleObjects = item.value.GetArray();
				APP_TRACE_LOG(LL_SYS, L"Cheat DB single objects size: %u", singleObjects.Size());

				for (const auto& obj_item : singleObjects)
				{
					idx++;

					if (!obj_item.IsObject())
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB single object #%u is not an object!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_NOT_OBJECT), (void*)stData.c_str());
						return;
					}

					const auto& objContent = obj_item.GetObject();
					
					// Sanity check for object
					if (!objContent.HasMember(xorstr_(L"id")) ||
						!objContent.HasMember(xorstr_(L"detection_name")) ||
						!objContent.HasMember(xorstr_(L"scan_type")) ||
						!objContent.HasMember(xorstr_(L"disabled")))
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB single object #%u has missing members!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_MISSING_MEMBER), (void*)stData.c_str());
						return;
					}

					// Check node types
					if (!objContent[xorstr_(L"id")].IsString() ||
						!objContent[xorstr_(L"detection_name")].IsString() ||
						!objContent[xorstr_(L"scan_type")].IsNumber() ||
						!objContent[xorstr_(L"disabled")].IsBool())
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB single object #%u has invalid structure!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_NOT_VALID_MEMBER), (void*)stData.c_str());
						return;
					}

					// Get whitelist nodes
					const std::wstring id_w = objContent[xorstr_(L"id")].GetString();
					const std::wstring detection_name_w = objContent[xorstr_(L"detection_name")].GetString();
					const auto scan_type = objContent[xorstr_(L"scan_type")].GetUint();
					const auto disabled = objContent[xorstr_(L"disabled")].GetBool();

					const auto id_a = stdext::to_ansi(id_w);
					const auto detection_name_a = stdext::to_ansi(detection_name_w);
					
					const auto wstDecryptedID = !bStreamed ? stdext::to_wide(VigenereCrypt::decrypt(id_a, VigenereCrypt::STRING_CRYPT_KEY)) : id_w;
					const auto wstDecryptedDetectionName = !bStreamed ? stdext::to_wide(VigenereCrypt::decrypt(detection_name_a, VigenereCrypt::STRING_CRYPT_KEY)) : detection_name_w;

					APP_TRACE_LOG(LL_SYS, L"Cheat DB single object #%u(%s): Detection name: %s, Scan type: %u , Disabled: %s",
						idx, id_w.c_str(), wstDecryptedDetectionName.c_str(), scan_type, (disabled ? xorstr_(L"Yes") : xorstr_(L"No"))
					);

					// Skip disabled objects
					if (disabled)
					{
						APP_TRACE_LOG(LL_WARN, L"Cheat DB single object #%u is disabled, skipping!", idx);
						continue;
					}

					// Sanity check for nodes
					if (detection_name_w.empty() ||
						scan_type <= CHEAT_DB_SCAN_NULL ||
						scan_type >= CHEAT_DB_SCAN_MAX)
					{
						APP_TRACE_LOG(LL_ERR, L"Cheat DB single object #%u has not valid values!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_NOT_VALID_VALUE), (void*)stData.c_str());
						return;
					}

					// Declare new cheat object
					auto node_ctx = stdext::make_shared_nothrow<SCheatDBNode>();

					// Set node values to container
					node_ctx->idx = idx;
					node_ctx->id = wstDecryptedID;
					node_ctx->from_local_db = !bStreamed;
					node_ctx->type = scan_type;
					node_ctx->detection_name = wstDecryptedDetectionName;

					// Iterate sub nodes, set values
					auto param_idx = 0u;
					
					std::map <uint32_t, std::wstring> params;
					for (const auto& param : objContent)
					{
						param_idx++;

						const std::wstring stNodeKey = std::wstring(param.name.GetString(), param.name.GetStringLength());

						if (stNodeKey.find(xorstr_(L"_value")) != std::wstring::npos)
						{
							if (!param.value.IsString())
							{
								APP_TRACE_LOG(LL_ERR, L"Cheat DB stream node: %u(%u) value is not string", idx, param_idx);
								CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_NOT_VALID_PARAM_VALUE), (void*)stData.c_str());
								return;
							}

							// Get param value
							const auto wstParamValue = std::wstring(param.value.GetString(), param.value.GetStringLength());
							if (wstParamValue.empty())
							{
								APP_TRACE_LOG(LL_ERR, L"Cheat DB stream node: %u(%u) value is empty", idx, param_idx);
								CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_EMPTY_PARAM_VALUE), (void*)stData.c_str());
								return;
							}
							const auto stParamValue = stdext::to_ansi(wstParamValue);
							const auto stDecryptedValue = !bStreamed ? VigenereCrypt::decrypt(stParamValue, VigenereCrypt::STRING_CRYPT_KEY) : stParamValue;

							APP_TRACE_LOG(LL_TRACE, L"Cheat DB single object #%u: Param #%u: %s = %hs(%hs)", idx, param_idx, stNodeKey.c_str(), stParamValue.c_str(), stDecryptedValue.c_str());
							
							// Convert param_{IDX}_value > {IDX}
							std::wstring regex_output;
							try
							{
								regex_output = std::regex_replace(stNodeKey, std::wregex(xorstr_(L"[^0-9]*([0-9]+).*")), std::wstring(xorstr_(L"$1")));
							}
							catch (const std::out_of_range& e)
							{
								APP_TRACE_LOG(LL_ERR, L"Regex exception(1): %hs", e.what());
								CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_REGEX_FAIL, 1, (void*)e.what());
							}
							catch (const std::runtime_error& e)
							{
								APP_TRACE_LOG(LL_ERR, L"Regex exception(2): %hs", e.what());
								CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_REGEX_FAIL, 2, (void*)e.what());
							}
							catch (...)
							{
								APP_TRACE_LOG(LL_ERR, L"Regex exception(3)");
								CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_REGEX_FAIL, 3);
							}

							if (regex_output.empty() || !stdext::is_number(regex_output))
							{
								APP_TRACE_LOG(LL_ERR, L"Cheat DB stream node: %u(%u) regex output is not valid. Value: %s", idx, param_idx, regex_output.c_str());
								CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_PARAM_VALUE_NOT_NUMBER), (void*)stData.c_str());
								return;
							}

							const auto db_idx = _wtoi(regex_output.c_str());
							if (db_idx > 10)
							{
								APP_TRACE_LOG(LL_ERR, L"Cheat DB stream node: %u(%u) index overflow. Value: %d", idx, param_idx, db_idx);
								CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_PARAM_INDEX_OVERFLOW), (void*)stData.c_str());
								return;
							}

							// Set param value
							params[db_idx] = stdext::to_wide(stDecryptedValue);
						}				
					}
					
					// Set params
					node_ctx->params = params;

					// Process node
					this->__ProcessCheatDBNode(node_ctx);
				}
			}
			// Handle date
			else if (item.name == xorstr_(L"date"))
			{
				if (!item.value.IsNumber())
				{
					APP_TRACE_LOG(LL_ERR, L"Cheat DB stream date is not a number! Type: %u", item.value.GetType());
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_DATE_TYPE_NOT_VALID), (void*)stData.c_str());
					return;
				}
				
				const auto date = item.value.GetUint();
				m_dwCheatDBDate = date;
				
				APP_TRACE_LOG(LL_SYS, L"Cheat DB stream date: %u", date);
			}
			// Unknown node
			else
			{
				APP_TRACE_LOG(LL_ERR, L"Unknown node name: %s", item.name.GetString());

				CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_CHEAT_DB_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_UNKNOWN_NODE_NAME), (void*)stData.c_str());
				return;
			}
		}

		APP_TRACE_LOG(LL_SYS, L"Cheat DB succefully processed. Node size: %u", node_size);
	}

	bool CCheatDBManager::ProcessPackedLocalCheatDB(const std::wstring& stFileName, uint8_t& pFailStep)
	{
		// Open file
		msl::file_ptr file(stFileName, xorstr_(L"rb"));
		if (!file)
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file: %s could not open with error: %hs", stFileName.c_str(), strerror(errno));
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_OPEN_FAIL);
			return false;
		}

		// Get buffer
		const auto vBuffer = file.read();
		if (vBuffer.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file: %s read failed with error: %hs", stFileName.c_str(), strerror(errno));
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_READ_FAIL);
			return false;
		}

		if (vBuffer.size() < sizeof(SCheatDBHeader))
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file: %s corrupted file size: %u", stFileName.c_str(), vBuffer.size());
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_CORRUPTED);
			return false;
		}

		// Parse header
		const auto pkHeader = reinterpret_cast<const SCheatDBHeader*>(vBuffer.data());
		if (pkHeader->magic != NM_CREATEMAGIC('N', 'M', 'D', 'B'))
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file magic is not valid: %p", pkHeader->magic);
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_NOT_VALID);
			return false;
		}

		if (pkHeader->version != NOMERCY_CDB_VERSION)
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file version is not valid: %u", pkHeader->version);
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_VERSION_NOT_VALID);
			return false;
		}

		if (!pkHeader->raw_size)
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file raw size is not valid!");
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_SIZE_METADATA_NOT_VALID);
			return false;
		}

		if (!pkHeader->raw_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file raw hash is not valid!");
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_HASH_METADATA_NOT_VALID);
			return false;
		}

		if (!pkHeader->final_size)
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file final size is not valid!");
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_FINAL_SIZE_METADATA_NOT_VALID);
			return false;
		}

		if (!pkHeader->final_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file final hash is not valid!");
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_FINAL_HASH_METADATA_NOT_VALID);
			return false;
		}

		// Alloc
		std::unique_ptr <uint8_t[]> buf(new (std::nothrow) uint8_t[pkHeader->final_size]);
		if (!buf)
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file read buffer: %u could not allocated with error: %s", pkHeader->final_size, _wcserror(errno));
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_MEMORY_BUFFER_ALLOC_FAIL);
			return false;
		}

		// Read
		memcpy(buf.get(), vBuffer.data() + sizeof(SCheatDBHeader), pkHeader->final_size);

		// Reverse buffer
		std::reverse(buf.get(), buf.get() + pkHeader->final_size);

		// Decrypt buffer
		BasicCrypt::DecryptBuffer(buf.get(), pkHeader->final_size, 0x69);

		// Validate
		const auto current_hash = XXH32(buf.get(), pkHeader->final_size, 0);
		if (current_hash != pkHeader->final_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"Local db file final hash mismatch, corrupted data.");
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_FINAL_HASH_NOT_VALID);
			return false;
		}

		// Decrypt
		std::vector <uint8_t> decrypted_buf(pkHeader->final_size);
		try
		{
			CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec(&NoMercy::DefaultCryptionKey[0], 32, &NoMercy::DefaultCryptionKey[32]);
			dec.ProcessData(&decrypted_buf[0], reinterpret_cast<const uint8_t*>(buf.get()), pkHeader->final_size);
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Caught exception on decryption: %hs", exception.what());
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_DECRYPTION_FAIL);
			return false;
		}
	
		// Decompress
		std::vector <char> decompressed_buf(pkHeader->raw_size);

		auto decompressedsize = LZ4_decompress_safe(
			reinterpret_cast<const char*>(decrypted_buf.data()), reinterpret_cast<char*>(&decompressed_buf[0]),
			decrypted_buf.size(), decompressed_buf.size()
		);
		if (decompressedsize != (int32_t)pkHeader->raw_size)
		{
			APP_TRACE_LOG(LL_ERR, L"Decomperssed size mismatch: %d-%u", decompressedsize, pkHeader->raw_size);
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_DECOMPRESSION_FAIL);
			return false;
		}

		// Validate
		const auto decompressed_hash = XXH32(decompressed_buf.data(), decompressed_buf.size(), 0);
		if (pkHeader->raw_hash != decompressed_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"Decomperssed hash mismatch: %p-%p", decompressed_hash, pkHeader->raw_hash);
			pFailStep = static_cast<uint8_t>(ECheatDBErrorCodes::DB_FILE_DECOMPRESSED_HASH_NOT_VALID);
			return false;
		}

		// Save & validate db version
		m_dwCheatDBVersion = pkHeader->version;

		const auto ws = CApplication::Instance().NetworkMgrInstance()->GetWebSocketClient();
		if (ws)
			ws->send_cheat_db_validation_message(m_dwCheatDBVersion);

		// Process
		const auto final_data_a = std::string(decompressed_buf.data(), decompressed_buf.size());
		const auto final_data_w = stdext::to_wide(final_data_a);
		this->ProcessCheatDB(final_data_w, false); // Simply wrap to stream processing func
		return true;
	}


	void CCheatDBManager::ProcessBlockedTools(const std::wstring& stData)
	{
		APP_TRACE_LOG(LL_SYS, L"Blocked tools processing started. Data:\n'%s'", stData.c_str());
		std::size_t node_size = 0;

		// Sanity check
		if (stData.empty())
		{
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_DATA_NULL), (void*)stData.c_str());
			return;
		}

		// Load as json
		auto document = rapidjson::GenericDocument<UTF16<>>{};
		document.Parse<kParseCommentsFlag, UTF16<> >(stData.c_str());
		if (document.HasParseError())
		{
			APP_TRACE_LOG(LL_ERR, L"Blocked tool DB stream could NOT parsed! Error: %hs offset: %u", GetParseError_En(document.GetParseError()), document.GetErrorOffset());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_JSON_PARSE_FAIL), (void*)stData.c_str());
			return;
		}
		if (!document.IsObject())
		{
			APP_TRACE_LOG(LL_ERR, L"Blocked tool DB stream base is not an object! Type: %u", document.GetType());
			CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_JSON_BASE_NOT_OBJECT), (void*)stData.c_str());
			return;
		}

		// Iterate over all nodes
		for (const auto& item : document.GetObject())
		{
			APP_TRACE_LOG(LL_SYS, L"Processing node. Key: %s", item.name.GetString());

			// Process single object node
			if (item.name == xorstr_(L"single"))
			{
				if (!item.value.IsArray())
				{
					APP_TRACE_LOG(LL_ERR, L"Blocked tool DB stream single is not an array! Type: %u", item.value.GetType());
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_BASE_NOT_ARRAY), (void*)stData.c_str());
					return;
				}

				auto idx = 0u;
				const auto& singleObjects = item.value.GetArray();
				APP_TRACE_LOG(LL_SYS, L"Blocked tool DB single objects size: %u", singleObjects.Size());

				for (const auto& obj_item : singleObjects)
				{
					idx++;

					if (!obj_item.IsObject())
					{
						APP_TRACE_LOG(LL_ERR, L"Blocked tool DB single object #%u is not an object!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_NOT_OBJECT), (void*)stData.c_str());
						return;
					}

					const auto& objContent = obj_item.GetObject();

					// Sanity check for object
					if (!objContent.HasMember(xorstr_(L"id")) ||
						!objContent.HasMember(xorstr_(L"category")) ||
						!objContent.HasMember(xorstr_(L"name")) ||
						!objContent.HasMember(xorstr_(L"enabled")) ||
						!objContent.HasMember(xorstr_(L"method")) ||
						!objContent.HasMember(xorstr_(L"detection_value")) ||
						!objContent.HasMember(xorstr_(L"default_action")))
					{
						APP_TRACE_LOG(LL_ERR, L"Blocked tool DB single object #%u has missing members!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_MISSING_MEMBER), (void*)stData.c_str());
						return;
					}

					// Check node types
					if (!objContent[xorstr_(L"id")].IsString() ||
						!objContent[xorstr_(L"category")].IsString() ||
						!objContent[xorstr_(L"name")].IsString() ||
						!objContent[xorstr_(L"enabled")].IsBool() ||
						!objContent[xorstr_(L"method")].IsNumber() ||
						!objContent[xorstr_(L"detection_value")].IsString() ||
						!objContent[xorstr_(L"default_action")].IsString())
					{
						APP_TRACE_LOG(LL_ERR, L"Blocked tool DB single object #%u has invalid structure!", idx);
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_NOT_VALID_MEMBER), (void*)stData.c_str());
						return;
					}

					// Handle values
					const auto wstDetectionID		= std::wstring(objContent[xorstr_(L"id")].GetString());
					const auto wstDetectionCategory = std::wstring(objContent[xorstr_(L"category")].GetString());
					const auto wstDetectionName		= std::wstring(objContent[xorstr_(L"name")].GetString());
					const auto bDetectionEnabled	= objContent[xorstr_(L"enabled")].GetBool();
					const auto nDetectionMethod		= objContent[xorstr_(L"method")].GetUint();
					const auto wstDetectionValue	= std::wstring(objContent[xorstr_(L"detection_value")].GetString());
					const auto wstDetectionAction	= std::wstring(objContent[xorstr_(L"default_action")].GetString());

					// Format sanity check
					const std::vector <uint32_t> vecValidCategoryValues = {
						stdext::hash(xorstr_("generic")),
						stdext::hash(xorstr_("cert_provider")),
						stdext::hash(xorstr_("game_specific")),
						stdext::hash(xorstr_("memory_scanner")),
						stdext::hash(xorstr_("memory_viewer")),
						stdext::hash(xorstr_("graphic_addon")),
						stdext::hash(xorstr_("sys_monitor")),
						stdext::hash(xorstr_("ark")),
						stdext::hash(xorstr_("net_monitor")),
						stdext::hash(xorstr_("hwid_changer")),
						stdext::hash(xorstr_("memory_dumper")),
						stdext::hash(xorstr_("debug_tool")),
						stdext::hash(xorstr_("injector")),
						stdext::hash(xorstr_("disassembler")),
						stdext::hash(xorstr_("pe_tool")),
						stdext::hash(xorstr_("window_hijack"))
					};
					const std::vector <uint32_t> vecValidActionValues = {
						stdext::hash(xorstr_("warning")),
						stdext::hash(xorstr_("close_game")),
						stdext::hash(xorstr_("close_process")),
						stdext::hash(xorstr_("log")),
						stdext::hash(xorstr_("kick")),
						stdext::hash(xorstr_("temp_ban")),
						stdext::hash(xorstr_("perma_ban"))
					};
					const auto nScanMethodMaxValue = static_cast<uint32_t>(EBlockedToolScanMethods::BLOCKED_TOOL_SCAN_MAX);

					const auto nCorruptedParamLogLevel = bDetectionEnabled ? LL_ERR : LL_WARN;
					auto bHasCorruptedVal = false;
					if (wstDetectionID.empty() /* || !stdext::is_valid_uuid(wstDetectionID)*/)
					{
						APP_TRACE_LOG(nCorruptedParamLogLevel, L"Blocked tool DB single object #%u has not valid values in 'id' key!", idx);
						bHasCorruptedVal = true;
					}
					else if (wstDetectionCategory.empty() || !stdext::in_vector(vecValidCategoryValues, stdext::hash(wstDetectionCategory.c_str())))
					{
						APP_TRACE_LOG(nCorruptedParamLogLevel, L"Blocked tool DB single object #%u has not valid values in 'category' key!", idx);
						bHasCorruptedVal = true;
					}
					else if (wstDetectionName.empty())
					{
						APP_TRACE_LOG(nCorruptedParamLogLevel, L"Blocked tool DB single object #%u has not valid values in 'name' key!", idx);
						bHasCorruptedVal = true;
					}
					else if (!nDetectionMethod || nDetectionMethod > nScanMethodMaxValue)
					{
						APP_TRACE_LOG(nCorruptedParamLogLevel, L"Blocked tool DB single object #%u has not valid values in 'method' key!", idx);
						bHasCorruptedVal = true;
					}
					else if (wstDetectionValue.empty())
					{
						APP_TRACE_LOG(nCorruptedParamLogLevel, L"Blocked tool DB single object #%u has not valid values in 'detection_value' key!", idx);
						bHasCorruptedVal = true;
					}
					else if (wstDetectionAction.empty() || !stdext::in_vector(vecValidActionValues, stdext::hash(wstDetectionAction.c_str())))
					{
						APP_TRACE_LOG(nCorruptedParamLogLevel, L"Blocked tool DB single object #%u has not valid values in 'default_action' key!", idx);
						bHasCorruptedVal = true;
					}

					APP_TRACE_LOG(LL_SYS, L"Blocked tool object #%u: Detection name: %s, Category: %s, Enabled: %s, Method: %u, Value: %s, Action: %s",
						idx, wstDetectionName.c_str(), wstDetectionCategory.c_str(), (bDetectionEnabled ? xorstr_(L"Yes") : xorstr_(L"No")),
						nDetectionMethod, wstDetectionValue.c_str(), wstDetectionAction.c_str()
					);

					// Skip disabled objects
					if (!bDetectionEnabled)
					{
						APP_TRACE_LOG(LL_WARN, L"Blocked tool object #%u is disabled, skipping!", idx);
						continue;
					}

					// Validate sanity
					if (bHasCorruptedVal)
					{
						CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_SINGLE_OBJECT_ITEM_NOT_VALID_VALUE), (void*)stData.c_str());
						return;
					}

					// Parse string values
					auto nCategory = BLOCKED_TOOL_CATEGORY_NULL;
					if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("generic")))
						nCategory = BLOCKED_TOOL_CATEGORY_GENERIC;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("cert_provider")))
						nCategory = BLOCKED_TOOL_CATEGORY_CERT_PROVIDER;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("game_specific")))
						nCategory = BLOCKED_TOOL_CATEGORY_GAME_SPECIFIC;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("memory_scanner")))
						nCategory = BLOCKED_TOOL_CATEGORY_MEM_SCANNER;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("memory_viewer")))
						nCategory = BLOCKED_TOOL_CATEGORY_MEM_VIEWER;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("graphic_addon")))
						nCategory = BLOCKED_TOOL_CATEGORY_GRAPHIC_ADDON;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("sys_monitor")))
						nCategory = BLOCKED_TOOL_CATEGORY_SYS_MONITOR;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("ark")))
						nCategory = BLOCKED_TOOL_CATEGORY_ARK;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("net_monitor")))
						nCategory = BLOCKED_TOOL_CATEGORY_NET_MON;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("hwid_changer")))
						nCategory = BLOCKED_TOOL_CATEGORY_HWID_CHANGER;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("memory_dumper")))
						nCategory = BLOCKED_TOOL_CATEGORY_MEM_DUMPER;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("debug_tool")))
						nCategory = BLOCKED_TOOL_CATEGORY_DEBUG_TOOL;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("injector")))
						nCategory = BLOCKED_TOOL_CATEGORY_INJECTOR;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("disassembler")))
						nCategory = BLOCKED_TOOL_CATEGORY_DISASSEMBLER;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("pe_tool")))
						nCategory = BLOCKED_TOOL_CATEGORY_PE_TOOL;
					else if (stdext::hash(wstDetectionCategory.c_str()) == stdext::hash(xorstr_("window_hijack")))
						nCategory = BLOCKED_TOOL_CATEGORY_WINDOW_HIJACK;

					auto nActionVal = BLOCKED_TOOL_ACTION_NULL;
					if (stdext::hash(wstDetectionAction.c_str()) == stdext::hash(xorstr_("warning")))
						nActionVal = BLOCKED_TOOL_ACTION_WARNING;
					else if (stdext::hash(wstDetectionAction.c_str()) == stdext::hash(xorstr_("close_game")))
						nActionVal = BLOCKED_TOOL_ACTION_CLOSE_GAME;
					else if (stdext::hash(wstDetectionAction.c_str()) == stdext::hash(xorstr_("close_process")))
						nActionVal = BLOCKED_TOOL_ACTION_CLOSE_PROCESS;
					else if (stdext::hash(wstDetectionAction.c_str()) == stdext::hash(xorstr_("log")))
						nActionVal = BLOCKED_TOOL_ACTION_LOG;
					else if (stdext::hash(wstDetectionAction.c_str()) == stdext::hash(xorstr_("kick")))
						nActionVal = BLOCKED_TOOL_ACTION_KICK;
					else if (stdext::hash(wstDetectionAction.c_str()) == stdext::hash(xorstr_("temp_ban")))
						nActionVal = BLOCKED_TOOL_ACTION_TEMP_BAN;
					else if (stdext::hash(wstDetectionAction.c_str()) == stdext::hash(xorstr_("perma_ban")))
						nActionVal = BLOCKED_TOOL_ACTION_PERMA_BAN;
					else if (stdext::hash(wstDetectionAction.c_str()) == stdext::hash(xorstr_("force_minimize")))
						nActionVal = BLOCKED_TOOL_ACTION_FORCE_MINIMIZE;
					else if (stdext::hash(wstDetectionAction.c_str()) == stdext::hash(xorstr_("troll")))
						nActionVal = BLOCKED_TOOL_ACTION_TROLL;

					// Declare new cheat object
					auto node_ctx = stdext::make_shared_nothrow<SBlockedToolNode>();

					// Set node values to container
					node_ctx->idx = 100000 + idx; // add +100k to primary index to seperate index-es from cheat_db records 
					node_ctx->id = wstDetectionID;
					node_ctx->category = nCategory;
					node_ctx->detection_name = wstDetectionName;
					node_ctx->method = static_cast<EBlockedToolScanMethods>(nDetectionMethod);
					node_ctx->value = wstDetectionValue;
					node_ctx->action = nActionVal;

					// Process node
					this->__ProcessBlockedToolNode(node_ctx);
				}
			}
			// Handle date
			else if (item.name == xorstr_(L"date"))
			{
				if (!item.value.IsNumber())
				{
					APP_TRACE_LOG(LL_ERR, L"Blocked tool date is not a number! Type: %u", item.value.GetType());
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_DATE_TYPE_NOT_VALID), (void*)stData.c_str());
					return;
				}

				const auto date = item.value.GetUint();
				m_dwBlockedToolDate = date;

				APP_TRACE_LOG(LL_SYS, L"Blocked tool stream date: %u", date);
			}
			// Unknown node
			else
			{
				APP_TRACE_LOG(LL_ERR, L"Unknown node name: %s", item.name.GetString());

				CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_BLOCKED_TOOLS_STREAM, static_cast<uint32_t>(ECheatDBProcessingErrorCodes::DB_UNKNOWN_NODE_NAME), (void*)stData.c_str());
				return;
			}
		}

		APP_TRACE_LOG(LL_SYS, L"Blocked tools succefully processed. Node size: %u", node_size);
	}
}
