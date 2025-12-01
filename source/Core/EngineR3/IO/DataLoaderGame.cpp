#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "DataLoader.hpp"
#include "../../../Common/FilePtr.hpp"
#include "../../../Common/Keys.hpp"

namespace NoMercy
{
	enum class EGameDataErrorCodes : uint8_t
	{
		ERROR_CODE_NONE,
		ERROR_CODE_OPEN_FAIL,
		ERROR_CODE_NOT_VALID_FILE,
		ERROR_CODE_NOT_VALID_VERSION,
		ERROR_CODE_NOT_VALID_SIZE,
		ERROR_CODE_NOT_VALID_HASH,
		ERROR_CODE_NOT_VALID_FINAL_SIZE,
		ERROR_CODE_NOT_VALID_FINAL_HASH,
		ERROR_CODE_DATA_BUFFER_ALLOC_FAIL,
		ERROR_CODE_DATA_HASH_CORRUPTED,
		ERROR_CODE_DECRYPT_FAILED,
		ERROR_CODE_DECOMPRESS_FAILED,
		ERROR_CODE_DECOMPRESSED_HASH_MISMATCH,
		ERROR_CODE_DATA_EMPTY,
		ERROR_CODE_DATA_PARSE_FAIL,
		ERROR_CODE_DATA_BASE_NOT_OBJECT,
		ERROR_CODE_DATA_KEY_NOT_STRING,
		ERROR_CODE_DATA_KEY_NOT_KNOWN,
		ERROR_CODE_DATA_KEY_TYPE_NOT_CORRECT,
		ERROR_CODE_DATA_IP_ARRAY_NULL,
		ERROR_CODE_DATA_IP_COUNT_OVERFLOW,
		ERROR_CODE_DATA_IP_NOT_STRING,
		ERROR_CODE_DATA_LICENSE_NULL,
		ERROR_CODE_DATA_STAGE_NULL,
		ERROR_CODE_DATA_STAGE_UNKNOWN,
		ERROR_CODE_DATA_STAGE_KEY_NULL,
		ERROR_CODE_DATA_VERSION_NULL,
		ERROR_CODE_DATA_GAME_CODE_NULL,
		ERROR_CODE_DATA_INIT_OPTIONS_ARRAY_NULL,
		ERROR_CODE_DATA_INIT_OPTIONS_NOT_STRING,
		ERROR_CODE_DATA_INIT_OPTIONS_NODE_EMPTY,
		ERROR_CODE_DATA_HEARTBEAT_ENABLED_KEY_INVALID,
		ERROR_CODE_DATA_HEARTBEAT_TYPE_KEY_INVALID,
		ERROR_CODE_DATA_HEARTBEAT_INTERVAL_KEY_INVALID,
		ERROR_CODE_DATA_HEARTBEAT_SEED_KEY_INVALID,
		ERROR_CODE_DATA_HEARTBEAT_TYPE_VALUE_INVALID,
		ERROR_CODE_DATA_HEARTBEAT_INTERVAL_VALUE_INVALID,
		ERROR_CODE_DATA_NET_GUARD_ENABLED_KEY_INVALID,
		ERROR_CODE_DATA_NET_GUARD_VERSION_KEY_INVALID,
		ERROR_CODE_DATA_NET_GUARD_SEED_KEY_INVALID,
		ERROR_CODE_DATA_NET_GUARD_VERSION_VALUE_INVALID,
		ERROR_CODE_DATA_LAUNCHER_CHECK_INTEGRITY_KEY_INVALID,
		ERROR_CODE_DATA_LAUNCHER_EXECUTABLE_KEY_INVALID,
		ERROR_CODE_DATA_LAUNCHER_HASH_KEY_INVALID,
		ERROR_CODE_DATA_LAUNCHER_EXECUTABLE_VALUE_INVALID,
		ERROR_CODE_DATA_LAUNCHER_HASH_VALUE_INVALID,
		ERROR_CODE_DATA_UNKNOWN_KEY = 0xFF
	};

	bool CDataLoader::LoadPackedGameData(const std::wstring& stFileName, uint8_t& pFailStep)
	{
		// Open file
		msl::file_ptr file(stFileName, xorstr_(L"rb"));
		if (!file)
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game data file: %s could not open, Error: %u", stFileName.c_str(), errno);
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_OPEN_FAIL);
			return false;
		}

		// Read file info
		uint32_t magic = 0;
		file.read(&magic, sizeof(magic));
		if (magic != NM_CREATEMAGIC('N', 'M', 'G', 'D'))
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game data file magic is not valid: %p", magic);
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_NOT_VALID_FILE);
			return false;
		}

		uint32_t version = 0;
		file.read(&version, sizeof(version));
		if (version != NOMERCY_GAME_DATA_VERSION)
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game data file version is not valid: %u", magic);
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_NOT_VALID_VERSION);
			return false;
		}

		uint32_t raw_size = 0;
		file.read(&raw_size, sizeof(raw_size));
		if (!raw_size)
		{
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_NOT_VALID_SIZE);
			return false;
		}

		uint32_t raw_hash = 0;
		file.read(&raw_hash, sizeof(raw_hash));
		if (!raw_hash)
		{
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_NOT_VALID_HASH);
			return false;
		}

		uint32_t final_size = 0;
		file.read(&final_size, sizeof(final_size));
		if (!final_size)
		{
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_NOT_VALID_FINAL_SIZE);
			return false;
		}

		uint32_t final_hash = 0;
		file.read(&final_hash, sizeof(final_hash));
		if (!final_hash)
		{
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_NOT_VALID_FINAL_HASH);
			return false;
		}

		// Alloc & read
		std::unique_ptr <uint8_t[]> buf(new uint8_t[final_size]);
		if (!buf)
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game data file read buffer could not allocated");
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_BUFFER_ALLOC_FAIL);
			return false;
		}
		file.read(buf.get(), final_size);

		// Validate
		const auto current_hash = XXH32(buf.get(), final_size, 0);
		if (current_hash != final_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game data file final hash mismatch, corrupted data.");
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_HASH_CORRUPTED);
			return false;
		}

		// Decrypt
		std::vector <uint8_t> decrypted_buf(final_size);
		try
		{
			CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec(&NoMercy::DefaultCryptionKey[0], 32, &NoMercy::DefaultCryptionKey[32]);
			dec.ProcessData(&decrypted_buf[0], reinterpret_cast<const uint8_t*>(buf.get()), final_size);
		}
		catch (const CryptoPP::Exception& exception)
		{
			APP_TRACE_LOG(LL_ERR, L"Caught exception on decryption: %hs", exception.what());
			pFailStep =	static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DECRYPT_FAILED);
			return false;
		}

		// Decompress
		std::vector <char> decompressed_buf(raw_size);

		const auto decompressedsize = LZ4_decompress_safe(
			reinterpret_cast<const char*>(decrypted_buf.data()), reinterpret_cast<char*>(&decompressed_buf[0]),
			decrypted_buf.size(), decompressed_buf.size()
		);
		if (decompressedsize != (int32_t)raw_size)
		{
			APP_TRACE_LOG(LL_ERR, L"Decomperssed size mismatch: %d-%u", decompressedsize, raw_size);
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DECOMPRESS_FAILED);
			return false;
		}

		// Validate
		const auto decompressed_hash = XXH32(decompressed_buf.data(), decompressed_buf.size(), 0);
		if (raw_hash != decompressed_hash)
		{
			APP_TRACE_LOG(LL_ERR, L"Decomperssed hash mismatch: %p-%p", decompressed_hash, raw_hash);
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DECOMPRESSED_HASH_MISMATCH);
			return false;
		}

		// Process
		const auto stBuffer = std::string(decompressed_buf.data(), decompressed_buf.size());
		const auto wstBuffer = stdext::to_wide(stBuffer);
		return this->ProcessGameData(wstBuffer, pFailStep);
	}

	bool CDataLoader::ProcessGameData(const std::wstring& stContent, uint8_t& pFailStep)
	{
		static const auto lstKnownSections = {
			xorstr_(L"ip_addresses"), xorstr_(L"license_code"), xorstr_(L"executable_hash"),
			xorstr_(L"game_version"), xorstr_(L"game_code"), xorstr_(L"init_options"), xorstr_(L"client_limit"), 
			xorstr_(L"disabled"), xorstr_(L"heartbeat"), xorstr_(L"net_guard"), xorstr_(L"launcher"),
			xorstr_(L"use_crash_handler"), xorstr_(L"compability_mode"), xorstr_(L"stage_key"),
			xorstr_(L"stage")
		};

		if (stContent.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game data file is empty");
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_EMPTY);
			return false;
		}
		
		auto document = rapidjson::GenericDocument<UTF16<>>{};
		document.Parse<kParseCommentsFlag, UTF16<> >(stContent.c_str());
		if (document.HasParseError())
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game data could NOT parsed! Error: %hs offset: %u", GetParseError_En(document.GetParseError()), document.GetErrorOffset());
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_PARSE_FAIL);
			return false;
		}
		if (!document.IsObject())
		{
			APP_TRACE_LOG(LL_ERR, L"NoMercy game data base is not an object! Type: %u", document.GetType());
			pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_BASE_NOT_OBJECT);
			return false;
		}

		size_t idx = 0;
		std::vector <std::wstring> vProcessedKeys;
		for (auto node = document.MemberBegin(); node != document.MemberEnd(); ++node)
		{
			idx++;

			if (!node->name.IsString())
			{
				APP_TRACE_LOG(LL_ERR, L"NoMercy game data node: %u key is not an string! Key: %s Type: %u",
					idx, node->name.IsString() ? node->name.GetString() : xorstr_(L"<not_string>"), node->name.GetType()
				);
				pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_KEY_NOT_STRING);
				return false;
			}

			const std::wstring id = node->name.GetString();
			// APP_TRACE_LOG(LL_SYS, L"[%u] Node: %s", idx, id.c_str());

			if (std::find(lstKnownSections.begin(), lstKnownSections.end(), id) == lstKnownSections.end())
			{
				APP_TRACE_LOG(LL_ERR, L"NoMercy game data node: %s is not an known section!", id.c_str());
				// pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_KEY_NOT_KNOWN);
				// return false;
				continue;
			}

			if (((id == xorstr_(L"ip_addresses") || id == xorstr_(L"init_options")) && !node->value.IsArray()) ||
				((id == xorstr_(L"license_code") || id == xorstr_(L"executable_hash") || id == xorstr_(L"stage") || id == xorstr_(L"stage_key")) && !node->value.IsString()) ||
				((id == xorstr_(L"game_version") || id == xorstr_(L"game_code") || id == xorstr_(L"client_limit")) && !node->value.IsNumber()) ||
				((id == xorstr_(L"disabled") || id == xorstr_(L"use_crash_handler") || id == xorstr_(L"compability_mode")) && !node->value.IsBool()) ||
				((id == xorstr_(L"heartbeat") || id == xorstr_(L"net_guard") || id == xorstr_(L"launcher")) && !node->value.IsObject()))
			{
				APP_TRACE_LOG(LL_ERR, L"NoMercy game data node: %u type is not correct! Key: %s Type: %u", idx, id.c_str(), node->value.GetType());
				pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_KEY_TYPE_NOT_CORRECT);
				return false;
			}

			switch (stdext::hash(id.c_str()))
			{
				case stdext::hash("ip_addresses"):
				{
					if (!node->value.GetArray().Size())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data ip array is null");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_IP_ARRAY_NULL);
						return false;
					}

					size_t child_idx = 0;
					for (const auto& p : node->value.GetArray())
					{
						child_idx++;

						if (child_idx > 4)
						{
							APP_TRACE_LOG(LL_ERR, L"NoMercy game data ip count overflow");
							pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_IP_COUNT_OVERFLOW);
							return false;
						}

						if (!p.IsString())
						{
							APP_TRACE_LOG(LL_ERR, L"NoMercy game data ip node: %u is not string. type: %u", child_idx, p.GetType());
							pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_IP_NOT_STRING);
							return false;
						}
						NoMercyCore::CApplication::Instance().DataInstance()->AddLicensedIp(p.GetString());
					}
				} break;
				case stdext::hash("stage"):
				{
					const std::wstring stage = node->value.GetString();
					if (stage.empty())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data stage is null");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_STAGE_NULL);
						return false;
					}

					DWORD dwStage = 0;
					if (stage == xorstr_(L"dev"))
						dwStage = STATE_DEV;
					else if (stage == xorstr_(L"beta"))
						dwStage = STATE_BETA;
					else if (stage == xorstr_(L"rc"))
						dwStage = STATE_RC;
					else if (stage == xorstr_(L"rtm"))
						dwStage = STATE_RTM;
					else
					{
						APP_TRACE_LOG(LL_ERR, L"Unknown stage: %s", stage.c_str());
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_STAGE_UNKNOWN);
						return false;
					}

					NoMercyCore::CApplication::Instance().DataInstance()->SetStage(dwStage, stage);
				} break;
				case stdext::hash("stage_key"):
				{
					const auto dwStage = NoMercyCore::CApplication::Instance().DataInstance()->GetStage();
					if (dwStage == STATE_DEV || dwStage == STATE_BETA)
					{
						const std::wstring stagekey = node->value.GetString();
						if (stagekey.empty())
						{
							APP_TRACE_LOG(LL_ERR, L"NoMercy game data stage key is null");
							pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_STAGE_KEY_NULL);
							return false;
						}

						NoMercyCore::CApplication::Instance().DataInstance()->SetStageKey(stagekey.c_str());
					}
				} break;
				case stdext::hash("license_code"):
				{
					const std::wstring license = node->value.GetString();
					if (license.empty())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data license is null");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_LICENSE_NULL);
						return false;
					}
					NoMercyCore::CApplication::Instance().DataInstance()->SetLicenseCode(license.c_str());

					if (CApplication::Instance().AppIsClient())
					{
						std::wstring strStandaloneLicense = xorstr_(L"ABCDEF123490");
						if (!wcscmp(license.c_str(), strStandaloneLicense.c_str()))
							NoMercyCore::CApplication::Instance().DataInstance()->SetAppType(NM_STANDALONE);
						else
							NoMercyCore::CApplication::Instance().DataInstance()->SetAppType(NM_CLIENT);
					}
				} break;
				case stdext::hash("executable_hash"):
				{
					const std::wstring correct_hash = node->value.GetString();
					if (!correct_hash.empty())
					{
						APP_TRACE_LOG(LL_SYS, L"Correct executable hash: %s", correct_hash.c_str());
						const auto executable = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath();
						if (!executable.empty())
						{
							APP_TRACE_LOG(LL_SYS, L"Executable: %s", executable.c_str());
							const auto current_hash = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(executable);
							if (!current_hash.empty())
							{
								APP_TRACE_LOG(LL_SYS, L"Current executable hash: %s", current_hash.c_str());
								if (correct_hash != current_hash)
								{
									APP_TRACE_LOG(LL_CRI, L"Executable hash mismatch!");
									CApplication::Instance().OnCloseRequest(EXIT_ERR_CORRUPTED_APPLICATION_EXECUTABLE, 0);
									return false;
								}
							}
						}
					}
				} break;
				case stdext::hash("game_version"):
				{
					const auto game_version = node->value.GetUint();
					if (!game_version)
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data version is null");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_VERSION_NULL);
						return false;
					}
					NoMercyCore::CApplication::Instance().DataInstance()->SetGameVersion(game_version);
				} break;
				case stdext::hash("game_code"):
				{
					const auto game_code = node->value.GetUint();
					if (!game_code)
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data game code is null");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_GAME_CODE_NULL);
						return false;
					}
					NoMercyCore::CApplication::Instance().DataInstance()->SetGameCode(game_code);
				} break;
				case stdext::hash("init_options"):
				{
					if (!node->value.GetArray().Size())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data init_options is null");
						// pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_INIT_OPTIONS_ARRAY_NULL);
						// return false;
					}
					else
					{
						uint64_t dwOptions = 0;

						size_t child_idx = 0;
						for (const auto& p : node->value.GetArray())
						{
							child_idx++;

							if (!p.IsString())
							{
								APP_TRACE_LOG(LL_ERR, L"NoMercy game data init_options node: %u is not string. type: %u", child_idx, p.GetType());
								pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_INIT_OPTIONS_NOT_STRING);
								return false;
							}

							const auto stNode = std::wstring(p.GetString(), p.GetStringLength());
							if (stNode.empty())
							{
								APP_TRACE_LOG(LL_ERR, L"NoMercy game data init_options node: %u is empty", child_idx);
								pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_INIT_OPTIONS_NODE_EMPTY);
								return false;
							}

							switch (stdext::hash(stNode.c_str()))
							{
								case stdext::hash("silent_mode"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_RUN_SILENT_MODE;
								} break;

								case stdext::hash("disable_log_file_telemetry"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_DISABLE_LOG_FILE_TELEMETRY;
								} break;

								case stdext::hash("block_system_handle_access"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_BLOCK_SYSTEM_OWNED_HANDLE_ACCESS;
								} break;
								
								case stdext::hash("hook_game_process_winapi_functions"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_HOOK_GAME_PROCESS_CRITICAL_WINAPI_FUNCTIONS;
								} break;

								case stdext::hash("hook_game_engine_functions"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_HOOK_GAME_ENGINE_CRITICAL_FUNCTIONS;
								} break;

								case stdext::hash("protect_graphic_engine_functions"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_PROTECT_GRAPHIC_ENGINE_FUNCTIONS;
								} break;

								case stdext::hash("always_protect_game_screen"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALWAYS_PROTECT_GAME_SCREEN;
								} break;

								case stdext::hash("block_switch_window"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_BLOCK_SWITCH_WINDOW;
								} break;
								
								case stdext::hash("disable_display_in_system_tray"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_DISABLE_DISPLAY_IN_TRAY;
								} break;

								case stdext::hash("allow_virtual_machine"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALLOW_VIRTUAL_MACHINE;
								} break;

								case stdext::hash("allow_mouse_macro"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALLOW_MOUSE_MACRO;
								} break;

								case stdext::hash("allow_keyboard_macro"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALLOW_KEYBOARD_MACRO;
								} break;

								case stdext::hash("allow_user_debugger"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALLOW_USER_DEBUGGER;
								} break;
								
								case stdext::hash("allow_kernel_debugger"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALLOW_KERNEL_DEBUGGER;
								} break;
								
								case stdext::hash("allow_disabled_secure_boot"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALLOW_SECURE_BOOT_DISABLE;
								} break;
								
								case stdext::hash("allow_enabled_test_signature_mode"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALLOW_ENABLED_TEST_SIGNATURE;
								} break;
								
								case stdext::hash("alloc_disabled_hvci"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALLOW_HVCI_DISABLE;
								} break;
								
								case stdext::hash("alloc_disabled_tpm"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_ALLOW_TPM_DISABLE;
								} break;

								case stdext::hash("disable_game_memory_anti_tamper"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_DISABLE_GAME_MEMORY_ANTI_TAMPER;
								} break;

								case stdext::hash("disable_game_process_window_watchdog"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_DISABLE_WATCHDOG_INSIDE_GAME_PROCESS;
								} break;

								case stdext::hash("disable_game_process_win32_message_hook"):
								{
									dwOptions |= NoMercyCore::EInitOptions::INIT_OPTION_DISABLE_WIN32_MESSAGE_HOOK_INSIDE_GAME_PROCESS;
								} break;

								default:
									break;
							}
						}
						
						NoMercyCore::CApplication::Instance().DataInstance()->SetInitOptions(dwOptions);
					}
				} break;
				case stdext::hash("client_limit"): // 0 = unlimited
				{
					NoMercyCore::CApplication::Instance().DataInstance()->SetClientLimit(node->value.GetUint());
				} break;
				case stdext::hash("disabled"):
				{
					NoMercyCore::CApplication::Instance().DataInstance()->SetDisabled(node->value.GetBool());
				} break;
				case stdext::hash("use_crash_handler"):
				{
					NoMercyCore::CApplication::Instance().DataInstance()->SetUseCrashHandler(node->value.GetBool());
				} break;
				case stdext::hash("compability_mode"):
				{
					NoMercyCore::CApplication::Instance().DataInstance()->SetCompabilityMode(node->value.GetBool());
				} break;
				case stdext::hash("heartbeat"):
				{
					// Check sub nodes existance and type
					if (!node->value.HasMember(xorstr_(L"enabled")) || !node->value[xorstr_(L"enabled")].IsBool())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data heartbeat:enabled key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_HEARTBEAT_ENABLED_KEY_INVALID);
						return false;
					}
					if (!node->value.HasMember(xorstr_(L"type")) || !node->value[xorstr_(L"type")].IsUint())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data heartbeat:type key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_HEARTBEAT_TYPE_KEY_INVALID);
						return false;
					}
					if (!node->value.HasMember(xorstr_(L"heartbeat_interval")) || !node->value[xorstr_(L"heartbeat_interval")].IsUint())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data heartbeat:heartbeat_interval key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_HEARTBEAT_INTERVAL_KEY_INVALID);
						return false;
					}
					if (!node->value.HasMember(xorstr_(L"heartbeat_seed")) || !node->value[xorstr_(L"heartbeat_seed")].IsUint64())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data heartbeat:heartbeat_seed key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_HEARTBEAT_SEED_KEY_INVALID);
						return false;
					}

					// Get values
					const auto enabled = node->value[xorstr_(L"enabled")].GetBool();
					const auto type = node->value[xorstr_(L"type")].GetUint();
					const auto heartbeat_interval = node->value[xorstr_(L"heartbeat_interval")].GetUint();
					const auto heartbeat_seed = node->value[xorstr_(L"heartbeat_seed")].GetUint64();

					APP_TRACE_LOG(LL_SYS, 
						L"NoMercy game data heartbeat:enabled = %d heartbeat:type = %u heartbeat:heartbeat_interval = %u heartbeat:heartbeat_seed = %llu",
						enabled, type, heartbeat_interval, heartbeat_seed
					);

					// Check values
					if (type != 1 && type != 2)
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data heartbeat:type value is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_HEARTBEAT_TYPE_VALUE_INVALID);
						return false;
					}
					if (heartbeat_interval < 5000)
					{
						APP_TRACE_LOG(LL_ERR, L"Heartbeat interval must be greater or equal than 5000ms");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_HEARTBEAT_INTERVAL_VALUE_INVALID);
						return false;
					}
					
					// Set values
					NoMercyCore::CApplication::Instance().DataInstance()->SetHeartbeatEnabled(enabled);
					NoMercyCore::CApplication::Instance().DataInstance()->SetHeartbeatType(type);
					NoMercyCore::CApplication::Instance().DataInstance()->SetHeartbeatInterval(heartbeat_interval);
					NoMercyCore::CApplication::Instance().DataInstance()->SetHeartbeatSeed(heartbeat_seed);
				} break;
				case stdext::hash("net_guard"):
				{
					// Check sub nodes existance and type
					if (!node->value.HasMember(xorstr_(L"enabled")) || !node->value[xorstr_(L"enabled")].IsBool())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data net_guard:enabled key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_NET_GUARD_ENABLED_KEY_INVALID);
						return false;
					}
					if (!node->value.HasMember(xorstr_(L"version")) || !node->value[xorstr_(L"version")].IsUint())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data net_guard:version key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_NET_GUARD_VERSION_KEY_INVALID);
						return false;
					}
					if (!node->value.HasMember(xorstr_(L"seed")) || !node->value[xorstr_(L"seed")].IsUint64())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data net_guard:seed key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_NET_GUARD_SEED_KEY_INVALID);
						return false;
					}

					// Get values
					const auto enabled = node->value[xorstr_(L"enabled")].GetBool();
					const auto version = node->value[xorstr_(L"version")].GetUint();
					const auto seed = node->value[xorstr_(L"seed")].GetUint64();
					
					APP_TRACE_LOG(LL_SYS, L"NoMercy game data net_guard:enabled = %d net_guard:version = %u net_guard:seed = %llu", enabled, version, seed);

					// Check values
					if (version != 1)
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data net_guard:version value is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_NET_GUARD_VERSION_VALUE_INVALID);
						return false;
					}

					// Set values
					NoMercyCore::CApplication::Instance().DataInstance()->SetNetGuardEnabled(enabled);
					NoMercyCore::CApplication::Instance().DataInstance()->SetNetGuardVersion(version);
					NoMercyCore::CApplication::Instance().DataInstance()->SetNetGuardSeed(seed);
				} break;
				case stdext::hash("launcher"):
				{
					// Check sub nodes existance and type
					if (!node->value.HasMember(xorstr_(L"check_integrity")) || !node->value[xorstr_(L"check_integrity")].IsBool())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data launcher:check_integrity key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_LAUNCHER_CHECK_INTEGRITY_KEY_INVALID);
						return false;
					}
					if (!node->value.HasMember(xorstr_(L"executable")) || !node->value[xorstr_(L"executable")].IsString())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data launcher:executable key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_LAUNCHER_EXECUTABLE_KEY_INVALID);
						return false;
					}
					if (!node->value.HasMember(xorstr_(L"hash")) || !node->value[xorstr_(L"hash")].IsString())
					{
						APP_TRACE_LOG(LL_ERR, L"NoMercy game data launcher:hash key is not valid");
						pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_LAUNCHER_HASH_KEY_INVALID);
						return false;
					}

					// Get values
					const auto check_integrity = node->value[xorstr_(L"check_integrity")].GetBool();
					const auto executable = node->value[xorstr_(L"executable")].GetString();
					const auto hash = std::wstring(node->value[xorstr_(L"hash")].GetString(), node->value[xorstr_(L"hash")].GetStringLength());

					APP_TRACE_LOG(LL_SYS, L"NoMercy game data launcher:check_integrity = %d launcher:executable = %s launcher:hash = %s", check_integrity, executable, hash.c_str());

					// Check values
					if (check_integrity)
					{
						if (!executable || !*executable || !wcslen(executable))
						{
							APP_TRACE_LOG(LL_ERR, L"NoMercy game data launcher:executable value is not valid");
							pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_LAUNCHER_EXECUTABLE_VALUE_INVALID);
							return false;
						}
						/*
						if (!hash || !*hash || !wcslen(hash))
						{
							APP_TRACE_LOG(LL_ERR, L"NoMercy game data launcher:hash value is not valid");
							pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_LAUNCHER_HASH_VALUE_INVALID);
							return false;
						}
						*/
					}

					// Set values
					NoMercyCore::CApplication::Instance().DataInstance()->SetLauncherIntegrityCheckEnabled(check_integrity);
					NoMercyCore::CApplication::Instance().DataInstance()->SetLauncherExecutable(executable);
					NoMercyCore::CApplication::Instance().DataInstance()->SetLauncherExecutableHash(hash);
				} break;
				default:
					APP_TRACE_LOG(LL_ERR, L"NoMercy game data unknown key: %s", id.c_str());
					pFailStep = static_cast<uint8_t>(EGameDataErrorCodes::ERROR_CODE_DATA_UNKNOWN_KEY);
					return false;
			}
			vProcessedKeys.emplace_back(id);
		}

		return true;
	}
};
