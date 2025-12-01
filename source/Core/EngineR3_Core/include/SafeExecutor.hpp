#pragma once
#include "AnyCall.hpp"
#include "ExitHelper.hpp"
#include "../../EngineR3_Core/include/WinAPIManager.hpp"
#include "../../EngineR3_Core/include/ErrorIDs.hpp"
#include "../../EngineR3_Core/include/Application.hpp"
#include <ProtectionMacros.h>
#include <optional>
#include <winsta.h>
#include <DbgHelp.h>
#include <WtsApi32.h>
#include <lazy_importer.hpp>

#ifndef IS_VALID_SMART_PTR
#define IS_VALID_SMART_PTR(ptr)		(ptr && ptr.get())
#endif

namespace NoMercyCore
{
	static constexpr auto STACK_MAX_FRAME_COUNT = 32;
	static constexpr auto EXCEPTION_CPP_MAGIC = 0xE06D7363;

	enum ESafeExecutorFunctionIds : uint32_t
	{
		SAFE_FUNCTION_ID_NULL,
		SAFE_FUNCTION_ID_TEST,
		SAFE_FUNCTION_ID_CREATE_INSTANCE,
		SAFE_FUNCTION_ID_RELEASE_INSTANCE,
		SAFE_FUNCTION_ID_PREPARE_CORE,
		SAFE_FUNCTION_ID_INITIALIZE,
		SAFE_FUNCTION_ID_DECREASE_PRIV,
		SAFE_FUNCTION_ID_TELEMETRY_LOG,
		SAFE_FUNCTION_ID_SAFE_THREAD_EXEC,
		SAFE_FUNCTION_ID_NET_IPC_PACKET_DISPATCHER,
		SAFE_FUNCTION_ID_SMBIOS_PARSE
	};
	enum ESafeExecutorExceptions : int32_t
	{
		SAFE_EXECUTOR_NOT_WORKED = -1,
		SAFE_EXECUTOR_NO_EXCEPTION,
		SAFE_EXECUTOR_CPP_EXCEPTION_INVALID_ARGUMENT,
		SAFE_EXECUTOR_CPP_EXCEPTION_OUT_OF_RANGE,
		SAFE_EXECUTOR_CPP_EXCEPTION_LOGIC_ERROR,
		SAFE_EXECUTOR_CPP_EXCEPTION_SYSTEM_ERROR,
		SAFE_EXECUTOR_CPP_EXCEPTION_RUNTIME_ERROR,
		SAFE_EXECUTOR_CPP_EXCEPTION_BAD_ALLOC,
		SAFE_EXECUTOR_CPP_EXCEPTION_STD,
		SAFE_EXECUTOR_UNHANDLED_EXCEPTION,
		SAFE_EXECUTOR_SEH_EXCEPTION,
		SAFE_EXECUTOR_UNKNOWN_DATA_TYPE
	};

	struct SSafeExecutorStackInformation
	{
		uint64_t idx{ 0 };
		uint64_t frame{ 0 };
		char module_name[32]{ '\0' };
		char image_name[256]{ '\0' };
		char loaded_image_name[256]{ '\0' };
		char symbol_name[256]{ '\0' };
		char file_name[256]{ '\0' };
		uint32_t file_line{ 0 };
	};
	struct SSafeExecutorExceptionContext
	{
		uintptr_t address{ 0 };
		char address_symbol[300]{ '\0' };
		uint32_t code{ 0 };
		uint32_t flags{ 0 };
		std::map <std::string, uint32_t> registers{};
		std::vector <std::shared_ptr <SSafeExecutorStackInformation>> stack{};
	};
	struct SSafeExecutorContext
	{
		uint32_t index{ 0 };
		int32_t return_code{ SAFE_EXECUTOR_NOT_WORKED };
		std::string error_message{};
		uint32_t error_code{ 0 };
		std::optional <intmax_t> return_value{};
		std::shared_ptr <SSafeExecutorExceptionContext> exception{};
	};

	static bool ServiceMessageBox(const std::string& stTitle, const std::string& stMessage, WORD wType)
	{
		auto bRet = false;

//		__PROTECTOR_START__("svc_msg_box_a");

		auto dwResponse = 0UL;
		bRet = WTSSendMessageA(
			WTS_CURRENT_SERVER_HANDLE,
			WTSGetActiveConsoleSessionId(),
			const_cast<LPSTR>(stTitle.c_str()),
			static_cast<DWORD>(stdext::CRT::string::_strlen_a(stTitle.c_str())),
			const_cast<LPSTR>(stMessage.c_str()),
			static_cast<DWORD>(stdext::CRT::string::_strlen_a(stMessage.c_str())),
			wType,
			0,
			&dwResponse,
			FALSE
		);

		if (!bRet)
		{
			bRet = 0 != ShellMessageBoxA(0, 0, stMessage.c_str(), stTitle.c_str(), wType);
		}

		if (!bRet)
		{
			const auto wstMessage = stdext::to_wide(stMessage);
			const auto wstTitle = stdext::to_wide(stTitle);

			UNICODE_STRING wTitle;
			RtlInitUnicodeString(&wTitle, wstTitle.c_str());

			UNICODE_STRING wText;
			RtlInitUnicodeString(&wText, wstMessage.c_str());

			ULONG_PTR params[4] = {
				(ULONG_PTR)&wText,
				(ULONG_PTR)&wTitle,
				(ULONG)NoMercyCore::WinAPI::ResponseButtonOK,
				INFINITE
			};

			ULONG res = 0;
			bRet = NT_SUCCESS(NtRaiseHardError(STATUS_SERVICE_NOTIFICATION, 4, 0x3, params, 0, &res));
		}

		if (!bRet && g_winAPIs && g_winAPIs->MessageBoxTimeout)
		{
			bRet = 0 != g_winAPIs->MessageBoxTimeout(0, stMessage.c_str(), stTitle.c_str(), wType, 0, 5000);
		}

//		__PROTECTOR_END__("svc_msg_box_a");

		return bRet;
	}
	static bool ServiceMessageBox(const std::wstring& wstTitle, const std::wstring& wstMessage, WORD wType)
	{
		auto bRet = false;

//		__PROTECTOR_START__("svc_msg_box_w");

		auto dwResponse = 0UL;
		bRet = WTSSendMessageW(
			WTS_CURRENT_SERVER_HANDLE,
			WTSGetActiveConsoleSessionId(),
			const_cast<LPWSTR>(wstTitle.c_str()),
			static_cast<DWORD>(stdext::CRT::string::_strlen_w(wstTitle.c_str())) * 2,
			const_cast<LPWSTR>(wstMessage.c_str()),
			static_cast<DWORD>(stdext::CRT::string::_strlen_w(wstMessage.c_str())) * 2,
			wType,
			0,
			&dwResponse,
			FALSE
		);

		if (!bRet)
		{
			bRet = 0 != ShellMessageBoxW(0, 0, wstMessage.c_str(), wstTitle.c_str(), wType);
		}

		if (!bRet)
		{
			UNICODE_STRING wTitle;
			RtlInitUnicodeString(&wTitle, wstTitle.c_str());

			UNICODE_STRING wText;
			RtlInitUnicodeString(&wText, wstMessage.c_str());

			ULONG_PTR params[4] = {
				(ULONG_PTR)&wText,
				(ULONG_PTR)&wTitle,
				(ULONG)NoMercyCore::WinAPI::ResponseButtonOK,
				INFINITE
			};

			ULONG res = 0;
			bRet = NT_SUCCESS(NtRaiseHardError(STATUS_SERVICE_NOTIFICATION, 4, 0x3, params, 0, &res));
		}

//		__PROTECTOR_END__("svc_msg_box_w");

		return bRet;
	}
	inline bool GetSymbolName(DWORD64 ullAddress, std::string& stName, PDWORD64 pdw64Displacement, PDWORD64 pdwSymbolAddress = nullptr, HANDLE hProcess = NtCurrentProcess())
	{
		static const auto fnSymGetSymFromAddr64 = LI_FN(SymGetSymFromAddr64).forwarded_safe();
		if (ullAddress && fnSymGetSymFromAddr64)
		{
			BYTE pBuffer[sizeof(IMAGEHLP_SYMBOL64) + MAX_SYM_NAME + 1] = { 0x0 };

			auto pSymbol64 = reinterpret_cast<IMAGEHLP_SYMBOL64*>(pBuffer);
			pSymbol64->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
			pSymbol64->MaxNameLength = MAX_SYM_NAME;

			auto dwDisplacement64 = 0ULL;
			if (fnSymGetSymFromAddr64(hProcess, ullAddress, &dwDisplacement64, pSymbol64))
			{
				stName.assign(pSymbol64->Name);
				if (pdwSymbolAddress) *pdwSymbolAddress = pSymbol64->Address;
				if (pdw64Displacement) *pdw64Displacement = dwDisplacement64;
				return true;
			}
		}
		return false;
	}

	using TSafeExecutorDefaultHandler = std::function<bool()>;
	
	class CSafeExecutor : public CAnyCaller
	{
	public:
		virtual ~CSafeExecutor() = default;
		CSafeExecutor() = default;
		CSafeExecutor(bool close_on_fail) :
			m_close_on_fail(close_on_fail)
		{
		};

		template <typename T>
		std::unique_ptr <SSafeExecutorContext> SafeExec(uint32_t index, const std::any& fn)
		{
			this->add_fn(index, fn);

			SSafeExecutorContext ctx{ 0 };
			ctx.index = index;
			ctx.return_code = SAFE_EXECUTOR_NOT_WORKED;

			this->SafeExecImpl<T>(ctx);
			return this->SafeExecReturn(ctx);
		}

		template <typename T, typename... Args>
		std::unique_ptr <SSafeExecutorContext> SafeExecArg(uint32_t index, const std::any& fn, Args&&... args)
		{
			this->add_fn(index, fn);

			SSafeExecutorContext ctx{ 0 };
			ctx.index = index;
			ctx.return_code = SAFE_EXECUTOR_NOT_WORKED;

			this->SafeExecImplArg<T>(ctx, std::forward<Args>(args)...);
			return this->SafeExecReturn(ctx);
		}

	protected:
		inline std::unique_ptr <SSafeExecutorContext> SafeExecReturn(_In_ SSafeExecutorContext& ctx)
		{
			/*
			const auto ret = ctx.return_code;

			if (m_close_on_fail && ret != SAFE_EXECUTOR_NO_EXCEPTION)
			{
				const auto ex_msg = fmt::format(xorstr_(L"Exception: {0} ({1}) detected!"), ctx.error_code, ctx.error_message);
				switch (ret)
				{
					case SAFE_EXECUTOR_CPP_EXCEPTION_INVALID_ARGUMENT:
					case SAFE_EXECUTOR_CPP_EXCEPTION_OUT_OF_RANGE:
					case SAFE_EXECUTOR_CPP_EXCEPTION_LOGIC_ERROR:
					case SAFE_EXECUTOR_CPP_EXCEPTION_SYSTEM_ERROR:
					case SAFE_EXECUTOR_CPP_EXCEPTION_RUNTIME_ERROR:
					case SAFE_EXECUTOR_CPP_EXCEPTION_BAD_ALLOC:
					case SAFE_EXECUTOR_CPP_EXCEPTION_STD:
						SafeExitProcess(CORE_ERROR_SAFE_EXECUTOR_CPP_EXCEPTION, ctx.index, ex_msg);
						break;
						
					case SAFE_EXECUTOR_UNHANDLED_EXCEPTION:
						SafeExitProcess(CORE_ERROR_SAFE_EXECUTOR_CPP_UNHANDLED_EXCEPTION, ctx.index, ex_msg);
						break;
						
					case SAFE_EXECUTOR_SEH_EXCEPTION:
						SafeExitProcess(CORE_ERROR_SAFE_EXECUTOR_SEH_EXCEPTION, ctx.index, ex_msg);
						break;
						
					default:
						break;
				}
			}
			*/
			return stdext::make_unique_nothrow<SSafeExecutorContext>(ctx);
		}

		inline uint32_t SafeSehExceptionParser(_Inout_ SSafeExecutorContext& ctx, const uint32_t code, const EXCEPTION_POINTERS* pEP)
		{
			if (!pEP || !pEP->ExceptionRecord)
				goto _end;

			ctx.exception = stdext::make_shared_nothrow<SSafeExecutorExceptionContext>();
			if (!IS_VALID_SMART_PTR(ctx.exception))
				goto _end;

			// Basic exception data
			{
				ctx.exception->address = (uintptr_t)pEP->ExceptionRecord->ExceptionAddress;

				std::string stExceptionAddrSymbol;
				GetSymbolName((DWORD64)PtrToPtr64(pEP->ExceptionRecord->ExceptionAddress), stExceptionAddrSymbol, nullptr);
				stdext::CRT::string::_strncpy_a(ctx.exception->address_symbol, sizeof(ctx.exception->address_symbol), stExceptionAddrSymbol.c_str(), stExceptionAddrSymbol.size());

				ctx.exception->code = pEP->ExceptionRecord->ExceptionCode;
				ctx.exception->flags = pEP->ExceptionRecord->ExceptionFlags;
			}

			// Registers
			if (pEP->ContextRecord)
			{
				auto pContext = *pEP->ContextRecord;

#ifndef _M_X64
				ctx.exception->registers.emplace(xorstr_("Eax"), pContext.Eax);
				ctx.exception->registers.emplace(xorstr_("Ebx"), pContext.Ebx);
				ctx.exception->registers.emplace(xorstr_("Ecx"), pContext.Ecx);
				ctx.exception->registers.emplace(xorstr_("Edx"), pContext.Edx);
				ctx.exception->registers.emplace(xorstr_("Esi"), pContext.Esi);
				ctx.exception->registers.emplace(xorstr_("Edi"), pContext.Edi);
				ctx.exception->registers.emplace(xorstr_("Ebp"), pContext.Ebp);
				ctx.exception->registers.emplace(xorstr_("Esp"), pContext.Esp);
#else
				ctx.exception->registers.emplace(xorstr_("Rax"), pContext.Rax);
				ctx.exception->registers.emplace(xorstr_("Rbx"), pContext.Rbx);
				ctx.exception->registers.emplace(xorstr_("Rcx"), pContext.Rcx);
				ctx.exception->registers.emplace(xorstr_("Rdx"), pContext.Rdx);
				ctx.exception->registers.emplace(xorstr_("Rsi"), pContext.Rsi);
				ctx.exception->registers.emplace(xorstr_("Rdi"), pContext.Rdi);
				ctx.exception->registers.emplace(xorstr_("Rbp"), pContext.Rbp);
				ctx.exception->registers.emplace(xorstr_("Rsp"), pContext.Rsp);
#endif
			}

			// Stack
			{
				const auto fnRtlCaptureStackBackTrace = LI_FN(RtlCaptureStackBackTrace).forwarded_safe();
				const auto fnSymGetModuleInfo64 = LI_FN(SymGetModuleInfo64).forwarded_safe();
				const auto fnSymGetLineFromAddr64 = LI_FN(SymGetLineFromAddr64).forwarded_safe();
				if (fnRtlCaptureStackBackTrace && fnSymGetModuleInfo64 && fnSymGetLineFromAddr64)
				{
					LPVOID lpFrames[STACK_MAX_FRAME_COUNT] = { 0x0 };
					for (auto& lpFrame : lpFrames)
						lpFrame = nullptr;

					auto wCapturedFrames = fnRtlCaptureStackBackTrace(1, STACK_MAX_FRAME_COUNT, lpFrames, nullptr);
					if (!wCapturedFrames)
						goto _end;

					for (auto i = 0; i < wCapturedFrames; i++)
					{
						auto stack_ctx = stdext::make_shared_nothrow<SSafeExecutorStackInformation>();

						stack_ctx->idx = i;

#pragma warning(push) 
#pragma warning(disable: 4826)
						auto ullCurrFrame = reinterpret_cast<DWORD64>(lpFrames[i]);
						stack_ctx->frame = ullCurrFrame;

						// Get module info
						IMAGEHLP_MODULE64 im64 = { 0 };
						im64.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

						if (fnSymGetModuleInfo64(NtCurrentProcess(), reinterpret_cast<DWORD64>(lpFrames[i]), &im64))
						{
							stdext::CRT::string::_strncpy_a(stack_ctx->module_name, sizeof(stack_ctx->module_name), im64.ModuleName, sizeof(im64.ModuleName));
							stdext::CRT::string::_strncpy_a(stack_ctx->image_name, sizeof(stack_ctx->image_name), im64.ImageName, sizeof(im64.ImageName));
							stdext::CRT::string::_strncpy_a(stack_ctx->loaded_image_name, sizeof(stack_ctx->loaded_image_name), im64.LoadedImageName, sizeof(im64.LoadedImageName));
						}
#pragma warning(pop) 

						// Get symbol name
						auto dwDisplacement64 = 0ULL;
						std::string stSymbolName;
						if (GetSymbolName(ullCurrFrame, stSymbolName, &dwDisplacement64))
						{
							stdext::CRT::string::_strncpy_a(stack_ctx->symbol_name, sizeof(stack_ctx->symbol_name), stSymbolName.c_str(), stSymbolName.size());
						}

						// Get source filename and line
						auto dwDisplacement = 0UL;
						IMAGEHLP_LINE64 il64 = { 0 };
						if (fnSymGetLineFromAddr64(NtCurrentProcess(), ullCurrFrame, &dwDisplacement, &il64))
						{
							stdext::CRT::string::_strncpy_a(stack_ctx->file_name, sizeof(stack_ctx->file_name), il64.FileName, sizeof(il64.FileName));
							stack_ctx->file_line = il64.LineNumber;
						}

						ctx.exception->stack.emplace_back(stack_ctx);
					}
				}
			}
_end:
			return code == EXCEPTION_CPP_MAGIC ? EXCEPTION_CONTINUE_SEARCH : EXCEPTION_EXECUTE_HANDLER;
		}

		/*
		 * High level C++ Exception handler
		 * Supported: std::exception, unhandled exception
		 */
		template <typename T>
		inline void SafeExecImpl(_Inout_ SSafeExecutorContext& ctx)
		{
			CrashHandlerImpl(
				ctx,
				[&] {
					try
					{
						if constexpr (std::is_same<T, void>::value || std::is_same<T, std::function<void()>>::value)
						{
							this->call_fn<T>(ctx.index);
							ctx.return_value.emplace(1);
						}
						else
						{
							ctx.return_value.emplace(this->call_fn<T>(ctx.index));
						}
					}
					catch (const std::invalid_argument& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_INVALID_ARGUMENT;
						ctx.error_message = ex.what();
					}
					catch (const std::out_of_range& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_OUT_OF_RANGE;
						ctx.error_message = ex.what();
					}
					catch (const std::logic_error& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_LOGIC_ERROR;
						ctx.error_message = ex.what();
					}
					catch (const std::system_error& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_SYSTEM_ERROR;
						ctx.error_message = ex.what();
					}
					catch (const std::runtime_error& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_RUNTIME_ERROR;
						ctx.error_message = ex.what();
					}
					catch (const std::bad_alloc& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_BAD_ALLOC;
						ctx.error_message = ex.what();
					}
					catch (const std::exception& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_STD;
						ctx.error_message = ex.what();
					}
					catch (...)
					{
						ctx.return_code = SAFE_EXECUTOR_UNHANDLED_EXCEPTION;
						ctx.error_code = 0xD34DC0D3;
					}
				},
				[&](const uint32_t error_code) {
					ctx.return_code = SAFE_EXECUTOR_SEH_EXCEPTION;
					ctx.error_code = error_code;
				}
			);

			ctx.return_code = SAFE_EXECUTOR_NO_EXCEPTION;
		}

		template <typename T, typename... Args>
		inline void SafeExecImplArg(SSafeExecutorContext& ctx, Args&&... arg)
		{
			CrashHandlerImpl(
				ctx,
				[&] {
					try
					{
						if (std::is_same<T, void>::value)
						{
							this->call_fn<T>(ctx.index, std::forward<Args>(arg)...);
							ctx.return_value.emplace(1);
						}
						else
						{
							ctx.return_value.emplace(this->call_fn<T>(ctx.index, std::forward<Args>(arg)...));
						}
					}
					catch (const std::invalid_argument& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_INVALID_ARGUMENT;
						ctx.error_message = ex.what();
					}
					catch (const std::out_of_range& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_OUT_OF_RANGE;
						ctx.error_message = ex.what();
					}
					catch (const std::logic_error& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_LOGIC_ERROR;
						ctx.error_message = ex.what();
					}
					catch (const std::system_error& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_SYSTEM_ERROR;
						ctx.error_message = ex.what();
					}
					catch (const std::runtime_error& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_RUNTIME_ERROR;
						ctx.error_message = ex.what();
					}
					catch (const std::bad_alloc& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_BAD_ALLOC;
						ctx.error_message = ex.what();
					}
					catch (const std::exception& ex)
					{
						ctx.return_code = SAFE_EXECUTOR_CPP_EXCEPTION_STD;
						ctx.error_message = ex.what();
					}
					catch (...)
					{
						ctx.return_code = SAFE_EXECUTOR_UNHANDLED_EXCEPTION;
						ctx.error_code = 0xD34DC0D3;
					}
				},
				[&](const uint32_t error_code) {
					ctx.return_code = SAFE_EXECUTOR_SEH_EXCEPTION;
					ctx.error_code = error_code;
				}
			);

			ctx.return_code = SAFE_EXECUTOR_NO_EXCEPTION;
		}

		/*
		 * Low level SEH Exception handler
		 */
		inline void CrashHandlerImpl(SSafeExecutorContext& ctx, const std::function<void()>& body, const std::function<void(uint32_t)>& handler)
		{
			__try
			{
				body();
			}
			__except (SafeSehExceptionParser(ctx, GetExceptionCode(), GetExceptionInformation()))
			{
				if (NoMercyCore::CApplication::InstancePtr())
					NoMercyCore::CApplication::Instance().InvokeFatalErrorCallback();
				
				handler(GetExceptionCode());
			}
		}

	private:
		bool m_close_on_fail;
	};
};
