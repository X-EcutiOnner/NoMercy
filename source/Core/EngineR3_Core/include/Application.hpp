#pragma once
#include "../include/LogHelper.hpp"
#include "../include/WinAPIManager.hpp"
#include "../include/DirFunctions.hpp"
#include "../include/MiniDump.hpp"
#include "../include/InitilizationManager.hpp"
#include "../include/CryptFunctions.hpp"
#include "../include/Data.hpp"
#include "../include/Screenshot.hpp"
#include "../include/WMIHelper.hpp"
#include "../include/HW-Info.hpp"
#include "../include/Functions.hpp"
#include "../include/ErrorMessageHelper.hpp"
#include "../include/SentryManager.hpp"

namespace NoMercyCore
{
	static std::atomic_bool gs_abShuttingDown = false;
	static std::atomic_bool gs_abExitHandled = false;

	using TOnFatalError = std::function<void()>;

	class CApplication : public CSingleton <CApplication>
	{
		// Lifecycle
	public:
		virtual ~CApplication();

		CApplication(const CApplication&) = delete;
		CApplication(CApplication&&) noexcept = delete;
		CApplication& operator=(const CApplication&) = delete;
		CApplication& operator=(CApplication&&) noexcept = delete;

		// Public methods
	public:
		// Constructor
		CApplication(const uint8_t nAppType, const HINSTANCE hInstance, LPCVOID c_lpModuleInfo);

		// Initialization
		bool Initialize();

		// Finalization
		void Finalize();

		// Getter
		bool IsShuttingDown() const				{ return gs_abShuttingDown.load();	};
		bool IsInitialized() const				{ return m_bInitialized;			};
		uint8_t GetAppType() const				{ return m_nAppType;				};
		HINSTANCE GetInstance() const			{ return m_hInstance;				};
		LPVOID GetModuleInfo() const			{ return (LPVOID)m_lpModuleInfo;	};
		auto IsLogCollectorEnabled() const		{ return m_bEnableLogCollector;		};
		auto IsLogCollectorCompleted() const	{ return m_bLogCollectorCompleted;	};
		auto GetStartTimestamp() const			{ return m_nStartTimestamp;			};
		auto GetInitErrorCode() const			{ return m_nInitErrCode;			};
		auto GetInitErrorSubCode() const		{ return m_nInitErrSubCode;			};

		// Setter
		void SetShutDownFlag()			{ gs_abShuttingDown.exchange(true); };
		void EnableLogCollector()		{ m_bEnableLogCollector = true; };
		void SetLogCollectorCompleted() { m_bLogCollectorCompleted = true; };
		void SetFatalErrorCallback(const TOnFatalError& fn) { m_fnOnFatalError = fn; };

		// Dispatcher
		void InvokeFatalErrorCallback() { if (m_fnOnFatalError) m_fnOnFatalError(); };

		// Class method wrappers
		auto LogHelperInstance()			{ return m_spLogHelper;			};
		auto WinAPIManagerInstance()		{ return m_spWinAPIManager;		};
		auto FunctionsInstance()			{ return m_spFunctions;			};
		auto DirFunctionsInstance()			{ return m_spDirFuncs;			};
		auto InitilizationManagerInstance()	{ return m_spInitilizationMgr;	};
		auto CryptFunctionsInstance()		{ return m_spCryptoFuncs;		};
		auto DataInstance()					{ return m_spDataManager;		};
		auto ScreenshotManagerInstance()	{ return m_spScreenshotManager;	};
		auto WMIHelperInstance()			{ return m_spWMIHelper;			};
		auto HWIDManagerInstance()			{ return m_spHWIDManager;		};
		auto ErrorMessageHelperInstance()	{ return m_spErrMsgHelper;		};
		auto GetSentryManagerInstance()		{ return m_spSentryManager;		};

		// Utilities
		bool RegisterShutdownBlockReason(HWND hWnd);
		void UnregisterShutdownBlockReason(HWND hWnd);
		
	protected:
		uint32_t __InitializeAntiEmulation();
		void __InitializeShutdownWatcher();

	private:
		bool m_bInitialized;

		uint8_t m_nAppType;
		HINSTANCE m_hInstance;
		LPCVOID m_lpModuleInfo;

		bool m_bEnableLogCollector;
		bool m_bLogCollectorCompleted;
		bool m_bShutdownBlockInitialized;
		uint32_t m_nStartTimestamp;
		uint32_t m_nInitErrCode;
		uint32_t m_nInitErrSubCode;

		std::shared_ptr <CLogHelper>			m_spLogHelper;
		std::shared_ptr <CWinAPIManager>		m_spWinAPIManager;
		std::shared_ptr <CFunctions>			m_spFunctions;
		std::shared_ptr <CDirFunctions>			m_spDirFuncs;
		std::shared_ptr <CInitilizationManager>	m_spInitilizationMgr;
		std::shared_ptr <CCryptFunctions>		m_spCryptoFuncs;
		std::shared_ptr <CData>					m_spDataManager;
		std::shared_ptr <CScreenshotMgr>		m_spScreenshotManager;
		std::shared_ptr <CWMIHelper>			m_spWMIHelper;
		std::shared_ptr <CHwidManager>			m_spHWIDManager;
		std::shared_ptr <CErrorMessageHelper>	m_spErrMsgHelper;
		std::shared_ptr <CSentryManager>		m_spSentryManager;

		std::unique_ptr <CMiniDump>				m_upMiniDumpHelper;

		TOnFatalError m_fnOnFatalError;
	};
};
