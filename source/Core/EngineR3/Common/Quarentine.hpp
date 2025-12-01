#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>

namespace NoMercy
{
	static constexpr auto sc_nCheatDBBlacklistIDBase = 10000000;

	enum class EQuarentineTypes : uint32_t
	{
		NONE = 0,
		
		// Blacklist objects
		BL_BASE = 100,
		BL_SYMLINK,
		BL_EVENT_NAME,
		BL_MUTANT_NAME,
		BL_SEMAPHORE_NAME,
		BL_JOB_NAME,
		BL_FILE_MAPPING_NAME,
		BL_SERVICE_NAME,
		BL_HANDLE_OWNER_CLASS,
		BL_DRIVER_FILE_NAME,
		BL_WINDOWS_STATION,
		BL_WAITABLE_TIMER,
		BL_HANDLE_OBJECT_NAME,
		BL_DEBUG_STRING,
		
		BL_COMMON_BASE = 200,
		BL_WINDOW,
		BL_PROCESS,
		BL_MODULE,
		BL_FILE,
		BL_MEMORY,
		BL_THREAD,
		
		// Whitelist objects
		WL_BASE = 1000,
		WL_PROCESS_HOLLOWING,
		WL_ARBITARY_USER_POINTER,
		WL_DEBUG_PRIV_REMOVED_PROCESS,
		
		MAX
	};
	
	struct SCommonQuarentineHandler
	{
		uint32_t idx{ 0 };
		std::wstring data{ L"" };
	};
	
	struct SWindowCheckObjects
	{
		uint32_t	idx{ 0 };
		std::wstring	class_name{ L"" };
		std::wstring	window_name{ L"" };
		std::wstring	window_heuristic{ L"" };
		uint32_t	window_style{ 0 };
		uint32_t	window_ex_style{ 0 };
		RECT		window_rect{ 0 };
		uint8_t		wnd_proc_data[12]{ 0x0 };
	};
	struct SProcessCheckObjects
	{
		uint32_t	idx{ 0 };
		// Process name scanner
		std::wstring	process_name{ L"" };
		// Process file hash scanner
		std::wstring	process_file_hash{ L"" };
		// Process file desc scanner
		std::wstring	process_file_desc{ L"" };
		// Entrypoint scanner
		PVOID64		base_ptr{ nullptr };
		std::wstring	base_pattern{ L"" };
		std::wstring	base_mask{ L"" };
		// Icon scanner
		std::wstring	icon_hash{ L"" };
	};
	struct SModuleCheckObjects
	{
		uint32_t idx{ 0 };
		// Module name scanner
		std::wstring name{ L"" };
		// Module file hash scanner
		std::wstring hash{ L"" };
		// Module PE timestamp scanner
		uint32_t timestamp{ 0 };
		// Module PE exported function names scanner
		std::wstring export_func_name{ L"" };
	};
	struct SFileCheckObjects
	{
		uint32_t idx{ 0 };
		// File basic info scanner
		std::wstring name{ L"" };
		uint32_t size{ 0 };
		uint32_t timestamp{ 0 };
		// File pe info scanner
		uint32_t pe_timestamp{ 0 };
		uint32_t pe_sizeofcode{ 0 };
		uint32_t pe_sizeofinitdata{ 0 };
		// File hash scanner
		std::wstring md5{ L"" };
		std::wstring sha1{ L"" };
		std::wstring tlsh{ L"" };
		std::wstring section_sha256{ L"" };
		// File metadata scanner
		uint32_t metadata_idx_low{ 0 };
		uint32_t metadata_idx_high{ 0 };
		uint32_t metadata_volume_serial{ 0 };
		// File certificate scanner
		std::wstring cert_hash{ L"" };
		std::wstring cert_serial{ L"" };
		std::wstring cert_issuer{ L"" };
		std::wstring cert_subject{ L"" };
		std::wstring cert_provider{ L"" };
		// File contained string scanner
		std::wstring contained_string{ L"" };
		// File version table scanner
		std::wstring version_company_name{ L"" };
		std::wstring version_product_name{ L"" };
		std::wstring version_internal_name{ L"" };
		std::wstring version_file_description{ L"" };
		std::wstring version_file_name{ L"" };
		// File blacklisted pattern scanner
		std::wstring blacklisted_pattern{ L"" };
	};
	struct SMemoryCheckObjects
	{
		uint32_t idx{ 0 };
		std::wstring id{ L"" };
		// Mapped file scanner
		std::wstring file_name{ L"" };
		uint64_t mapped_file_checksum{ 0 };
		// Mapped file PE section scanner
		std::wstring region_name{ L"" };
		uint64_t region_base{ 0 };
		uint32_t region_size{ 0 };
		uint32_t region_checksum{ 0 };
		std::wstring region_checksum_sha256{ L"" };
		uint32_t region_charecteristics{ 0 };
		float region_entropy{ 0.0f };
		// Mapped file PE hash scanner
		std::wstring region_hash{ L"" };
		// Mapped file PE EAT scanner
		uint32_t eat_base{ 0 };
		uint32_t eat_ordinal{ 0 };
		std::wstring export_name{ L"" };
		// Mapped file pattern scanner
		std::wstring pattern{ L"" };
		std::wstring mask{ L"" };
		uint32_t pattern_type{ 0 };
		// Mapped file memory dump scanner
		std::wstring memory_base{ L"" };
		std::wstring memory_copy{ L"" };
	};
	struct SThreadCheckObject
	{
		uint32_t idx{ 0 };
		// Thread context scanner
		uint32_t context_offset{ 0 };
		uint32_t context_range_size{ 0 };
		uint32_t context_pattern_type{ 0 };
		std::wstring context_pattern{ L"" };
	};

	struct SCheatDBNode;
	struct SCheatDBBlacklistOptions;

	template <typename T>
	class IQuarentineNode
	{
#define LOCK_MTX_Q std::lock_guard <std::recursive_mutex> lock(m_rmMutex);

	public:
		IQuarentineNode() {};
		virtual ~IQuarentineNode() {};

		auto SetWhitelisted(const T obj) { LOCK_MTX_Q; m_vWhiteList.emplace_back(obj); };
		auto SetBlacklisted(const T obj, const SCheatDBBlacklistOptions opt)
		{
			LOCK_MTX_Q;

			m_vBlackList.emplace_back(std::make_tuple(obj, opt));
		};

		auto& GetWhitelist() const		{ LOCK_MTX_Q; return m_vWhiteList; };
		auto& GetBlacklist() const		{ LOCK_MTX_Q; return m_vBlackList; };

	private:
		mutable std::recursive_mutex m_rmMutex;

		std::vector <T> m_vWhiteList;
		std::vector <std::tuple <T, SCheatDBBlacklistOptions>> m_vBlackList;
	};

	class CQuarentine : public std::enable_shared_from_this <CQuarentine>
	{
	public:
		// Constructor & destructor
		CQuarentine();
		virtual ~CQuarentine();

		// Initialization & Finalization
		bool Initialize();
		void Release();

		// Getters
		auto SymLinkQuarentine()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLSymLinkMutex);			return m_spSymlinkQuarentine;			};
		auto EventNameQuarentine()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLEventNameMutex);			return m_spEventNameQuarentine;			};
		auto MutantNameQuarentine()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLMutantNameMutex);		return m_spMutantNameQuarentine;		};
		auto SemaphoreNameQuarentine()		{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLSemaphoreNameMutex);		return m_spSemaphoreNameQuarentine;		};
		auto JobNameQuarentine()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLJobNameMutex);			return m_spJobNameQuarentine;			};
		auto FileMappingNameQuarentine()	{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLFileMappingNameMutex);	return m_spFileMappingNameQuarentine;	};
		auto ServiceNameQuarentine()		{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLServiceNameMutex);		return m_spServiceNameQuarentine;		};
		auto HandleOwnerClassQuarentine()	{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLHandleOwnerClassMutex);	return m_spHandleOwnerClassQuarentine;	};
		auto DriverFileNameQuarentine()		{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLDriverFileNameMutex);	return m_spDriverFileNameQuarentine;	};
		auto WindowsStationQuarentine()		{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLWindowsStationMutex);	return m_spWindowsStationQuarentine;	};
		auto WaitableTimerQuarentine()  	{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLWaitableTimerMutex);		return m_spWaitableTimerQuarentine;		};
		auto HandleObjectNameQuarentine()	{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLHandleObjectNameMutex);	return m_spHandleObjectNameQuarentine;	};
		auto DebugStringQuarentine()		{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLDebugStringMutex);		return m_spDebugStringQuarentine; };
		
		auto WindowQuarentine()				{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLWindowMutex);		return m_spWindowQuarentine;		};
		auto ProcessQuarentine()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLProcessMutex);		return m_spProcessQuarentine;		};
		auto ModuleQuarentine()				{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLModuleMutex);		return m_spModuleQuarentine;		};
		auto FileQuarentine()				{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLFileMutex);			return m_spFileQuarentine;			};
		auto MemoryQuarentine()				{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLMemoryMutex);		return m_spMemoryQuarentine;		};
		auto ThreadQuarentine()				{ std::lock_guard <std::recursive_mutex> __lock(m_mtxBLThreadMutex);		return m_spThreadQuarentine;		};

		auto ProcessHollowingQuarentine()			{ std::lock_guard <std::recursive_mutex> __lock(m_mtxWLProcessHollowingMutex);			return m_spProcessHollowingQuarentine;			};
		auto ArbitaryUserPointerQuarentine()		{ std::lock_guard <std::recursive_mutex> __lock(m_mtxWLArbitaryUserPointerMutex);		return m_spArbitaryUserPointerQuarentine;		};
		auto DebugPrivRemovedProcessQuarentine()	{ std::lock_guard <std::recursive_mutex> __lock(m_mtxWLDebugPrivRemovedProcessMutex);	return m_spDebugPrivRemovedProcessQuarentine;	};

		// Utilities
		bool IsAllowedFileCertificate(const std::wstring& serial, const std::wstring& subject, const std::wstring& issuer, const std::wstring& provider, const std::wstring& hash);

	private:
		bool m_bInitialized;
		
		// Blacklist objects
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spSymlinkQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spEventNameQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spMutantNameQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spSemaphoreNameQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spJobNameQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spFileMappingNameQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spServiceNameQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spHandleOwnerClassQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spDriverFileNameQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spWindowsStationQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spWaitableTimerQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spHandleObjectNameQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spDebugStringQuarentine;

		// Ext. blacklist objects
		std::shared_ptr <IQuarentineNode <SWindowCheckObjects> >	m_spWindowQuarentine;
		std::shared_ptr <IQuarentineNode <SProcessCheckObjects> >	m_spProcessQuarentine;
		std::shared_ptr <IQuarentineNode <SModuleCheckObjects> >	m_spModuleQuarentine;
		std::shared_ptr <IQuarentineNode <SFileCheckObjects> >		m_spFileQuarentine;
		std::shared_ptr <IQuarentineNode <SMemoryCheckObjects>>		m_spMemoryQuarentine;
		std::shared_ptr <IQuarentineNode <SThreadCheckObject> >		m_spThreadQuarentine;
	
		// Whitelist objects
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spProcessHollowingQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spArbitaryUserPointerQuarentine;
		std::shared_ptr <IQuarentineNode <SCommonQuarentineHandler> > m_spDebugPrivRemovedProcessQuarentine;

		// Lock objects
		mutable std::recursive_mutex m_mtxBLSymLinkMutex;
		mutable std::recursive_mutex m_mtxBLEventNameMutex;
		mutable std::recursive_mutex m_mtxBLMutantNameMutex;
		mutable std::recursive_mutex m_mtxBLSemaphoreNameMutex;
		mutable std::recursive_mutex m_mtxBLJobNameMutex;
		mutable std::recursive_mutex m_mtxBLFileMappingNameMutex;
		mutable std::recursive_mutex m_mtxBLServiceNameMutex;
		mutable std::recursive_mutex m_mtxBLHandleOwnerClassMutex;
		mutable std::recursive_mutex m_mtxBLDriverFileNameMutex;
		mutable std::recursive_mutex m_mtxBLWindowsStationMutex;
		mutable std::recursive_mutex m_mtxBLWaitableTimerMutex;
		mutable std::recursive_mutex m_mtxBLHandleObjectNameMutex;
		mutable std::recursive_mutex m_mtxBLDebugStringMutex;
		
		mutable std::recursive_mutex m_mtxBLWindowMutex;
		mutable std::recursive_mutex m_mtxBLProcessMutex;
		mutable std::recursive_mutex m_mtxBLModuleMutex;
		mutable std::recursive_mutex m_mtxBLFileMutex;
		mutable std::recursive_mutex m_mtxBLMemoryMutex;
		mutable std::recursive_mutex m_mtxBLThreadMutex;
		
		mutable std::recursive_mutex m_mtxWLProcessHollowingMutex;
		mutable std::recursive_mutex m_mtxWLArbitaryUserPointerMutex;
		mutable std::recursive_mutex m_mtxWLDebugPrivRemovedProcessMutex;
	};
};
