#include "../../PCH.hpp"
#include "../../Index.hpp"
#include "../../Application.hpp"
#include "../SDKManager.hpp"
#include "Metin2_SDK.hpp"
#include "../../../EngineR3_Core/include/PEHelper.hpp"

using namespace NoMercy;

// TODO:
// hide python module from peb, erase python module pe 

CMetin2SDKMgr::CMetin2SDKMgr() :
	m_bInitialized(false), m_bEterPackCheckEnabled(true),
	m_pSend(nullptr), m_pSendSequence(nullptr),
	m_pGetVID(nullptr), m_pGetPhase(nullptr), m_pGetPlayerName(nullptr),
	m_pGetMappedFileIsExist(nullptr), m_pGetMappedFileHash(nullptr),
	m_hHeartbeatTimer(nullptr), m_bHeartbeatEnabled(false), m_nHeartbeatType(0),
	m_pPy_InitModule4(nullptr), m_pPyParser_ASTFromString(nullptr), m_pPyParser_ASTFromFile(nullptr),
	m_pPyTuple_Check(nullptr), m_pPyTuple_Size(nullptr), m_pPyTuple_GetItem(nullptr), m_pPyString_AsString(nullptr),
	m_pPyImport_GetModuleDict(nullptr), m_pPyDict_Next(nullptr), m_pPyObject_HasAttrString(nullptr),
	m_pPyObject_GetAttrString(nullptr), m_pPy_DecRef(nullptr), m_pPy_None(nullptr),
	m_pPyRun_SimpleString(nullptr), m_pPyRun_SimpleStringFlags(nullptr), m_pPyRun_SimpleFile(nullptr), m_pPyRun_SimpleFileFlags(nullptr),
	m_pPyRun_SimpleFileEx(nullptr), m_pPyRun_SimpleFileExFlags(nullptr), m_pPyFile_FromString(nullptr), m_pPyFile_FromStringFlags(nullptr),
	m_pPyString_InternFromString(nullptr), m_pPyThreadState_Get(nullptr)
{
	m_vFunctions.clear();
	m_spRandom = std::shared_ptr<CMTRandom>(0);
}

void CMetin2SDKMgr::OnClientMessage(int nCode, const void* c_lpMessage)
{
	LOCK_MTX_M2;

	switch (nCode)
	{
		case NM_DATA_SEND_NET_SEND_PACKET:
		{
			m_pSend = reinterpret_cast<TSendWrapper>(c_lpMessage);
		} break;
		
		case NM_DATA_SEND_TRACEERROR:
			break;

		case NM_DATA_SEND_MAPPED_FILE_EXIST:
		{
			m_pGetMappedFileIsExist = reinterpret_cast<TIsMappedFileExist>(c_lpMessage);
		} break;

		case NM_DATA_SEND_VID:
		{
			m_pGetVID = reinterpret_cast<TGetVID>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PHASE:
		{
			m_pGetPhase = reinterpret_cast<TGetPhase>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PLAYER_NAME:
		{
			m_pGetPlayerName = reinterpret_cast<TGetPlayerName>(c_lpMessage);
		} break;

		case NM_DATA_SEND_MAPPED_FILE_HASH:
		{
			m_pGetMappedFileHash = reinterpret_cast<TGetMappedFileHash>(c_lpMessage);
		} break;

		case NM_DATA_SEND_NET_SEND_SEQ:
		{
			m_pSendSequence = reinterpret_cast<TSendSequence>(c_lpMessage);
		} break;

		case NM_DATA_SEND_Py_InitModule4:
		{
			m_pPy_InitModule4 = reinterpret_cast<TPy_InitModule4>(c_lpMessage);
		} break;
		
		case NM_DATA_SEND_PyParser_ASTFromString:
		{
			m_pPyParser_ASTFromString = reinterpret_cast<TPyParser_ASTFromString>(c_lpMessage);
		} break;
		
		case NM_DATA_SEND_PyParser_ASTFromFile:
		{
			m_pPyParser_ASTFromFile = reinterpret_cast<TPyParser_ASTFromFile>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyTuple_Check:
		{
			m_pPyTuple_Check = reinterpret_cast<TPyTuple_Check>(c_lpMessage);
		} break;
		
		case NM_DATA_SEND_PyTuple_Size:
		{
			m_pPyTuple_Size = reinterpret_cast<TPyTuple_Size>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyTuple_GetItem:
		{
			m_pPyTuple_GetItem = reinterpret_cast<TPyTuple_GetItem>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyString_AsString:
		{
			m_pPyString_AsString = reinterpret_cast<TPyString_AsString>(c_lpMessage);
		} break;
		
		case NM_DATA_SEND_PyImport_GetModuleDict:
		{
			m_pPyImport_GetModuleDict = reinterpret_cast<TPyImport_GetModuleDict>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyDict_Next:
		{
			m_pPyDict_Next = reinterpret_cast<TPyDict_Next>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyObject_HasAttrString:
		{
			m_pPyObject_HasAttrString = reinterpret_cast<TPyObject_HasAttrString>(c_lpMessage);
		} break;
		
		case NM_DATA_SEND_PyObject_GetAttrString:
		{
			m_pPyObject_GetAttrString = reinterpret_cast<TPyObject_GetAttrString>(c_lpMessage);
		} break;

		case NM_DATA_SEND_Py_DecRef:
		{
			m_pPy_DecRef = reinterpret_cast<TPy_DecRef>(c_lpMessage);
		} break;

		case NM_DATA_SEND_Py_None:
		{
			m_pPy_None = reinterpret_cast<TPy_None>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyRun_SimpleString:
		{
			m_pPyRun_SimpleString = reinterpret_cast<TPyRun_SimpleString>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyRun_SimpleStringFlags:
		{
			m_pPyRun_SimpleStringFlags = reinterpret_cast<TPyRun_SimpleStringFlags>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyRun_SimpleFile:
		{
			m_pPyRun_SimpleFile = reinterpret_cast<TPyRun_SimpleFile>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyRun_SimpleFileFlags:
		{
			m_pPyRun_SimpleFileFlags = reinterpret_cast<TPyRun_SimpleFileFlags>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyRun_SimpleFileEx:
		{
			m_pPyRun_SimpleFileEx = reinterpret_cast<TPyRun_SimpleFileEx>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyRun_SimpleFileExFlags:
		{
			m_pPyRun_SimpleFileExFlags = reinterpret_cast<TPyRun_SimpleFileExFlags>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyFile_FromString:
		{
			m_pPyFile_FromString = reinterpret_cast<TPyFile_FromString>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyFile_FromStringFlags:
		{
			m_pPyFile_FromStringFlags = reinterpret_cast<TPyFile_FromStringFlags>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyString_InternFromString:
		{
			m_pPyString_InternFromString = reinterpret_cast<TPyString_InternFromString>(c_lpMessage);
		} break;

		case NM_DATA_SEND_PyThreadState_Get:
		{
			m_pPyThreadState_Get = reinterpret_cast<TPyThreadState_Get>(c_lpMessage);
		} break;
		
		default:
			SDK_LOG(LL_CRI, L"Unknown function id: %d", nCode);
			break;
	}

	auto pData = stdext::make_shared_nothrow<SM2SDKFuncData>();
	if (IS_VALID_SMART_PTR(pData))
	{
		pData->c_pFuncAddr	= c_lpMessage;
		pData->iCode		= nCode;

		m_vFunctions.emplace_back(pData);
	}
}

void CMetin2SDKMgr::Release()
{
	ReleaseHeartbeatTimer();
}

void CMetin2SDKMgr::OnGameTick()
{
	const auto dwTimestamp = CApplication::Instance().FunctionsInstance()->GetCurrentTimestamp();
	const auto stTimestamp = std::to_string(dwTimestamp);

	CApplication::Instance().SDKHelperInstance()->SendMessageToClient(NM_DATA_RECV_TICK_RESPONSE, stTimestamp.c_str(), nullptr);
}

DWORD CMetin2SDKMgr::InitialThreadRoutine(void)
{
	APP_TRACE_LOG(LL_TRACE, L"Initial thread has been started!");

	CheckMainFolderFiles();
	CheckLibFolderForPythonLibs();
	CheckMilesFolderForMilesPlugins();
	CheckYmirFolder();

	return 0;
}

DWORD WINAPI CMetin2SDKMgr::StartInitialThreadRoutine(LPVOID lpParam)
{
	const auto This = reinterpret_cast<CMetin2SDKMgr*>(lpParam);
	return This->InitialThreadRoutine();
}

void CMetin2SDKMgr::OnGameInitialize()
{
	LOCK_MTX_M2;

	m_bInitialized = true;

	const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_GAME_INITIAL_CHECK, StartInitialThreadRoutine, (void*)this, 0, true);
	if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
	{
		APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
		return;
	}
	else
	{
		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
		);
	}

	InitializeHeartbeatTimer();
}

void CMetin2SDKMgr::EnableHeartbeat(uint8_t type)
{
	LOCK_MTX_M2;

	SDK_LOG(LL_SYS, L"Heartbeat type: %u enabled!", type);
	m_nHeartbeatType = type;
	m_bHeartbeatEnabled = true;
}

bool CMetin2SDKMgr::FunctionIsInGameArea(DWORD_PTR dwAddress)
{
	LPVOID lpBase = nullptr;
	SIZE_T cbSize = 0;
	if (!CPEFunctions::GetTextSectionInformation(g_winModules->hBaseModule, &lpBase, &cbSize))
		return false;

	const auto dwCodeHi = (DWORD_PTR)lpBase + cbSize;
	if (dwAddress >= (DWORD_PTR)lpBase && dwAddress <= dwCodeHi)
		return true;

	return false;
}

bool CMetin2SDKMgr::VerifyFunctionModules()
{
	LOCK_MTX_M2;

	for (const auto & pCurrFunc : m_vFunctions)
	{
		if (IS_VALID_SMART_PTR(pCurrFunc))
		{
			if (pCurrFunc->iCode >= NM_DATA_SEND_TRACEERROR /* min */ && pCurrFunc->iCode <= NM_DATA_SEND_NET_SEND_SEQ /* max */)
			{
				if (!pCurrFunc->c_pFuncAddr)
				{
					SDK_LOG(LL_CRI, L"Null func? Code: %d", pCurrFunc->iCode);
					return false;
				}

				if (FunctionIsInGameArea((DWORD_PTR)pCurrFunc->c_pFuncAddr) == false)
				{
					SDK_LOG(LL_CRI, L"Hooked func? Code: %d Adr: %p", pCurrFunc->iCode, pCurrFunc->c_pFuncAddr);
					return false;
				}
			}
			else if (pCurrFunc->iCode >= NM_DATA_SEND_Py_InitModule4 /* min */ && pCurrFunc->iCode <= NM_DATA_SEND_Python_Max)
			{
				if (!pCurrFunc->c_pFuncAddr)
				{
					SDK_LOG(LL_CRI, L"Null func? Code: %d", pCurrFunc->iCode);
					return false;
				}

				if (g_winModules->hPython == nullptr && FunctionIsInGameArea((DWORD_PTR)pCurrFunc->c_pFuncAddr) == false)
				{
					SDK_LOG(LL_CRI, L"1-Hooked py func? Code: %d Adr: %p", pCurrFunc->iCode, pCurrFunc->c_pFuncAddr);
					// return false;
				}
				else if (
					g_winModules->hPython != nullptr &&
					CApplication::Instance().FunctionsInstance()->IsInModuleRange(g_winModules->hPython, (DWORD_PTR)pCurrFunc->c_pFuncAddr) == false
				)
				{
					SDK_LOG(LL_CRI, L"2-Hooked py func? Code: %d Adr: %p", pCurrFunc->iCode, pCurrFunc->c_pFuncAddr);
					// return false;
				}
			}
		}
	}
	return true;
}
