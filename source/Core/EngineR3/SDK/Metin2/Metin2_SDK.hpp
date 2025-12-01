#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <xorstr.hpp>
#include <cstring>
#include <string.h>
#include "../../Common/MTRandom.hpp"
#define HAVE_SNPRINTF
#pragma warning(push) 
#pragma warning(disable: 5033)
#include <python27/Python.h>
#pragma warning(pop)

namespace NoMercy
{
#define LOCK_MTX_M2 std::lock_guard <std::recursive_mutex> __lock(m_rmMutex)

	struct SM2SDKFuncData
	{
		LPCVOID c_pFuncAddr;
		int iCode;
	};

	class CMetin2SDKMgr
	{
		typedef bool(__cdecl* TSendWrapper)				(const char* c_pData, int iLength);
		typedef bool(__cdecl* TSendSequence)			();
		typedef DWORD(__cdecl* TGetVID)					();
		typedef DWORD(__cdecl* TGetPhase)				();
		typedef const char*(__cdecl* TGetPlayerName)	();
		typedef bool(__cdecl* TIsMappedFileExist)		(const char* c_szFileName);
		typedef DWORD(__cdecl* TGetMappedFileHash)		(const char* c_szFileName);

	public:
		typedef PyObject* (__cdecl* TPy_InitModule4)		(const char* c_szName, PyMethodDef* pMethods, const char* c_szDoc, PyObject* pSelf, int iApiver);
		typedef _mod* (__cdecl* TPyParser_ASTFromString)	(const char* c_szCode, const char* c_szFilename, int iType, PyCompilerFlags* flags, PyArena*);
		typedef _mod* (__cdecl* TPyParser_ASTFromFile)		(FILE*, const char*, int, char*, char*, PyCompilerFlags*, int*, PyArena*);
		typedef bool(__cdecl* TPyTuple_Check)			(PyObject* pObject);
		typedef int(__cdecl* TPyTuple_Size)				(PyObject* pObject);
		typedef PyObject* (__cdecl* TPyTuple_GetItem)	(PyObject* pObject, int iIndex);
		typedef const char* (__cdecl* TPyString_AsString)	(PyObject* pObject);
		typedef PyObject* (__cdecl* TPyImport_GetModuleDict)	();
		typedef int(__cdecl* TPyDict_Next)				(PyObject* pObject, int* piPos, PyObject** pKey, PyObject** pValue);
		typedef bool(__cdecl* TPyObject_HasAttrString)	(PyObject* pObject, const char* c_szName);
		typedef PyObject* (__cdecl* TPyObject_GetAttrString)	(PyObject* pObject, const char* c_szName);
		typedef void(__cdecl* TPy_DecRef)				(PyObject* pObject);
		typedef PyObject* (__cdecl* TPy_None)			();
		typedef int (__cdecl* TPyRun_SimpleString)	(const char* c_szCode);
		typedef int (__cdecl* TPyRun_SimpleStringFlags)	(const char* c_szCode, PyCompilerFlags* pFlags);
		typedef int (__cdecl* TPyRun_SimpleFile)		(FILE* pFile, const char* c_szFilename);
		typedef int (__cdecl* TPyRun_SimpleFileFlags)	(FILE* pFile, const char* c_szFilename, int iCloseIt, PyCompilerFlags* pFlags);
		typedef int (__cdecl* TPyRun_SimpleFileEx)		(FILE* pFile, const char* c_szFilename, int iCloseIt);
		typedef int (__cdecl* TPyRun_SimpleFileExFlags)	(FILE* pFile, const char* c_szFilename, int iCloseIt, PyCompilerFlags* pFlags);
		typedef int (__cdecl* TPyFile_FromString)		(const char* c_szFilename, const char* c_szMode);
		typedef PyObject* (__cdecl* TPyFile_FromStringFlags)	(const char* c_szFilename, const char* c_szMode, PyCompilerFlags* pFlags);
		typedef PyObject* (__cdecl* TPyString_InternFromString)	 (const char* c_szString);
		typedef PyThreadState* (__cdecl* TPyThreadState_Get)	();
		
	public:
		CMetin2SDKMgr();
		~CMetin2SDKMgr() = default;

		void Release();

		void OnGameTick();
		void OnGameInitialize();
		void OnClientMessage(int Code, const void* lpMessage);

		auto IsInitialized() const		{ LOCK_MTX_M2; return m_bInitialized; };
		auto GetHeartbeatType() const	{ LOCK_MTX_M2; return m_nHeartbeatType; };
		auto IsHeartbeatEnabled() const { LOCK_MTX_M2; return m_bHeartbeatEnabled; };

		void OnHeartbeatTick();
		void EnableHeartbeat(uint8_t type);
		bool InitializeHeartbeatTimer();
		void ReleaseHeartbeatTimer();

		bool VerifyFunctionModules();

		auto GetPhase()									 { LOCK_MTX_M2; return m_pGetPhase ? m_pGetPhase() : (DWORD)-2; };
		auto GetPlayerName()							 { LOCK_MTX_M2; return m_pGetPlayerName ? m_pGetPlayerName() : ""; };
	
		bool InitializePythonHooks();
		void RemovePythonModuleWatcher();
		void DestroyPythonHooks();
		void CheckPythonModules();

	protected:
		auto Send(const char* c_pData, int iLength)		 { LOCK_MTX_M2; return m_pSend ? m_pSend(c_pData, iLength) : false; };
		auto SendSequence()								 { LOCK_MTX_M2; return m_pSendSequence ? m_pSendSequence() : false; };
		auto GetVID()									 { LOCK_MTX_M2; return m_pGetVID ? m_pGetVID() : (DWORD)-1; };
		auto IsMappedFileExist(const char* c_szFileName) { LOCK_MTX_M2; return m_pGetMappedFileIsExist ? m_pGetMappedFileIsExist(c_szFileName) : false; };
		auto GetMappedFileHash(const char* c_szFileName) { LOCK_MTX_M2; return m_pGetMappedFileHash ? m_pGetMappedFileHash(c_szFileName) : (DWORD)-1; };

	protected:
		void DumpMappedFileHashes();
		bool FunctionIsInGameArea(DWORD_PTR dwAddress);

	protected:
		void CheckMainFolderFiles();
		void CheckLibFolderForPythonLibs();
		void CheckMilesFolderForMilesPlugins();
		void CheckYmirFolder();

	protected:
		DWORD					InitialThreadRoutine(void);
		static DWORD WINAPI		StartInitialThreadRoutine(LPVOID lpParam);

	protected:
		std::vector <std::string> PyTupleToStdVector(PyObject* pyTupleObj);

	private:
		mutable std::recursive_mutex m_rmMutex;

		bool				m_bInitialized;
		bool				m_bEterPackCheckEnabled;
		uint8_t				m_nHeartbeatType;
		bool				m_bHeartbeatEnabled;
		HANDLE				m_hHeartbeatTimer;
		CStopWatch <std::chrono::milliseconds> m_pHeartbeatCheckTimer;

		TSendWrapper		m_pSend;
		TSendSequence		m_pSendSequence;
		TGetVID				m_pGetVID;
		TGetPhase			m_pGetPhase;
		TGetPlayerName		m_pGetPlayerName;
		TIsMappedFileExist	m_pGetMappedFileIsExist;
		TGetMappedFileHash	m_pGetMappedFileHash;

		TPy_InitModule4			m_pPy_InitModule4;
		TPyParser_ASTFromString	m_pPyParser_ASTFromString;
		TPyParser_ASTFromFile	m_pPyParser_ASTFromFile;
		TPyTuple_Check			m_pPyTuple_Check;
		TPyTuple_Size			m_pPyTuple_Size;
		TPyTuple_GetItem		m_pPyTuple_GetItem;
		TPyString_AsString		m_pPyString_AsString;
		TPyImport_GetModuleDict	m_pPyImport_GetModuleDict;
		TPyDict_Next			m_pPyDict_Next;
		TPyObject_HasAttrString	m_pPyObject_HasAttrString;
		TPyObject_GetAttrString	m_pPyObject_GetAttrString;
		TPy_DecRef				m_pPy_DecRef;
		TPy_None				m_pPy_None;
		TPyRun_SimpleString m_pPyRun_SimpleString;
		TPyRun_SimpleStringFlags m_pPyRun_SimpleStringFlags;
		TPyRun_SimpleFile m_pPyRun_SimpleFile;
		TPyRun_SimpleFileFlags m_pPyRun_SimpleFileFlags;
		TPyRun_SimpleFileEx m_pPyRun_SimpleFileEx;
		TPyRun_SimpleFileExFlags m_pPyRun_SimpleFileExFlags;
		TPyFile_FromString m_pPyFile_FromString;
		TPyFile_FromStringFlags m_pPyFile_FromStringFlags;
		TPyString_InternFromString m_pPyString_InternFromString;
		TPyThreadState_Get m_pPyThreadState_Get;

		std::vector <std::shared_ptr <SM2SDKFuncData> >	m_vFunctions;
		std::shared_ptr <CMTRandom>	m_spRandom;
	};
};
