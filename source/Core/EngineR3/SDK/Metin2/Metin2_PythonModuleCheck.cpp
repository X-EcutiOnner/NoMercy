#include "../../PCH.hpp"
#include "../../Index.hpp"
#include "../../Application.hpp"
#include "../SDKManager.hpp"
#include "Metin2_SDK.hpp"
#include <MinHook.h>
using namespace NoMercy;

static decltype(&Py_InitModule4) OPy_InitModule4 = nullptr;
static decltype(&PyParser_ASTFromString) OPyParser_ASTFromString = nullptr;
static decltype(&PyParser_ASTFromFile) OPyParser_ASTFromFile = nullptr;
static CMetin2SDKMgr::TPyRun_SimpleString OPyRun_SimpleString = nullptr;
static CMetin2SDKMgr::TPyRun_SimpleStringFlags OPyRun_SimpleStringFlags = nullptr;
static CMetin2SDKMgr::TPyRun_SimpleFile OPyRun_SimpleFile = nullptr;
static CMetin2SDKMgr::TPyRun_SimpleFileFlags OPyRun_SimpleFileFlags = nullptr;
static CMetin2SDKMgr::TPyRun_SimpleFileEx OPyRun_SimpleFileEx = nullptr;
static CMetin2SDKMgr::TPyRun_SimpleFileExFlags OPyRun_SimpleFileExFlags = nullptr;
static decltype(&PyFile_FromString) OPyFile_FromString = nullptr;
static decltype(&PyString_InternFromString) OPyString_InternFromString = nullptr;

static std::map <std::string, PyObject*> gs_PythonModules;
static bool IsKnownModule(PyObject* module)
{
//	SDK_LOG(LL_SYS, L"Checking python module: %p from: %u modules", module, gs_PythonModules.size());

	for (const auto& [stModuleName, pPyObject] : gs_PythonModules)
	{
		if (pPyObject == module)
		{
//			SDK_LOG(LL_SYS, L"%p >> %hs", module, stModuleName.c_str());
			return true;
		}
	}

	SDK_LOG(LL_ERR, L"Unknown python module: %p", module);
	return false;
}

PyObject* Py_InitModule4Detour(const char* name, PyMethodDef* methods, const char* doc, PyObject* self, int apiver)
{
//	SDK_LOG(LL_SYS, L"[Py_InitModule4] - %hs - %p - %p - %d", name, methods, self, apiver);

	auto pyObj = OPy_InitModule4(name, methods, doc, self, apiver);
	if (pyObj)
	{
		SDK_LOG(LL_SYS, L"Python module (%hs) loaded at %p", name, pyObj);
		gs_PythonModules.emplace(name, pyObj);
	}
	return pyObj;
}
struct _mod* PyParser_ASTFromStringDetour(const char* arg1, const char* arg2, int arg3, PyCompilerFlags* flags, PyArena* arena)
{
	SDK_LOG(LL_CRI, L"[PyParser_ASTFromString] - %hs - %hs - %d - %p - %p", arg1, arg2, arg3, flags, arena);
	// TODO: Analyse
	return OPyParser_ASTFromString(arg1, arg2, arg3, flags, arena);
}
struct _mod* PyParser_ASTFromFileDetour(FILE* arg1, const char* arg2, int arg3, char* arg4, char* arg5, PyCompilerFlags* arg6, int* arg7, PyArena* arena)
{
	SDK_LOG(LL_CRI, L"[PyParser_ASTFromFile] - %p - %hs - %d - %hs - %hs - %p - %d - %p", arg1, arg2, arg3, arg4, arg5, arg6, arg7, arena);

	NoMercy::CApplication::Instance().OnCloseRequest(EXIT_ERR_UNALLOWED_PYTHON_API, 1);
	return OPyParser_ASTFromFile(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arena);
}
int PyRun_SimpleStringDetour(const char* s)
{
	SDK_LOG(LL_CRI, L"[PyRun_SimpleString] - %hs", s);
	
	return OPyRun_SimpleString(s);
}
int PyRun_SimpleStringFlagsDetour(const char* command, PyCompilerFlags* flags)
{
	SDK_LOG(LL_CRI, L"[PyRun_SimpleStringFlags] - %hs - %p", command, flags);

	return OPyRun_SimpleStringFlags(command, flags);
}
int PyRun_SimpleFileDetour(FILE* arg1, const char* arg2)
{
	SDK_LOG(LL_CRI, L"[PyRun_SimpleFile] - %p - %hs", arg1, arg2);

	return OPyRun_SimpleFile(arg1, arg2);
}
int PyRun_SimpleFileFlagsDetour(FILE* arg1, const char* arg2, int arg3, PyCompilerFlags* arg4)
{
	SDK_LOG(LL_CRI, L"[PyRun_SimpleFileFlags] - %p - %hs - %d - %p", arg1, arg2, arg3, arg4);

	return OPyRun_SimpleFileFlags(arg1, arg2, arg3, arg4);
}
int PyRun_SimpleFileExDetour(FILE* arg1, const char* arg2, int arg3)
{
	SDK_LOG(LL_CRI, L"[PyRun_SimpleFileEx] - %p - %hs - %d", arg1, arg2, arg3);

	return OPyRun_SimpleFileEx(arg1, arg2, arg3);
}
int PyRun_SimpleFileExFlagsDetour(FILE* arg1, const char* arg2, int arg3, PyCompilerFlags* arg4)
{
	SDK_LOG(LL_CRI, L"[PyRun_SimpleFileExFlags] - %p - %hs - %d - %p", arg1, arg2, arg3, arg4);

	return OPyRun_SimpleFileExFlags(arg1, arg2, arg3, arg4);
}
PyObject* PyFile_FromStringDetour(char* arg1, char* arg2)
{
	SDK_LOG(LL_CRI, L"[PyFile_FromString] - %hs - %hs", arg1, arg2);

	return OPyFile_FromString(arg1, arg2);
}
PyObject* PyString_InternFromStringDetour(const char* arg1)
{
	SDK_LOG(LL_CRI, L"[PyString_InternFromString] - %hs", arg1);

	return OPyString_InternFromString(arg1);
}

template <typename T>
inline bool __CreateHook(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
	MEMORY_BASIC_INFORMATION mbi{};
	if (g_winAPIs->VirtualQuery(pTarget, &mbi, sizeof(mbi)))
	{
		SDK_LOG(LL_SYS, L"%p protection: %u", pTarget, mbi.Protect);
	}
	auto status = MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
	if (status != MH_OK)
	{
		SDK_LOG(LL_ERR, L"MH_CreateHook failed with status: %d", status);
		return false;
	}
	status = MH_EnableHook(pTarget);
	if (status != MH_OK)
	{
		SDK_LOG(LL_ERR, L"MH_EnableHook failed with status: %d", status);
		return false;
	}
	return true;
}

bool CMetin2SDKMgr::InitializePythonHooks()
{
	LOCK_MTX_M2;

	SDK_LOG(LL_SYS, L"Initializing Python Hooks...");
	
	auto status = MH_Initialize();
	if (status != MH_OK)
	{
		SDK_LOG(LL_ERR, L"MH_Initialize failed with status: %d", status);
		return false;
	}

	if (!__CreateHook(m_pPy_InitModule4, Py_InitModule4Detour, &OPy_InitModule4))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for Py_InitModule4 (%p)", m_pPy_InitModule4);
		return false;
	}
	if (!__CreateHook(m_pPyParser_ASTFromString, PyParser_ASTFromStringDetour, &OPyParser_ASTFromString))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyParser_ASTFromString (%p)", m_pPyParser_ASTFromString);
		return false;
	}
	if (!__CreateHook(m_pPyParser_ASTFromFile, PyParser_ASTFromFileDetour, &OPyParser_ASTFromFile))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyParser_ASTFromFile (%p)", m_pPyParser_ASTFromFile);
		return false;
	}
	// TESTME
	/*
	if (!__CreateHook(m_pPyRun_SimpleString, PyRun_SimpleStringDetour, &OPyRun_SimpleString))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyRun_SimpleString (%p)", m_pPyRun_SimpleString);
		return false;
	}
	if (!__CreateHook(m_pPyRun_SimpleStringFlags, PyRun_SimpleStringFlagsDetour, &OPyRun_SimpleStringFlags))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyRun_SimpleStringFlags (%p)", m_pPyRun_SimpleStringFlags);
		return false;
	}
	if (!__CreateHook(m_pPyRun_SimpleFile, PyRun_SimpleFileDetour, &OPyRun_SimpleFile))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyRun_SimpleFile (%p)", m_pPyRun_SimpleFile);
		return false;
	}
	if (!__CreateHook(m_pPyRun_SimpleFileFlags, PyRun_SimpleFileFlagsDetour, &OPyRun_SimpleFileFlags))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyRun_SimpleFileFlags (%p)", m_pPyRun_SimpleFileFlags);
		return false;
	}
	if (!__CreateHook(m_pPyRun_SimpleFileEx, PyRun_SimpleFileExDetour, &OPyRun_SimpleFileEx))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyRun_SimpleFileEx (%p)", m_pPyRun_SimpleFileEx);
		return false;
	}
	if (!__CreateHook(m_pPyRun_SimpleFileExFlags, PyRun_SimpleFileExFlagsDetour, &OPyRun_SimpleFileExFlags))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyRun_SimpleFileExFlags (%p)", m_pPyRun_SimpleFileExFlags);
		return false;
	}
	if (!__CreateHook(m_pPyFile_FromString, PyFile_FromStringDetour, &OPyFile_FromString))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyFile_FromString (%p)", m_pPyFile_FromString);
		return false;
	}
	if (!__CreateHook(m_pPyFile_FromStringFlags, PyFile_FromStringFlagsDetour, &OPyFile_FromStringFlags))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyFile_FromStringFlags (%p)", m_pPyFile_FromStringFlags);
		return false;
	}
	if (!__CreateHook(m_pPyString_InternFromString, PyString_InternFromStringDetour, &OPyString_InternFromString))
	{
		SDK_LOG(LL_ERR, L"Failed to create hook for PyString_InternFromString (%p)", m_pPyString_InternFromString);
		return false;
	}
	*/
	
	SDK_LOG(LL_SYS, L"Python Hooks initialized!");
	return true;
}
void CMetin2SDKMgr::RemovePythonModuleWatcher()
{
	LOCK_MTX_M2;

	SDK_LOG(LL_SYS, L"Removing Python Module Watcher...");

	if (OPy_InitModule4)
	{
		MH_DisableHook(m_pPy_InitModule4);
		MH_RemoveHook(m_pPy_InitModule4);
		OPy_InitModule4 = nullptr;
	}

	SDK_LOG(LL_SYS, L"Python Module Watcher removed!");
}

void CMetin2SDKMgr::DestroyPythonHooks()
{	
	LOCK_MTX_M2;

	SDK_LOG(LL_SYS, L"Destroying Python Hooks...");

	if (OPy_InitModule4)
	{
		MH_DisableHook(m_pPy_InitModule4);
		MH_RemoveHook(m_pPy_InitModule4);
		OPy_InitModule4 = nullptr;
	}
	if (OPyParser_ASTFromString)
	{
		MH_DisableHook(m_pPyParser_ASTFromString);
		MH_RemoveHook(m_pPyParser_ASTFromString);
		OPyParser_ASTFromString = nullptr;
	}
	if (OPyParser_ASTFromFile)
	{
		MH_DisableHook(m_pPyParser_ASTFromFile);
		MH_RemoveHook(m_pPyParser_ASTFromFile);
		OPyParser_ASTFromFile = nullptr;
	}
	
	/*
	if (OPyRun_SimpleString)
	{
		MH_DisableHook(m_pPyRun_SimpleString);
		MH_RemoveHook(m_pPyRun_SimpleString);
		OPyRun_SimpleString = nullptr;
	}
	if (OPyRun_SimpleStringFlags)
	{
		MH_DisableHook(m_pPyRun_SimpleStringFlags);
		MH_RemoveHook(m_pPyRun_SimpleStringFlags);
		OPyRun_SimpleStringFlags = nullptr;
	}
	if (OPyRun_SimpleFile)
	{
		MH_DisableHook(m_pPyRun_SimpleFile);
		MH_RemoveHook(m_pPyRun_SimpleFile);
		OPyRun_SimpleFile = nullptr;
	}
	if (OPyRun_SimpleFileFlags)
	{
		MH_DisableHook(m_pPyRun_SimpleFileFlags);
		MH_RemoveHook(m_pPyRun_SimpleFileFlags);
		OPyRun_SimpleFileFlags = nullptr;
	}
	if (OPyRun_SimpleFileEx)
	{
		MH_DisableHook(m_pPyRun_SimpleFileEx);
		MH_RemoveHook(m_pPyRun_SimpleFileEx);
		OPyRun_SimpleFileEx = nullptr;
	}
	if (OPyRun_SimpleFileExFlags)
	{
		MH_DisableHook(m_pPyRun_SimpleFileExFlags);
		MH_RemoveHook(m_pPyRun_SimpleFileExFlags);
		OPyRun_SimpleFileExFlags = nullptr;
	}
	if (OPyFile_FromString)
	{
		MH_DisableHook(m_pPyFile_FromString);
		MH_RemoveHook(m_pPyFile_FromString);
		OPyFile_FromString = nullptr;
	}
	if (OPyFile_FromStringFlags)
	{
		MH_DisableHook(m_pPyFile_FromStringFlags);
		MH_RemoveHook(m_pPyFile_FromStringFlags);
		OPyFile_FromStringFlags = nullptr;
	}
	if (OPyString_InternFromString)
	{
		MH_DisableHook(m_pPyString_InternFromString);
		MH_RemoveHook(m_pPyString_InternFromString);
		OPyString_InternFromString = nullptr;
	}
	*/

	SDK_LOG(LL_SYS, L"Python Hooks destroyed!");
}

// -------

std::vector <std::string> CMetin2SDKMgr::PyTupleToStdVector(PyObject* pyTupleObj)
{
	LOCK_MTX_M2;

	auto vBuffer = std::vector <std::string>();

	if (m_pPyTuple_Check(pyTupleObj))
	{
		for (Py_ssize_t i = 0; i < m_pPyTuple_Size(pyTupleObj); ++i)
		{
			PyObject* value = m_pPyTuple_GetItem(pyTupleObj, i);
			vBuffer.push_back(m_pPyString_AsString(value));
		}
	}

	SDK_LOG(LL_SYS, L"PyTupleToStdVector: %d", vBuffer.size());
	return vBuffer;
}

bool IsKnownLibFile(const std::string& stLibFile)
{
	const auto lstKnownFiles = {
		xorstr_("abc.pyc"), xorstr_("base64.pyc"), xorstr_("bisect.pyc"), xorstr_("codecs.pyc"),
		xorstr_("collections.pyc"), xorstr_("copy.pyc"), xorstr_("copy_reg.pyc"),
		xorstr_("fnmatch.pyc"), xorstr_("functools.pyc"), xorstr_("genericpath.pyc"), xorstr_("hashlib.pyc"),
		xorstr_("heapq.pyc"), xorstr_("httplib.pyc"), xorstr_("keyword.pyc"), xorstr_("linecache.pyc"),
		xorstr_("locale.pyc"), xorstr_("mimetools.pyc"), xorstr_("ntpath.pyc"), xorstr_("nturl2path.pyc"),
		xorstr_("os.pyc"), xorstr_("posixpath.pyc"), xorstr_("pyexpat.pyd"), xorstr_("pyexpat_d.pdb"),
		xorstr_("pyexpat_d.pyd"), xorstr_("random.pyc"), xorstr_("re.pyc"), xorstr_("rfc822.pyc"),
		xorstr_("shutil.pyc"), xorstr_("shutil.pyo"), xorstr_("site.pyc"), xorstr_("socket.pyc"),
		xorstr_("sre_compile.pyc"), xorstr_("sre_constants.pyc"), xorstr_("sre_parse.pyc"), xorstr_("stat.pyc"),
		xorstr_("string.pyc"), xorstr_("struct.pyc"), xorstr_("sysconfig.pyc"), xorstr_("tempfile.pyc"),
		xorstr_("traceback.pyc"), xorstr_("types.pyc"), xorstr_("urllib.pyc"), xorstr_("urllib2.pyc"),
		xorstr_("urlparse.pyc"), xorstr_("UserDict.pyc"), xorstr_("warnings.pyc"), xorstr_("weakref.pyc"),
		xorstr_("_abcoll.pyc"), xorstr_("_locale.pyc"), xorstr_("_socket.pyd"),
		xorstr_("_weakrefset.pyc"), xorstr_("__future__.pyc"),
		xorstr_("encodings\\__init__.pyc"), xorstr_("encodings\\aliases.pyc"), xorstr_("encodings\\cp949.pyc"),
		xorstr_("xml\\dom\\__init__.pyc"), xorstr_("xml\\dom\\domreg.pyc"), xorstr_("xml\\dom\\expatbuilder.pyc"),
		xorstr_("xml\\dom\\minicompat.pyc"), xorstr_("xml\\dom\\minidom.pyc"), xorstr_("xml\\dom\\nodefilter.pyc"),
		xorstr_("xml\\dom\\xmlbuilder.pyc"),
		xorstr_("xml\\filter\\__init__.pyc"), xorstr_("xml\\filter\\_expat.pyc"),
		xorstr_("xml\\__init__.pyc")
	};

	const auto stLibPath = fmt::format(xorstr_("{0}\\lib"), std::filesystem::current_path().string());
	if (!std::filesystem::exists(stLibPath))
	{
		SDK_LOG(LL_ERR, L"IsKnownLibFile: lib path (%hs) does not exist!", stLibPath.c_str());
		return false;
	}

	if (stLibFile.find(stLibPath) == std::string::npos)
	{
		SDK_LOG(LL_ERR, L"IsKnownLibFile: lib file (%hs) is not coming from lib path (%hs)!", stLibFile.c_str(), stLibPath.c_str());
		return false;
	}

	const auto stLibFileWithoutPath = stLibFile.substr(stLibPath.length() + 1);
	SDK_LOG(LL_SYS, L"IsKnownLibFile: lib file without path: %hs", stLibFileWithoutPath.c_str());
	
	for (const auto& stKnownFile : lstKnownFiles)
	{
		if (stLibFileWithoutPath.find(stKnownFile) != std::string::npos)
		{
			SDK_LOG(LL_SYS, L"IsKnownLibFile: lib file (%hs) is known!", stLibFile.c_str());
			return true;
		}
	}

	SDK_LOG(LL_ERR, L"IsKnownLibFile: lib file (%hs) is not known!", stLibFile.c_str());
	return false;
}

void CMetin2SDKMgr::CheckPythonModules()
{
#if 0
	SDK_LOG(LL_SYS, L"Checking Python Modules...");

	LOCK_MTX_M2;

	auto modules = m_pPyImport_GetModuleDict();
	if (!modules)
	{
		SDK_LOG(LL_ERR, L"PyImport_GetModuleDict failed!");
		return;
	}

	auto idx = 0;
	Py_ssize_t pos = 0;
	PyObject *mod_name, *mod;
    while (m_pPyDict_Next(modules, &pos, &mod_name, &mod))
	{
		idx++;
//		SDK_LOG(LL_SYS, L"Current module: %d", idx);
		
		const auto stModuleName = std::string(m_pPyString_AsString(mod_name));
		const auto bIsFile = m_pPyObject_HasAttrString(mod, xorstr_("__file__"));
//		SDK_LOG(LL_SYS, L"Module: %hs, IsFile: %d", stModuleName.c_str(), bIsFile ? 1 : 0);

		if (bIsFile) // file
		{
//			SDK_LOG(LL_SYS, L"Checking python file: %hs", stModuleName.c_str());
			
			auto pyModuleFileName = m_pPyObject_GetAttrString(mod, xorstr_("__file__"));
//			SDK_LOG(LL_SYS, L"Module file name: %p", pyModuleFileName);
			
			if (!pyModuleFileName || pyModuleFileName == m_pPy_None())
			{
				SDK_LOG(LL_ERR, L"Unknown module detected: %hs", stModuleName.c_str());
				CApplication::Instance().OnCloseRequest(EXIT_ERR_SUS_PYTHON_COMP, 1);
			}
//			SDK_LOG(LL_SYS, L"Module file name points some known mem");

			auto stCurrModuleFile = std::string(m_pPyString_AsString(pyModuleFileName));
//			SDK_LOG(LL_SYS, L"Module file name: %hs", stCurrModuleFile.c_str());
			
			if (!m_pGetMappedFileIsExist(stCurrModuleFile.c_str()) && !IsKnownLibFile(stCurrModuleFile))
			{
				SDK_LOG(LL_ERR, L"Suspected module file detected: %hs", stCurrModuleFile.c_str());
				CApplication::Instance().OnCloseRequest(EXIT_ERR_SUS_PYTHON_COMP, 2);
			}

//			SDK_LOG(LL_SYS, L"Module file is exist in pack: %hs", stCurrModuleFile.c_str());
		}
		else // builtin
		{
//			SDK_LOG(LL_SYS, L"Module: %hs is builtin", stModuleName.c_str());
			
			if (!IsKnownModule(mod)) // does not created by client's python api
			{
				SDK_LOG(LL_ERR, L"Suspected module detected: %hs", stModuleName.c_str());
				CApplication::Instance().OnCloseRequest(EXIT_ERR_SUS_PYTHON_COMP, 3);
			}

//			SDK_LOG(LL_SYS, L"Module: %hs is known", stModuleName.c_str());
		}
//		SDK_LOG(LL_SYS, L"Module: %hs checked!", stModuleName.c_str());

		m_pPy_DecRef(mod_name);
		m_pPy_DecRef(mod);

//		SDK_LOG(LL_SYS, L"Module: %hs objects released!", stModuleName.c_str());
	}
	SDK_LOG(LL_SYS, L"%d Python Modules checked!", idx);

	m_pPy_DecRef(modules);

//	SDK_LOG(LL_SYS, L"Python Modules checked!");
#endif
}
