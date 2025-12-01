#pragma region Includes
#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"

#include "../../../Common/FilePtr.hpp"
#include "../../../Common/HandleGuard.hpp"
#include "../Anti/AntiBreakpoint.hpp"
#include "../Anti/AntiDebug.hpp"
#include "../Common/MessageProcManager.hpp"
#include "../SelfProtection/SelfProtection.hpp"
#include "../Hook/Hooks.hpp"
#include "../SelfProtection/Pointers.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"
#include "../../EngineR3_Core/include/Pe.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ThreadEnumerator.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include "../../EngineR3_Core/include/AutoFSRedirection.hpp"
#include "../../EngineR3_Core/include/Elevation.hpp"
#include "../Helper/MemoryHelper.hpp"
#include "../Helper/ProcessHelper.hpp"
#include "../Helper/ThreadHelper.hpp"
#include "../Helper/HandleHelper.hpp"
#include "../Helper/ModuleHelper.hpp"
#include "../Helper/SessionHelper.hpp"
#include "../Helper/SectionHelper.hpp"
#include "../Thread/ThreadStackWalker.hpp"
#include "../Monitor/MemoryAccessDetect.hpp"
#include "../Common/ExceptionHandlers.hpp"

#include <DbgHelp.h>
#include <ShObjIdl.h>
#include <werapi.h>
#include <strsafe.h>
#include <intrin.h>

#include <ZipLib/ZipFile.h>
#include <ZipLib/streams/memstream.h>
#include <ZipLib/methods/Bzip2Method.h>

#include <MinHook.h>

#include <cryptopp/integer.h>
#include <cryptopp/rsa.h>
#include <cryptopp/pem.h>
#include <cryptopp/osrng.h>

#include <crashpad/client/simulate_crash_win.h>

#include "../Hook/Tls.hpp"

#include <sentry.h>
#include <cassert>

#pragma endregion Includes

namespace NoMercy
{
	void CApplication::__InitTestFunctions()
	{
		return;
	}
}
	 