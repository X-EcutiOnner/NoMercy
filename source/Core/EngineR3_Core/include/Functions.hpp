#pragma once

namespace NoMercyCore
{
	class CFunctions : public CSingleton <CFunctions>
	{
	public:
		CFunctions();
		virtual ~CFunctions();

		std::string GetCurrentTimeString();
		std::string GetFixedBuildDate();

		std::wstring FindExecutableRealPath(const std::wstring& wstPath);

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
		int OpenConsoleWindowEx();
		void OpenConsoleWindow();
#endif
	};
};
