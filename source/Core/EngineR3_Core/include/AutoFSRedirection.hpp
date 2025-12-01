#pragma once
#include "Application.hpp"
#include "NtApiWrapper.hpp"

namespace NoMercyCore
{
	class CAutoDisableFileRedirection
	{
	public:
		CAutoDisableFileRedirection() :
			m_pvCookie(nullptr)
		{
			if (CApplication::InstancePtr() && CApplication::Instance().WinAPIManagerInstance() && CApplication::Instance().WinAPIManagerInstance()->NTHelper())
			{
				CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &m_pvCookie);
			}
		}

		~CAutoDisableFileRedirection()
		{
			if (CApplication::InstancePtr() && CApplication::Instance().WinAPIManagerInstance() && CApplication::Instance().WinAPIManagerInstance()->NTHelper())
			{
				CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, m_pvCookie, nullptr);
			}
		}

	private:
		PVOID m_pvCookie;
	};
};
