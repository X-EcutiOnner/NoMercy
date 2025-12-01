#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <string>
#include <lazy_importer.hpp>

class CLimitSingleInstance
{
	public:
		explicit CLimitSingleInstance()
		{
			__Initialize();
		}
		explicit CLimitSingleInstance(const std::wstring& wstMutexName) :
			m_wstMutexName(wstMutexName)
		{
			__Initialize();
		}
		CLimitSingleInstance::~CLimitSingleInstance()
		{
			CloseInstance();
		}

		bool CreateInstance()
		{
			if (!m_fnCreateMutexW)
				return false;

			SECURITY_ATTRIBUTES sa{ 0 };
			sa.nLength = sizeof(sa);

			m_hMutex = m_fnCreateMutexW(&sa, FALSE, m_wstMutexName.c_str());
			return IsValid();
		}

		void CloseInstance()
		{
			if (m_fnCloseHandle && IsValid())
			{
				m_fnCloseHandle(m_hMutex);
				m_hMutex = nullptr;
			}
		}

		bool IsAnotherInstanceRunning()
		{
			if (!m_fnOpenMutexW)
				return true;

			m_hMutex = m_fnOpenMutexW(SYNCHRONIZE, FALSE, m_wstMutexName.c_str());

			const auto bRet = IsValid();

			CloseInstance();
			return bRet;
		}

		bool ProtectInstance()
		{
			if (!m_fnSetHandleInformation || !IsValid())
				return false;
			return !!m_fnSetHandleInformation(m_hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
		}

		bool IsValid()
		{
			return m_hMutex && m_hMutex != INVALID_HANDLE_VALUE;
		}

	protected:
		void __Initialize()
		{
			m_fnCreateMutexW		 = LI_FN(CreateMutexW).forwarded_safe();
			m_fnOpenMutexW			 = LI_FN(OpenMutexW).forwarded_safe();
			m_fnCloseHandle			 = LI_FN(CloseHandle).forwarded_safe();
			m_fnSetHandleInformation = LI_FN(SetHandleInformation).forwarded_safe();

			if (!m_fnCreateMutexW || !m_fnOpenMutexW || !m_fnCloseHandle || !m_fnSetHandleInformation)
				std::abort();
		}

	private:
		decltype(&CreateMutexW)			m_fnCreateMutexW{ nullptr };
		decltype(&OpenMutexW)			m_fnOpenMutexW{ nullptr };
		decltype(&CloseHandle)			m_fnCloseHandle{ nullptr };
		decltype(&SetHandleInformation) m_fnSetHandleInformation{ nullptr };

		std::wstring	m_wstMutexName{ L"" };
		HANDLE			m_hMutex{ nullptr };
};
