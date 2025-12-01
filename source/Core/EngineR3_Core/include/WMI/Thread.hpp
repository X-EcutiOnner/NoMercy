/******************************************************************************
 *
 * Copyright (c) 1999-2008 Antillia.com TOSHIYUKI ARAI. ALL RIGHTS RESERVED.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 *
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 *  Thread.h
 *
 *****************************************************************************/

#pragma once

#include "InvalidHandleException.hpp"

namespace SOL
{
	typedef unsigned(__stdcall* LPTHREAD_PROC)(void*);

	class Thread : public Object
	{
		static const UINT WM_SOL_THREAD_CANCEL = (WM_USER + 2009);

	public:
		Thread(DWORD stack = 0, void* param = nullptr)
		{
			this->m_param = param;

			// Create a suspended thread.
			DWORD flags = CREATE_SUSPENDED;

			m_handle = (HANDLE)_beginthreadex(nullptr, stack, Thread::procedure, this, flags, &m_threadId);
			if (!m_handle || m_handle == INVALID_HANDLE_VALUE)
			{
				m_handle = nullptr;
				throw InvalidHandleException(xorstr_("Failed to create a thread"), NoMercyCore::g_winAPIs->GetLastError());
			}
		}
		~Thread()
		{
			kill();
		}

		auto getParam() const { return m_param; };
		auto getThreadId() const { return m_threadId; };
		auto getHandle() const { return m_handle; };

		void exit(DWORD exitCode)
		{
			_endthreadex(exitCode);
		}

		// Thread main loop
		virtual void run()
		{
			// Do something
		}

		virtual DWORD start()
		{
			return resume();
		}

		bool close()
		{
			if (m_handle)
			{
				const auto ret = NoMercyCore::g_winAPIs->CloseHandle(m_handle);
				m_handle = nullptr;
				return ret;
			}

			return false;
		}

		void sleep(DWORD time)
		{
			NoMercyCore::g_winAPIs->Sleep(time);
		}

		DWORD suspend()
		{
			return NoMercyCore::g_winAPIs->SuspendThread(m_handle);
		}

		DWORD resume()
		{
			return NoMercyCore::g_winAPIs->ResumeThread(m_handle);
		}

		void setPriority(int priority)
		{
			NoMercyCore::g_winAPIs->SetThreadPriority(m_handle, priority);
		}

		bool post(UINT message, WPARAM wParam, LPARAM lParam)
		{
			if (m_handle)
				return NoMercyCore::g_winAPIs->PostThreadMessageW(m_threadId, message, wParam, lParam) ? true : false;
			return false;
		}

		bool getExitCode(DWORD* id)
		{
			return NoMercyCore::g_winAPIs->GetExitCodeThread(m_handle, id);
		}

		void kill()
		{
			if (m_handle)
			{
				this->close();

				DWORD id = 0;
				while (this->getExitCode(&id))
				{
					if (id == STILL_ACTIVE)
					{
						this->dispatchMessage();
						continue;
					}
					break;
				}
			}

			m_handle = NULL;
		}

		BOOL terminate(int exitCode)
		{
			BOOL ret = FALSE;

			if (m_handle)
				ret = NoMercyCore::g_winAPIs->TerminateThread(m_handle, exitCode);

			return ret;
		}

		int wait(int interval = INFINITE)
		{
			int ret = 0;

			if (m_handle)
				ret = NoMercyCore::g_winAPIs->WaitForSingleObject(m_handle, interval);

			return ret;
		}

		void msgWait()
		{
			while (true)
			{
				if (NoMercyCore::g_winAPIs->MsgWaitForMultipleObjects(1, &m_handle, FALSE, INFINITE, QS_ALLINPUT | QS_ALLEVENTS) == WAIT_OBJECT_0 + 1)
				{
					this->dispatchMessage();
				}
				else
				{
					break;
				}
			}
		}

		void dispatchMessage()
		{
			MSG msg{ 0 };
			while (NoMercyCore::g_winAPIs->PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
			{
				NoMercyCore::g_winAPIs->SleepEx(10, TRUE);

				if (msg.message == WM_SOL_THREAD_CANCEL)
				{
					this->terminate(0);
					break;
				}

				NoMercyCore::g_winAPIs->TranslateMessage(&msg);
				NoMercyCore::g_winAPIs->DispatchMessageW(&msg);
			}
		}

		virtual void stop()
		{
			this->post(WM_SOL_THREAD_CANCEL, 0, 0);
		}

		UINT getCancelMessage()
		{
			return WM_SOL_THREAD_CANCEL;
		}

	protected:
		void setHandle(HANDLE handle) { m_handle = handle; }
		void setThreadId(int id) { m_threadId = id; }

		static unsigned WINAPI procedure(void* param)
		{
			const auto thread = (Thread*)param;
			if (thread)
				thread->run();
			return 0;
		}

	private:
		void*			m_param;
		unsigned int	m_threadId;
		HANDLE			m_handle;
	};
}
