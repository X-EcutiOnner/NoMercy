/******************************************************************************
 *
 * Copyright (c) 1999-2015 Antillia.com TOSHIYUKI ARAI. ALL RIGHTS RESERVED.
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
 *  Exception.h
 *
 *****************************************************************************/

#pragma once

#include "Object.hpp"

namespace SOL
{
	class Exception : public Object
	{
		static const int MAX_MESSAGE = 1024 * 2;

	public:
		Exception(int error = 0) :
			m_message(nullptr), m_errorCode(error), m_hresult(0)
		{
			this->m_message = new char[MAX_MESSAGE];
			memset(this->m_message, 0, MAX_MESSAGE);
		}
		Exception(const char* msg, int error = 0) :
			m_message(nullptr), m_errorCode(error), m_hresult(0)
		{
			if (msg)
			{
				size_t slen = strlen(msg) + 1;
				this->m_message = new char[slen];
				strcpy_s(this->m_message, slen, msg);
			}
		}
		Exception(const wchar_t* msg, int error = 0) :
			m_message(nullptr), m_errorCode(error), m_hresult(0)
		{
			if (msg)
				this->m_message = toMBString(msg);
		}
		Exception(int error, const char* format, ...) :
			m_message(nullptr), m_errorCode(error), m_hresult(0)
		{
			this->m_message = new char[MAX_MESSAGE];
			memset(this->m_message, 0, MAX_MESSAGE);

			va_list pos;
			va_start(pos, format);
			vsprintf_s(this->m_message, MAX_MESSAGE, format, pos);
			va_end(pos);
		}
		Exception(DWORD error, const char* format, ...) :
			m_message(nullptr), m_errorCode(error), m_hresult(0)
		{
			this->m_message = new char[MAX_MESSAGE];
			memset(this->m_message, 0, MAX_MESSAGE);

			va_list pos;
			va_start(pos, format);
			vsprintf_s(this->m_message, MAX_MESSAGE, format, pos);
			va_end(pos);
		}
		Exception(int error, const wchar_t* format, ...) :
			m_message(nullptr), m_errorCode(error), m_hresult(0)
		{
			wchar_t wmessage[MAX_MESSAGE];
			memset(wmessage, (wchar_t)0, MAX_MESSAGE);

			va_list pos;
			va_start(pos, format);
			_vsnwprintf_s(wmessage, MAX_MESSAGE, _TRUNCATE, format, pos);
			va_end(pos);

			this->m_message = toMBString(wmessage);
		}
		Exception(DWORD error, const wchar_t* format, ...) :
			m_message(nullptr), m_errorCode(error), m_hresult(0)
		{
			wchar_t wmessage[MAX_MESSAGE];
			memset(wmessage, (wchar_t)0, MAX_MESSAGE);

			va_list pos;
			va_start(pos, format);
			_vsnwprintf_s(wmessage, MAX_MESSAGE, _TRUNCATE, format, pos);
			va_end(pos);

			this->m_message = toMBString(wmessage);
		}
		Exception(HRESULT hr, const wchar_t* format, ...) :
			m_message(nullptr), m_errorCode(0), m_hresult(hr)
		{
			wchar_t wmessage[MAX_MESSAGE];
			memset(wmessage, (wchar_t)0, MAX_MESSAGE);

			va_list pos;
			va_start(pos, format);
			_vsnwprintf_s(wmessage, MAX_MESSAGE, _TRUNCATE, format, pos);
			va_end(pos);

			this->m_message = toMBString(wmessage);
		}
		Exception(HRESULT hr, const char* format, ...) :
			m_message(nullptr), m_errorCode(0), m_hresult(hr)
		{
			this->m_message = new char[MAX_MESSAGE];
			memset(this->m_message, 0, MAX_MESSAGE);

			va_list pos;
			va_start(pos, format);
			vsprintf_s(this->m_message, MAX_MESSAGE, format, pos);
			va_end(pos);
		}

		~Exception()
		{
			if (m_message)
			{
				delete[] m_message;
				m_message = nullptr;
			}
		}

		auto getErrorMessage() const { return m_message; };
		auto getErrorCode() const { return m_errorCode; };
		auto getHRESULT() const { return m_hresult; };

	protected:
		char* toMBString(const wchar_t* wcstring)
		{
			char* mbstring = "";

			if (!wcstring)
				return mbstring;

			int cb = NoMercyCore::g_winAPIs->WideCharToMultiByte(CP_ACP, 0, wcstring, -1, NULL, 0, NULL, NULL);
			if (cb > 0)
			{
				mbstring = new char[cb];
				mbstring[0] = '\0';
				NoMercyCore::g_winAPIs->WideCharToMultiByte(CP_ACP, 0, wcstring, -1, mbstring, cb, NULL, NULL);
			}
			return mbstring;
		}

		void formatMessage(const char* format, va_list pos)
		{
			vsprintf_s(this->m_message, MAX_MESSAGE, format, pos);
		}

	private:
		char* m_message;
		int m_errorCode;
		HRESULT m_hresult;
	};

#define IException(format, ...) Exception(0, xorstr_(L"%s (%d) %s: "), format, xorstr_(__FILE__), __LINE__, xorstr_(__FUNCTION__), __VA_ARGS__);
#define HR_Exception(hr) throw Exception(hr, xorstr_(L"%s :: %p"), xorstr_(__FUNCTION__), hr);
}
