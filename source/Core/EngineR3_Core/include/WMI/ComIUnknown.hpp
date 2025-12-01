/******************************************************************************
 *
 * Copyright (c) 2009 Antillia.com TOSHIYUKI ARAI. ALL RIGHTS RESERVED.
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
 *  ComIUnknown.h
 *
 *****************************************************************************/

#pragma once

#include <objbase.h>
#include "Object.hpp"
#include "Exception.hpp"
#include "COMTypeConverter.hpp"

namespace SOL
{
	class ComIUnknown : public Object
	{
	public:
		ComIUnknown(IUnknown* pUnk = nullptr) :
			m_pUnknown(pUnk)
		{
		}
		~ComIUnknown()
		{
			clear();
		}

		void clear()
		{
			if (m_pUnknown)
			{
				m_pUnknown->Release();
				m_pUnknown = nullptr;
			}
		}

		ULONG addRef()
		{
			ULONG ref = 0;
			if (m_pUnknown)
				ref = m_pUnknown->AddRef();

			return ref;
		}
		ULONG release()
		{
			ULONG ref = 0;
			if (m_pUnknown)
				ref = m_pUnknown->Release();

			return ref;
		}

		HRESULT queryInterface(REFIID riid, void** ppvObject)
		{
			HRESULT hr = getIUnknown()->QueryInterface(riid, ppvObject);
			if (FAILED(hr))
				throw hr;
			
			return hr;
		}

		IDispatch* queryInterface(REFIID riid)
		{
			IDispatch* pObject = nullptr;
			HRESULT hr = queryInterface(riid, (void**)&pObject);
			if (FAILED(hr))
				throw hr;
			
			return pObject;
		}

		IEnumVARIANT* getEnumVariant()
		{
			IEnumVARIANT* pEnum = nullptr;
			HRESULT hr = queryInterface(__uuidof(IEnumVARIANT), (void**)&pEnum);
			if (FAILED(hr))
				throw hr;
			
			return pEnum;
		}

		void set(IUnknown* pUnk)
		{
			m_pUnknown = pUnk;
		}

		IUnknown* getIUnknown()
		{
			if (!m_pUnknown)
				throw E_POINTER;

			return m_pUnknown;
		}

		operator IUnknown* ()
		{
			return getIUnknown();
		}


		bool toBool(VARIANT_BOOL varBool)
		{
			bool rc = false;
			if (varBool == VARIANT_TRUE)
				rc = true;

			return rc;
		}
		VARIANT_BOOL toVariantBool(bool bBool)
		{
			VARIANT_BOOL rc = VARIANT_FALSE;
			if (bBool == true)
				rc = VARIANT_TRUE;

			return rc;
		}

		bool toString(_variant_t var, _bstr_t& string)
		{
			COMTypeConverter converter;
			return converter.toString(var, string);
		}
		_bstr_t toString(_variant_t var)
		{
			COMTypeConverter converter;
			return converter.toString(var);
		}

	private:
		IUnknown* m_pUnknown;
	};
}
