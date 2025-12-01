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
 *  ComObjectSet.h
 *
 *****************************************************************************/

#pragma once

#include <xorstr.hpp>
#include "ComObject.hpp"

namespace SOL
{
	class ComObjectSet : public ComObject
	{
	public:
		ComObjectSet(IDispatch* pDisp = nullptr) :
			ComObject(pDisp)
		{
		}
		~ComObjectSet()
		{
		}

		virtual long getCount()
		{
			return 0;
		}

		virtual IEnumVARIANT* getNewEnum()
		{
			HRESULT hr = E_FAIL;

			VARIANT result;
			VariantInit(&result);

			hr = getProperty(xorstr_(L"_NewEnum"), &result);
			if (FAILED(hr))
				throw hr;

			IEnumVARIANT* pEnumVar = NULL;

			IUnknown* pUnk = result.pdispVal;
			if (pUnk)
			{
				hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void**)&pEnumVar);
				pUnk->Release();
				pEnumVar->Reset();

				if (FAILED(hr))
					throw hr;
			}
			else
			{
				throw E_POINTER;
			}

			return pEnumVar;
		}

		virtual HRESULT getNewEnum(IEnumVARIANT** ppEnumVar)
		{
			HRESULT hr = E_FAIL;

			if (ppEnumVar == NULL)
				return hr;

			VARIANT result;
			VariantInit(&result);

			if (FAILED(hr = getProperty(xorstr_(L"_NewEnum"), &result)))
				throw hr;

			IUnknown* pUnk = result.pdispVal;
			if (pUnk)
			{
				hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void**)ppEnumVar);
				pUnk->Release();

				if (FAILED(hr))
					throw hr;
			}
			else
			{
				throw E_POINTER;
			}

			return hr;
		}
	};
}
