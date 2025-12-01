/******************************************************************************
 *
 * Copyright (c) 2010 Antillia.com TOSHIYUKI ARAI. ALL RIGHTS RESERVED.
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
 *  WbemClassObjectEnumerator.h
 *
 *****************************************************************************/

#pragma once

#include <objbase.h>
#include "ComIUnknown.hpp"
#include "COMTypeConverter.hpp"

namespace SOL
{
	class WbemClassObjectEnumerator : public ComIUnknown
	{
	public:
		WbemClassObjectEnumerator(IUnknown* enumerator = nullptr) :
			ComIUnknown(enumerator)
		{
		}
		~WbemClassObjectEnumerator()
		{
		}

		IEnumWbemClassObject* getEnumerator()
		{
			return (IEnumWbemClassObject*)getIUnknown();
		}

		HRESULT reset()
		{
			HRESULT hr = S_OK;

			IEnumWbemClassObject* enumerator = getEnumerator();
			if (FAILED(hr = enumerator->Reset()))
			{
				HR_Exception(hr);
			}

			return hr;
		}

		IWbemClassObject* next(__in long lTimeout, __in ULONG uCount, __out ULONG* puReturned)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* apObjects = NULL;
			IEnumWbemClassObject* enumerator = getEnumerator();
			if (FAILED(hr = enumerator->Next(lTimeout, uCount, &apObjects, puReturned)))
			{
				HR_Exception(hr);
			}
			
			return apObjects;
		}

		IWbemClassObject* next()
		{
			ULONG returned = 0;
			IWbemClassObject* apObjects = NULL;

			IEnumWbemClassObject* enumerator = getEnumerator();
			HRESULT hr = enumerator->Next(WBEM_INFINITE, 1, &apObjects, &returned);
			if (hr == S_FALSE || returned == 0)
			{
				return nullptr;
			}
			else if (FAILED(hr))
			{
				HR_Exception(hr);
			}

			return apObjects;
		}

		HRESULT next(__in long lTimeout, __in ULONG uCount, __out IWbemClassObject** apObjects, __out ULONG* puReturned)
		{
			HRESULT hr = S_OK;

			IEnumWbemClassObject* enumerator = getEnumerator();
			if (FAILED(hr = enumerator->Next(lTimeout, uCount, apObjects, puReturned)))
			{
				HR_Exception(hr);
			}

			return hr;
		}

		HRESULT nextAsync(__in ULONG uCount, __in IWbemObjectSink* pSink)
		{
			HRESULT hr = S_OK;

			IEnumWbemClassObject* enumerator = getEnumerator();
			if (FAILED(hr = enumerator->NextAsync(uCount, pSink)))
			{
				HR_Exception(hr);
			}

			return hr;
		}

		IEnumWbemClassObject* clone()
		{
			HRESULT hr = S_OK;

			IEnumWbemClassObject* pEnum = NULL;
			IEnumWbemClassObject* enumerator = getEnumerator();
			if (FAILED(hr = enumerator->Clone(&pEnum)))
			{
				HR_Exception(hr);
			}
			
			return pEnum;
		}

		HRESULT skip(__in long lTimeout, __in ULONG nCount)
		{
			HRESULT hr = S_OK;

			IEnumWbemClassObject* enumerator = getEnumerator();
			if (FAILED(hr = enumerator->Skip(lTimeout, nCount)))
			{
				HR_Exception(hr);
			}

			return hr;
		}
	};
}
