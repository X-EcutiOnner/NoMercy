/******************************************************************************
 *
 * Copyright (c) 2012 Antillia.com TOSHIYUKI ARAI. ALL RIGHTS RESERVED.
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
 *  SafeArray.h
 *
 *****************************************************************************/

#pragma once

#include "Object.hpp"
#include "Exception.hpp"

namespace SOL
{
	class SafeArray : public Object
	{
	public:
		SafeArray(SAFEARRAY* ar = nullptr) :
			array(ar), varType(0)
		{
		}
		~SafeArray()
		{
			clear();
		}

		void clear()
		{
			if (array)
			{
				SafeArrayDestroy(array);
				array = nullptr;
			}
		}

		operator SAFEARRAY* ()
		{
			return getArray();
		}

		bool create(VARTYPE vt, unsigned int dims, SAFEARRAYBOUND* bound)
		{
			bool rc = false;

			if (array)
				throw Exception(0, xorstr_(L"SafeArray is already created"));

			SAFEARRAY* sa = SafeArrayCreate(vt, dims, bound);
			if (sa)
			{
				varType = vt;
				array = sa;
				rc = true;
			}
			else
			{
				throw Exception(0, xorstr_(L"Failed to create SafeArray"));
			}

			return rc;
		}

		bool create(VARTYPE vt, long lLbound, unsigned int cElements)
		{
			bool rc = false;

			if (array)
				throw Exception(0, xorstr_(L"SafeArray is already created"));

			SAFEARRAY* sa = SafeArrayCreateVector(vt, lLbound, cElements);
			if (sa)
			{
				varType = vt;
				array = sa;
				rc = true;
			}
			else
			{
				throw Exception(0, xorstr_(L"Failed to create SafeArray"));
			}

			return rc;
		}

		SAFEARRAY* getArray()
		{
			if (array == NULL)
				throw Exception(0, xorstr_(L"SAFEARRAY is NULL"));

			return array;
		}

		VARTYPE getType()
		{
			return varType;
		}

		long getLBound()
		{
			SAFEARRAY* ar = getArray();

			long value = 0;
			SafeArrayGetLBound(ar, 1, &value);

			return value;
		}

		long getUBound()
		{
			SAFEARRAY* ar = getArray();

			long value = 0;
			SafeArrayGetUBound(ar, 1, &value);

			return value;
		}

		HRESULT accessData(void HUGEP** ppvData)
		{
			SAFEARRAY* ar = getArray();

			HRESULT hr = SafeArrayAccessData(ar, ppvData);
			if (FAILED(hr))
				throw hr;
			
			return hr;
		}

		HRESULT unaccessData()
		{
			SAFEARRAY* ar = getArray();

			HRESULT hr = SafeArrayUnaccessData(ar);
			if (FAILED(hr))
				throw hr;

			return hr;
		}

		_bstr_t getString(long index)
		{
			SAFEARRAY* ar = getArray();

			wchar_t* string = NULL;
			HRESULT hr = SafeArrayGetElement(ar, &index, &string);
			if (FAILED(hr))
				throw hr;

			return _bstr_t(string, false);
		}

		_variant_t getElement(long index)
		{
			SAFEARRAY* ar = getArray();

			VARIANT var;
			VariantInit(&var);

			HRESULT hr = SafeArrayGetElement(ar, &index, &var);
			if (FAILED(hr))
				throw hr;

			return _variant_t(var, false);
		}


		HRESULT putElement(long* indices, void* pv)
		{
			SAFEARRAY* ar = getArray();

			HRESULT hr = SafeArrayPutElement(ar, indices, pv);
			if (FAILED(hr))
				throw hr;

			return hr;
		}

		HRESULT getDim()
		{
			SAFEARRAY* ar = getArray();

			HRESULT hr = SafeArrayGetDim(ar);
			return hr;
		}

		HRESULT redim(SAFEARRAYBOUND* psaboundNew)
		{
			SAFEARRAY* ar = getArray();

			HRESULT hr = SafeArrayRedim(ar, psaboundNew);
			if (FAILED(hr))
				throw hr;

			return hr;
		}

		HRESULT lock()
		{
			SAFEARRAY* ar = getArray();

			HRESULT hr = SafeArrayLock(ar);
			if (FAILED(hr))
				throw hr;

			return hr;
		}

		HRESULT unlock()
		{
			SAFEARRAY* ar = getArray();

			HRESULT hr = SafeArrayUnlock(ar);
			if (FAILED(hr))
				throw hr;

			return hr;
		}

		SAFEARRAY* copy()
		{
			SAFEARRAY* psaOut = NULL;
			SAFEARRAY* ar = getArray();

			HRESULT hr = SafeArrayCopy(ar, &psaOut);
			if (FAILED(hr))
				throw hr;

			return psaOut;
		}

		UINT getElementSize()
		{
			SAFEARRAY* ar = getArray();
			return SafeArrayGetElemsize(ar);
		}

	private:
		VARTYPE    varType;  //Used in create method.
		SAFEARRAY* array;
	};
}
