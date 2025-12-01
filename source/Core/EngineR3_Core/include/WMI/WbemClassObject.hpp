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
 *  WbemClassObject.h
 *
 *****************************************************************************/

#pragma once

#include <objbase.h>
#include <wbemidl.h>
#include <wbemdisp.h>

#include "ComIUnknown.hpp"
#include "COMTypeConverter.hpp"
#include "SafeArray.hpp"

namespace SOL
{
	class WbemClassObject : public ComIUnknown
	{
	public:
		WbemClassObject(IUnknown* classObject = nullptr) :
			ComIUnknown(classObject)
		{
		}
		~WbemClassObject()
		{
		}


		IWbemClassObject* getClassObject()
		{
			return (IWbemClassObject*)getIUnknown();
		}


		IWbemQualifierSet* getQualifierSet()
		{
			HRESULT hr = S_OK;

			IWbemQualifierSet* pQualSet = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->GetQualifierSet(&pQualSet)))
			{
				HR_Exception(hr);
			}
			
			return pQualSet;
		}

		HRESULT get(__in LPCWSTR wszName, __in long lFlags, __out VARIANT* pVal, __out CIMTYPE* pType, __out long* plFlavor)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->Get(wszName, lFlags, pVal, pType, plFlavor)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		_variant_t get(__in LPCWSTR wszName, __in long lFlags = 0)
		{
			HRESULT hr = S_OK;

			VARIANT var;
			VariantInit(&var);

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->Get(wszName, lFlags, &var, NULL, NULL)))
			{
				HR_Exception(hr);
			}
			
			return _variant_t(var, false);
		}

		HRESULT put(__in LPCWSTR wszName, __in long lFlags, __in VARIANT* pVal, __in CIMTYPE type)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->Put(wszName, lFlags, pVal, type)))
			{
				HR_Exception(hr);
			}

			return hr;
		}

		HRESULT remove(__in LPCWSTR wszName)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->Delete(wszName)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		SAFEARRAY* getNames(__in LPCWSTR wszQualifierName, __in long lFlags, __in VARIANT* pQualifierVal)
		{
			HRESULT hr = S_OK;

			SAFEARRAY* pNames = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->GetNames(wszQualifierName, lFlags, pQualifierVal, &pNames)))
			{
				HR_Exception(hr);
			}
			
			return pNames;
		}

		SAFEARRAY* getNames(__in long lFlags = WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY)
		{
			HRESULT hr = S_OK;

			SAFEARRAY* pNames = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->GetNames(NULL, lFlags, NULL, &pNames)))
			{
				HR_Exception(hr);
			}
			
			return pNames;
		}

		HRESULT beginEnumeration(__in long lEnumFlags)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->BeginEnumeration(lEnumFlags)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		HRESULT next(__in long lFlags,__out BSTR* strName, __out VARIANT* pVal, __out CIMTYPE* pType, __out long* plFlavor)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->Next(lFlags, strName, pVal, pType, plFlavor)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		HRESULT endEnumeration()
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->EndEnumeration()))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IWbemQualifierSet* getPropertyQualifierSet(__in LPCWSTR wszProperty)
		{
			HRESULT hr = S_OK;

			IWbemQualifierSet* pQualSet = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->GetPropertyQualifierSet(wszProperty, &pQualSet)))
			{
				HR_Exception(hr);
			}
			
			return pQualSet;
		}

		IWbemClassObject* clone()
		{
			HRESULT hr = S_OK;

			IWbemClassObject* pCopy = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->Clone(&pCopy)))
			{
				HR_Exception(hr);
			}
			
			return pCopy;
		}

		_bstr_t getObjectText(__in long lFlags)
		{
			HRESULT hr = S_OK;

			BSTR strObjectText = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->GetObjectText(lFlags, &strObjectText)))
			{
				HR_Exception(hr);
			}
			
			return _bstr_t(strObjectText, false);
		}

		IWbemClassObject* spawnDerivedClass(__in long lFlags)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* pNewClass = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->SpawnDerivedClass(lFlags, &pNewClass)))
			{
				HR_Exception(hr);
			}
		
			return pNewClass;
		}

		IWbemClassObject* spawnInstance(__in long lFlags)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* pNewInstance = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->SpawnInstance(lFlags, &pNewInstance)))
			{
				HR_Exception(hr);
			}
			
			return pNewInstance;
		}

		HRESULT compareTo(__in long lFlags, __in IWbemClassObject* pCompareTo)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->CompareTo(lFlags, pCompareTo)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		_bstr_t getPropertyOrigin(__in LPCWSTR wszName)
		{
			HRESULT hr = S_OK;

			BSTR strClassName = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->GetPropertyOrigin(wszName, &strClassName)))
			{
				HR_Exception(hr);
			}
			
			return _bstr_t(strClassName, false);
		}

		HRESULT inheritsFrom(__in LPCWSTR strAncestor)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->InheritsFrom(strAncestor)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		HRESULT getMethod(__in LPCWSTR wszName, __in long lFlags, __out IWbemClassObject** ppInSignature,__out IWbemClassObject** ppOutSignature)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->GetMethod(wszName, lFlags, ppInSignature, ppOutSignature)))
			{
				HR_Exception(hr);
			}
		
			return hr;
		}

		HRESULT putMethod(__in LPCWSTR wszName, __in long lFlags, __in IWbemClassObject* pInSignature, __in IWbemClassObject* pOutSignature)
		{
			HRESULT hr = S_OK;

			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->PutMethod(wszName, lFlags, pInSignature, pOutSignature)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		HRESULT deleteMethod(__in LPCWSTR wszName)
		{
			HRESULT hr = S_OK;
			
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->DeleteMethod(wszName)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		HRESULT beginMethodEnumeration(__in long lEnumFlags)
		{
			HRESULT hr = S_OK;
		
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->BeginMethodEnumeration(lEnumFlags)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		HRESULT nextMethod(__in long lFlags, __out BSTR* pstrName, __out IWbemClassObject** ppInSignature, __out IWbemClassObject** ppOutSignature)
		{
			HRESULT hr = S_OK;
	
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->NextMethod(lFlags, pstrName, ppInSignature, ppOutSignature)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		HRESULT endMethodEnumeration()
		{
			HRESULT hr = S_OK;
	
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->EndMethodEnumeration()))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IWbemQualifierSet* getMethodQualifierSet(__in LPCWSTR wszMethod)
		{
			HRESULT hr = S_OK;

			IWbemQualifierSet* pQualSet = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->GetMethodQualifierSet(wszMethod, &pQualSet)))
			{
				HR_Exception(hr);
			}
			
			return pQualSet;
		}

		_bstr_t getMethodOrigin(__in LPCWSTR wszMethodName)
		{
			HRESULT hr = S_OK;

			BSTR strClassName = NULL;
			IWbemClassObject* classObject = getClassObject();
			if (FAILED(hr = classObject->GetMethodOrigin(wszMethodName, &strClassName)))
			{
				HR_Exception(hr);
			}
			
			return _bstr_t(strClassName, false);
		}
	};
}
