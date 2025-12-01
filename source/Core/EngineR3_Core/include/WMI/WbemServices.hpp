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
 *  WbemServices.h
 *
 *****************************************************************************/

#pragma once

#include <objbase.h>
#include <wbemidl.h>
#include <wbemdisp.h>
#include "ComIUnknown.hpp"

namespace SOL
{
	class WbemServices : public ComIUnknown
	{
	public:
		WbemServices(IWbemServices* services) :
			ComIUnknown(services), m_strQueryLanguage(L"WQL")
		{
		}
		~WbemServices()
		{
		}

		operator IWbemServices* ()
		{
			return getServices();
		}

		IWbemServices* getServices()
		{
			return (IWbemServices*)getIUnknown();
		}


		HRESULT openNamespace(__in const BSTR strNamespace, __in long lFlags, __in IWbemContext* pCtx,
			__out IWbemServices** ppWorkingNamespace, __out IWbemCallResult** ppResult)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->OpenNamespace(strNamespace, lFlags, pCtx, ppWorkingNamespace, ppResult)))
			{
				HR_Exception(hr);
			}

			return hr;
		}

		HRESULT cancelAsyncCall(__in IWbemObjectSink* pSink)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->CancelAsyncCall(pSink)))
			{
				HR_Exception(hr);
			}

			return hr;
		}

		IWbemObjectSink* queryObjectSink(__in long lFlags)
		{
			HRESULT hr = S_OK;

			IWbemObjectSink* pResponseHandler = NULL;
			IWbemServices* services = getServices();
			if (FAILED(hr = services->QueryObjectSink(lFlags, &pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return pResponseHandler;
		}

		HRESULT getObject(__in const BSTR strObjectPath, __in long lFlags, __in IWbemContext* pCtx,
			__out IWbemClassObject** ppObject, __out IWbemCallResult** ppCallResult)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->GetObject(strObjectPath, lFlags, pCtx, ppObject, ppCallResult)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		HRESULT getObjectAsync(__in const BSTR strObjectPath, __in long lFlags, __in IWbemContext* pCtx,
			__in IWbemObjectSink* pResponseHandler)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->GetObjectAsync(strObjectPath, lFlags, pCtx, pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IWbemCallResult* putClass(__in IWbemClassObject* pObject, __in long lFlags, __in IWbemContext* pCtx)
		{
			HRESULT hr = S_OK;

			IWbemCallResult* pCallResult = NULL;
			IWbemServices* services = getServices();
			if (FAILED(hr = services->PutClass(pObject, lFlags, pCtx, &pCallResult)))
			{
				HR_Exception(hr);
			}
			
			return pCallResult;
		}

		HRESULT putClassAsync(__in IWbemClassObject* pObject, __in long lFlags, __in IWbemContext* pCtx,
			__in IWbemObjectSink* pResponseHandler)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->PutClassAsync(pObject, lFlags, pCtx, pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IWbemCallResult* deleteClass(__in const BSTR strClass, __in long lFlags, __in IWbemContext* pCtx)
		{
			HRESULT hr = S_OK;

			IWbemCallResult* pCallResult = NULL;
			IWbemServices* services = getServices();
			if (FAILED(hr = services->DeleteClass(strClass, lFlags, pCtx, &pCallResult)))
			{
				HR_Exception(hr);
			}
			
			return pCallResult;
		}

		HRESULT deleteClassAsync(__in const BSTR strClass, __in long lFlags, __in IWbemContext* pCtx,
			__in IWbemObjectSink* pResponseHandler)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->DeleteClassAsync(strClass, lFlags, pCtx, pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IEnumWbemClassObject* createClassEnum(__in const BSTR strSuperclass, __in long lFlags, __in IWbemContext* pCtx)
		{
			HRESULT hr = S_OK;

			IEnumWbemClassObject* pEnum = NULL;
			IWbemServices* services = getServices();
			if (FAILED(hr = services->CreateClassEnum(strSuperclass, lFlags, pCtx, &pEnum)))
			{
				HR_Exception(hr);
			}
			
			return pEnum;
		}

		HRESULT createClassEnumAsync(__in const BSTR strSuperclass, __in long lFlags, __in IWbemContext* pCtx, __in IWbemObjectSink* pResponseHandler)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->CreateClassEnumAsync(strSuperclass, lFlags, pCtx, pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IWbemCallResult* putInstance(__in IWbemClassObject* pInst, __in long lFlags, __in IWbemContext* pCtx)
		{
			HRESULT hr = S_OK;

			IWbemCallResult* pCallResult = NULL;
			IWbemServices* services = getServices();
			if (FAILED(hr = services->PutInstance(pInst, lFlags, pCtx, &pCallResult)))
			{
				HR_Exception(hr);
			}
			
			return pCallResult;
		}

		HRESULT putInstanceAsync(__in IWbemClassObject* pInst, __in long lFlags, __in IWbemContext* pCtx, __in IWbemObjectSink* pResponseHandler)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->PutInstanceAsync(pInst, lFlags, pCtx, pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IWbemCallResult* deleteInstance(__in const BSTR strObjectPath, __in long lFlags, __in IWbemContext* pCtx)
		{
			HRESULT hr = S_OK;

			IWbemCallResult* pCallResult = NULL;
			IWbemServices* services = getServices();
			if (FAILED(hr = services->DeleteInstance(strObjectPath, lFlags, pCtx, &pCallResult)))
			{
				HR_Exception(hr);
			}
			
			return pCallResult;
		}

		HRESULT deleteInstanceAsync(__in const BSTR strObjectPath, __in long lFlags, __in IWbemContext* pCtx, __in IWbemObjectSink* pResponseHandler)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->DeleteInstanceAsync(strObjectPath, lFlags, pCtx, pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IEnumWbemClassObject* createInstanceEnum(__in const BSTR strFilter, __in long lFlags, __in IWbemContext* pCtx)
		{
			HRESULT hr = S_OK;

			IEnumWbemClassObject* pEnum = NULL;
			IWbemServices* services = getServices();
			if (FAILED(hr = services->CreateInstanceEnum(strFilter, lFlags, pCtx, &pEnum)))
			{
				HR_Exception(hr);
			}
		
			return pEnum;
		}

		HRESULT createInstanceEnumAsync(__in const BSTR strFilter, __in long lFlags, __in IWbemContext* pCtx, __in IWbemObjectSink* pResponseHandler)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->CreateInstanceEnumAsync(strFilter, lFlags, pCtx, pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IEnumWbemClassObject* execQuery(__in const BSTR strQuery, __in long lFlags = WBEM_FLAG_FORWARD_ONLY, __in IWbemContext* pCtx = nullptr)
		{
			HRESULT hr = S_OK;

			IEnumWbemClassObject* pEnum = NULL;
			IWbemServices* services = getServices();
			if (FAILED(hr = services->ExecQuery(this->m_strQueryLanguage, strQuery, lFlags, pCtx, &pEnum)))
			{
				HR_Exception(hr);
			}
			
			return pEnum;
		}

		HRESULT execQueryAsync(__in const BSTR strQuery, __in IWbemObjectSink* pResponseHandler, __in long lFlags = WBEM_FLAG_BIDIRECTIONAL,
			__in IWbemContext* pCtx = NULL)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->ExecQueryAsync(this->m_strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		IEnumWbemClassObject* execNotificationQuery(__in const BSTR strQuery,
			__in long lFlags = WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, __in IWbemContext* pCtx = NULL)
		{
			HRESULT hr = S_OK;

			IEnumWbemClassObject* pEnum = NULL;
			IWbemServices* services = getServices();
			if (FAILED(hr = services->ExecNotificationQuery(this->m_strQueryLanguage, strQuery, lFlags, pCtx, &pEnum)))
			{
				HR_Exception(hr);
			}
			
			return pEnum;
		}

		HRESULT execNotificationQueryAsync(__in const BSTR strQuery, __in IWbemObjectSink* pResponseHandler,
			__in long lFlags = WBEM_FLAG_SEND_STATUS, __in IWbemContext* pCtx = NULL)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->ExecNotificationQueryAsync(this->m_strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler)))
			{
				HR_Exception(hr);
			}
			
			return hr;
		}

		HRESULT execMethod(__in const BSTR strObjectPath, __in const BSTR strMethodName, __in long lFlags, __in IWbemContext* pCtx,
			__in IWbemClassObject* pInParams, __out IWbemClassObject** ppOutParams, __out IWbemCallResult** ppCallResult)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->ExecMethod(strObjectPath, strMethodName, lFlags, pCtx, pInParams, ppOutParams, ppCallResult)))
			{
				HR_Exception(hr);
			}

			return hr;
		}

		HRESULT execMethodAsync(__in const BSTR strObjectPath, __in const BSTR strMethodName, __in long lFlags, __in IWbemContext* pCtx,
			__in IWbemClassObject* pInParams, __in IWbemObjectSink* pResponseHandler)
		{
			HRESULT hr = S_OK;

			IWbemServices* services = getServices();
			if (FAILED(hr = services->ExecMethodAsync(strObjectPath, strMethodName, lFlags, pCtx, pInParams, pResponseHandler)))
			{
				HR_Exception(hr);
			}

			return hr;
		}

	private:
		BSTR m_strQueryLanguage;
	};
}
