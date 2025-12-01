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
 *  ComThreadModel.h
 *
 *****************************************************************************/

#pragma once

#include "Object.hpp"
#include "Exception.hpp"

namespace SOL
{
	class ComThreadModel : public Object
	{
	public:
		ComThreadModel(DWORD threadModel, bool initializeCom, bool setDefaultSecurity = true)
		{
			HRESULT hr = E_FAIL;

			if (initializeCom)
			{
				if (FAILED(hr = NoMercyCore::g_winAPIs->CoInitializeEx(NULL, threadModel)) && hr != RPC_E_CHANGED_MODE)
				{
					HR_Exception(hr);
				}

				if (setDefaultSecurity)
				{
					try {
						setDefaultSecurityLevels();
					} catch (...) {
						;//
					}
				}
			}
		}
		~ComThreadModel()
		{
			NoMercyCore::g_winAPIs->CoUninitialize();
		}

		// Set Default COM security levels with default authentication and Impersonation.
		void setDefaultSecurityLevels()
		{
			HRESULT hr = S_OK;

			if (FAILED(hr = NoMercyCore::g_winAPIs->CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL)))
			{
				if (hr != RPC_E_TOO_LATE) // just ignore
				{
					HR_Exception(hr);
				}
			}
		}
	};
}
