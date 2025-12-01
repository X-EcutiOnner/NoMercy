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
 *  COMTypeConverterr.h
 *
 *****************************************************************************/

#pragma once

#include "Object.hpp"

namespace SOL
{
	class COMTypeConverter : public Object
	{
	public:
		COMTypeConverter()
		{
		}

		/*
		 * Convery a variant(_variant_t) to a string(_bstr_t)
		 * by using ChangeType(VT_BSTR) method of _variant_t
		 */
		_bstr_t toString(__in _variant_t& variant)
		{
			if (variant.vt == VT_NULL)
				return _bstr_t("");
			
			variant.ChangeType(VT_BSTR);
			return (_bstr_t)variant;
		}

		/*
		 * Convery a variant(_variant_t) to a string(_bstr_t)
		 * by using ChangeType(VT_BSTR) method of _variant_t
		 */
		bool toString(__in _variant_t& variant, __out _bstr_t& string, __in_opt const _bstr_t& NULLExpr = "")
		{
			bool rc = false;

			string = "";

			if (variant.vt == VT_NULL)
			{
				string = NULLExpr;
			}
			else
			{
				try
				{
					variant.ChangeType(VT_BSTR);
					string = (_bstr_t)variant;
					rc = true;
				}
				catch (...)
				{
					// printf("Maybe converion failed\n"); Ignore this IException
				}
			}

			return rc;
		}

		/*
		 * Convery a string(_bstr_t) to a _variant_t datetime
		 * by using ChangeType(VT_DATE) method of _variant_t
		 */
		bool toDateTime(__in _bstr_t& string, __out _variant_t& datetime)
		{
			bool rc = false;
			_variant_t variant = string;

			try
			{
				variant.ChangeType(VT_DATE);
				datetime = variant;
				rc = true;
			}
			catch (...)
			{
				// printf("Maybe converion failed\n"); Ignore this IException
			}
			return rc;
		}

		/*
		 * Convery a st(SYSTEMTIME) to a _variant_t datetime
		 * by using Win32 API SystemTimeToVariantTime().
		 */
		bool toDateTime(__in SYSTEMTIME& st, __out _variant_t& datetime)
		{
			bool rc = false;

			VARIANT var;
			VariantInit(&var);
			var.vt = VT_DATE;

			if (SystemTimeToVariantTime(&st, &var.date))
			{
				datetime = var;
				rc = true;
			}

			return rc;
		}
	};
}
