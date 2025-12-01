#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "Access.hpp"

namespace NoMercy
{
	bool CAccess::SetMitigationPolicys()
	{
		APP_TRACE_LOG(LL_SYS, L"Set Mitigation Policy event has been started!");

		if (!IsWindows8OrGreater())
			return true;

		PROCESS_MITIGATION_DEP_POLICY depPolicy = { 0 }; // 8
		depPolicy.Enable = 1;
		depPolicy.Permanent = TRUE;
		depPolicy.DisableAtlThunkEmulation = TRUE;
		BOOL bDepPolicyRet = g_winAPIs->SetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy, sizeof(depPolicy));
		if (bDepPolicyRet) {
			APP_TRACE_LOG(LL_SYS, L"Dep Mitigation policy succesfully enabled!");
		} else {
			APP_TRACE_LOG(LL_ERR, L"Dep Mitigation policy can NOT Enabled! Last err: %u", g_winAPIs->GetLastError());
		}

		PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = { 0 }; // 8
		aslrPolicy.EnableForceRelocateImages = 1;
		aslrPolicy.DisallowStrippedImages = 1;
//		aslrPolicy.EnableBottomUpRandomization = true;
//		aslrPolicy.EnableHighEntropy = true;
    
		BOOL bAslrPolicyRet = g_winAPIs->SetProcessMitigationPolicy(ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy));
		if (bAslrPolicyRet) {
			APP_TRACE_LOG(LL_SYS, L"ASLR Mitigation policy succesfully enabled!");
		} else {
			APP_TRACE_LOG(LL_ERR, L"ASLR Mitigation policy can NOT Enabled! Last err: %u", g_winAPIs->GetLastError());
		}

		PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPolicy = { 0 }; // 8
		extensionPolicy.DisableExtensionPoints = 1;
		BOOL bExtensionPolicyRet = g_winAPIs->SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &extensionPolicy, sizeof(extensionPolicy));
		if (bExtensionPolicyRet) {
			APP_TRACE_LOG(LL_SYS, L"Extension Point Mitigation policy succesfully enabled!");
		} else {
			APP_TRACE_LOG(LL_ERR, L"Extension Point Mitigation policy can NOT Enabled! Last err: %u", g_winAPIs->GetLastError());
		}

/*
		// if (IsWindows8Point1OrGreater())
		{
			PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = { 0 }; // 8.1
			cfgPolicy.EnableControlFlowGuard = 1;
			cfgPolicy.EnableExportSuppression = 1;
			BOOL bCfgPolicyRet = g_winAPIs->SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy));
			if (bCfgPolicyRet) {
				APP_TRACE_LOG(LL_SYS, L"CFG Mitigation policy succesfully enabled!");
			} else {
				APP_TRACE_LOG(LL_ERR, L"CFG Mitigation policy can NOT Enabled! Last err: %u", g_winAPIs->GetLastError());
			}
		}
		*/

		// if (IsWindows10OrGreater()) // 10
		{
			PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy = { 0 };
			imageLoadPolicy.NoLowMandatoryLabelImages = 1;
			imageLoadPolicy.NoRemoteImages = 1;
			imageLoadPolicy.PreferSystem32Images = 1;
			BOOL bImageLoadPolicyRet = g_winAPIs->SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy));
			if (bImageLoadPolicyRet) {
				APP_TRACE_LOG(LL_SYS, L"Image Load Mitigation policy succesfully enabled!");
			} else {
				APP_TRACE_LOG(LL_ERR, L"Image Load Mitigation policy can NOT Enabled! Last err: %u", g_winAPIs->GetLastError());
			}

			/*
			PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = { 0 };
			signaturePolicy.MicrosoftSignedOnly = 1;
			BOOL bSignaturePolicyRet = g_winAPIs->SetProcessMitigationPolicy(ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy));
			if (bSignaturePolicyRet) {
				APP_TRACE_LOG(LL_SYS, L"Binary Signature Mitigation policy succesfully enabled!");
			} else {
				APP_TRACE_LOG(LL_ERR, L"Binary Signature Mitigation policy can NOT Enabled! Last err: %u", g_winAPIs->GetLastError());
			}
			*/

			PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY payloadPolicy = { 0 };
			payloadPolicy.EnableExportAddressFilter = 1;
			payloadPolicy.EnableImportAddressFilter = 1;
			payloadPolicy.EnableRopStackPivot = 1;
			payloadPolicy.EnableRopCallerCheck = 1;
			BOOL bPayloadPolicyRet = g_winAPIs->SetProcessMitigationPolicy(ProcessPayloadRestrictionPolicy, &payloadPolicy, sizeof(payloadPolicy));
			if (bPayloadPolicyRet) {
				APP_TRACE_LOG(LL_SYS, L"Payload restriction Mitigation policy succesfully enabled!");
			} else {
				APP_TRACE_LOG(LL_ERR, L"Payload restriction Mitigation policy can NOT Enabled! Last err: %u", g_winAPIs->GetLastError());
			}

			// FIXME: CEF spawn
			/*
			PROCESS_MITIGATION_CHILD_PROCESS_POLICY childProcPolicy = { 0 };
			childProcPolicy.NoChildProcessCreation = 1;
			BOOL bChildPolicyRet = g_winAPIs->SetProcessMitigationPolicy(ProcessChildProcessPolicy, &childProcPolicy, sizeof(childProcPolicy));
			if (bChildPolicyRet) {
				APP_TRACE_LOG(LL_SYS, L"Child process Mitigation policy succesfully enabled!");
			} else {
				APP_TRACE_LOG(LL_ERR, L"Child process Mitigation policy can NOT Enabled! Last err: %u", g_winAPIs->GetLastError());
			}
			*/


			// FIXME
			// VirtualProtect (1) failed for: C:\Windows\System32\KERNELBASE.dll:LoadStringW with error: 1655
			// Processing cheat db node failed. Exception: VirtualAlloc failed to allocate memory for call_function shellcode: The operation was blocked as the process prohibits dynamic code generation.
			/*
			// STATUS_DYNAMIC_CODE_BLOCKED
			PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic_code{};
			dynamic_code.ProhibitDynamicCode = true;
			if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamic_code, sizeof(dynamic_code))) {
				APP_TRACE_LOG(LL_ERR, L"Dynamic code Mitigation policy can NOT Enabled! Last err: %u", g_winAPIs->GetLastError());
			} else {
				APP_TRACE_LOG(LL_SYS, L"Dynamic code Mitigation policy succesfully enabled!");
			}
			*/
		}

		APP_TRACE_LOG(LL_SYS, L"Set Mitigation Policy event completed!");
		return true;
	}
};
