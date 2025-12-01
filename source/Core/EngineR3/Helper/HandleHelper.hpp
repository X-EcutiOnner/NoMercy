#pragma once
#undef GetObject

namespace NoMercy
{
	class CProcess;

	class CHandle
	{
	public:
		CHandle();
		CHandle(CProcess* Process, HANDLE hHandle, PVOID pObject, USHORT uTypeIndex, DWORD dwGrantedAccess);
		~CHandle();

		// moveable
		CHandle(CHandle&& other) noexcept;
		CHandle& operator=(CHandle&& other) noexcept;

		explicit operator bool() noexcept;

		bool IsValid() const;
		HANDLE GetHandle() const;
		PVOID GetObject() const;
		USHORT GetTypeIndex() const;
		DWORD GetGrantedAccess() const;

	private:
		CProcess* m_pOwnerProcess;
		HANDLE m_hHandle;
		PVOID m_pObject;
		USHORT m_uTypeIndex;
		DWORD m_dwGrantedAccess;
		bool m_bIsValid;
	};
}
