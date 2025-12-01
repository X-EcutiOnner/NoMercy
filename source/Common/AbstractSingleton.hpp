#pragma once
#include <typeinfo>
#include <cassert>
#include <memory>
#include <xorstr.hpp>
#include "Locks.hpp"
#include "StdExtended.hpp"

// Prevent the compiler from automatically providing implementations of various class features
#ifndef NM_NO_COPY_CTOR
#define NM_NO_COPY_CTOR(type) type(const type &) = delete
#define NM_NO_COPY_ASSIGNMENT(type) type &operator=(const type &) = delete
#define NM_NO_DEFAULT_CTOR(type) type() = delete
#define NM_NO_COPY_CTOR_AND_ASSIGNMENT(type)                                                                          \
	NM_NO_COPY_CTOR(type);                                                                                            \
	NM_NO_COPY_ASSIGNMENT(type)
#endif

template <typename T> 
class CSingleton
{
	static T* ms_singleton;

public:
	CSingleton()
	{
		if (ms_singleton)
		{
			MessageBoxA(nullptr, typeid(T).name(), xorstr_("CSingleton() DECLARED MORE THAN ONCE"), MB_ICONEXCLAMATION | MB_OK);
			
#ifdef _DEBUG
			if (IsDebuggerPresent())
				__debugbreak();
#endif
			
			std::abort();
		}

		m_lock = stdext::make_unique_nothrow<CCSLock>();
		assert(m_lock);

		ms_singleton = static_cast<T*>(this);
	}
	virtual ~CSingleton()
	{
		if (!ms_singleton)
		{
			MessageBoxA(nullptr, typeid(T).name(), xorstr_("~CSingleton() FREED AT RUNTIME"), MB_ICONEXCLAMATION | MB_OK);
			
#ifdef _DEBUG
			if (IsDebuggerPresent())
				__debugbreak();
#endif
			
			std::abort();
		}

		ms_singleton = nullptr;
	}

	NM_NO_COPY_CTOR(CSingleton);

	static T& Instance()
	{
		if (!ms_singleton)
		{
			MessageBoxA(nullptr, typeid(T).name(), xorstr_("CSingleton::Instance() NEVER DECLARED"), MB_ICONEXCLAMATION | MB_OK);
			
#ifdef _DEBUG
			if (IsDebuggerPresent())
				__debugbreak();
#endif
	
			std::abort();
		}

		return (*ms_singleton);
	}
	static T* InstancePtr()
	{
		return (ms_singleton);
	}

	virtual void Lock()
	{
		if (m_lock)
			m_lock->Lock();
	}
	virtual void Unlock()
	{
		if (m_lock)
			m_lock->Unlock();
	}

private:
	std::unique_ptr <CCSLock> m_lock;
};

template <typename T>
T * CSingleton<T>::ms_singleton = nullptr;
