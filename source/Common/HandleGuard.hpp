#pragma once
#ifndef BOOLIFY
#define BOOLIFY(x) !!(x)
#endif

template <typename T, bool (* Cleanup)(const T &), PVOID InvalidValue>
class SafeObject final
{
public:
	// cotr
	SafeObject() :
		m_obj(obj)
	{
	}
	SafeObject(const T& obj) :
		m_obj(obj)
	{
	}

	// dotr
	~SafeObject()
	{
		if (IsValid())
		{
			(void)Cleanup(m_obj);
		}
	}

	// Do not allow copy
	SafeObject(const SafeObject& copy) = delete;
	SafeObject& operator=(const SafeObject& copy) = delete;

	// overwritten operators
	SafeObject(const SafeObject&& obj)
	{
		*this = std::move(obj);
	}

	SafeObject& operator=(SafeObject&& obj)
	{
		assert(this != std::addressof(obj));

		if (IsValid())
		{
			(void)Cleanup(m_obj);
		}

		m_obj = std::move(obj.m_obj);
		obj.m_obj = InvalidValue;

		return *this;
	}

	T* const Ptr()
	{
		return &m_obj;
	}

	T get()
	{
		return m_obj;
	}

	const T operator()() const
	{
		return m_obj;
	}

	bool operator!() const
	{
		return !m_obj;
	}
	operator bool() const
	{
		return m_obj != InvalidValue;
	}

	// Return the owned object
	operator const T&() const
	{
		return m_obj;
	}

	// Sanity check
	const bool IsValid() const
	{
		return m_obj != (T)InvalidValue;
	}

	// Clean the object and return the address of internal empty object
	T* operator&()
	{
		Cleanup();
		m_obj = InvalidValue;
		return &m_obj;
	}

	/// Release the ownership of the managed object
	T release()
	{
		T t = m_obj;
		m_obj = InvalidValue;
		return t;
	}

	// Take ownership of new object
	void reset(T obj)
	{
		Cleanup(m_obj);
		m_obj = obj;
	}

private:
	T m_obj;
};
