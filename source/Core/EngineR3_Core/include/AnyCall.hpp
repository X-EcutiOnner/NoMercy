#pragma once
#include <any>
#include <map>
#include <functional>

class CAnyCaller
{
protected:
	CAnyCaller() = default;
	~CAnyCaller() = default;

	void add_fn(const uint32_t id, const std::any& fn)
	{
		m_calls[id] = fn;
	}

	template <typename ReturnType>
	ReturnType call_fn(const uint32_t id)
	{
		const auto& a = m_calls[id];
		return std::any_cast<std::function<ReturnType()>>(a)();
	}

	template <typename ReturnType, typename... Args>
	ReturnType call_fn(const uint32_t id, Args&&... arg)
	{
		const auto& a = m_calls[id];
		return std::any_cast<std::function<ReturnType(Args...)>>(a)(std::forward<Args>(arg)...);
	}

private:
	std::map <uint32_t, std::any> m_calls;
};
