#pragma once

namespace NoMercy
{
	static inline bool IsValidPtr(void* ptr)
	{
		return ptr && !IsBadReadPtr(ptr, sizeof(void*));
	}

	template <typename T>
	static inline bool IsValidPtr(T* ptr)
	{
		return ptr && !IsBadReadPtr(reinterpret_cast<void*>(ptr), sizeof(T));
	}

	template <typename T>
	static inline bool IsValidPtr(T ptr)
	{
		return ptr && !IsBadReadPtr(reinterpret_cast<void*>(ptr), sizeof(void*));
	}

	template <typename Type, typename Base, typename Offset>
	static inline Type Ptr(Base base, Offset offset)
	{
		static_assert(std::is_pointer<Type>::value || std::is_integral<Type>::value, "Type must be a pointer or address");
		static_assert(std::is_pointer<Base>::value || std::is_integral<Base>::value, "Base must be a pointer or address");
		static_assert(std::is_pointer<Offset>::value || std::is_integral<Offset>::value, "Offset must be a pointer or address");

		return base ? (Type)((uintptr_t)base + (uintptr_t)offset) : Type();
	}

	enum class PatternType
	{
		None,
		Address,
		Pointer,
		PointerUint8,
		PointerUint16,
		PointerUint32,
		PointerUint64,
		RelativePointer,
		RelativePointerUint8,
		RelativePointerUint16,
		RelativePointerUint32,
		RelativePointerUint64,
		PatternTypeCount
	};

	struct Pattern
	{
		std::wstring pattern;
		PatternType type;

		Pattern(const std::wstring& pattern_, PatternType type_) :
			pattern(pattern_), type(type_)
		{
		}
		Pattern(const std::wstring& pattern_, uint32_t type_) :
			pattern(pattern_), type((PatternType)type_)
		{
		}
	};

	class CPatternScanner
	{
		private:
			template <typename T, typename ret = void*>
			static ret ResolveRelativePtr(void *address)
			{
				if (!address)
					return ret();

				T offset = *reinterpret_cast<T*>(address);
				if (!offset)
					return ret();

				return reinterpret_cast<ret>(Ptr<uintptr_t>(address, offset) + sizeof(T));
			}

			template <typename T, typename ret = void*>
			static ret ResolvePtr(void *address)
			{
				if (!address)
					return ret();

				return reinterpret_cast<ret>(*reinterpret_cast<T *>(address));
			}

			static void* Resolve(void *address, PatternType type);
			static void* FindPattern(void *start, void *end, byte *pattern, char *mask, int offset);
			
		public:
			static void* findPattern(void* startAddress, uint32_t scanRange, const Pattern& pattern);
			static void* findPatternSafe(void* startAddress, uint32_t scanRange, const Pattern& pattern);
	};
};
