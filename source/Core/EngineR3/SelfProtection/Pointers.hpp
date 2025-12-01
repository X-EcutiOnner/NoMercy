#pragma once
#include <random>
#include <cstdint>
#include <limits>
#include <chrono>
#include <lazy_importer.hpp>
#include "../../EngineR3_Core/include/MiniDump.hpp"



namespace NoMercy
{
#pragma warning(push) 
#pragma warning(disable: 4003)
    template <typename T, typename = std::enable_if_t<std::is_scalar_v<T>>>
    struct DefaultKeyGenerator
    {
        T operator()() const
        {
            static std::default_random_engine generator(static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()));
            static std::uniform_int_distribution<int> distribution(std::numeric_limits<T>::min(), std::numeric_limits<T>::max());

            T key = distribution(generator);
            if (reinterpret_cast<uintptr_t>(&key) % 2 == 0)
                key += 1;

            return static_cast<uint8_t>(key);
        }
    };
#pragma warning(pop)

    template <typename Generator = DefaultKeyGenerator<uint8_t>>
    struct XOREncryptionImpl
    {
        XOREncryptionImpl() : m_key(Generator()()) {}

        void Encrypt(uint8_t* dest, uint8_t* src, size_t size) const
        {
            for (size_t i = 0; i < size; i++)
            {
                dest[i] = src[i] ^ getKey();
                m_key = ~m_key;
            }
        }

        void Decrypt(uint8_t* dest, uint8_t* src, size_t size) const
        {
            for (size_t i = 0; i < size; i++)
            {
                dest[i] = src[i] ^ getKey();
                m_key = ~m_key;
            }
        }

        uint8_t getKey() const
        {
            return const_cast<XOREncryptionImpl*>(this)->m_key;
        }

        mutable uint8_t m_key;
    };

    using DefaultEncryptionImpl = XOREncryptionImpl<>;

    template <typename T, typename Encryption = DefaultEncryptionImpl, typename = std::enable_if_t<std::is_scalar_v<T>>>
    struct EncryptedVariable
    {
        EncryptedVariable() : m_value(T()) {}

        EncryptedVariable(const T& value)
        {
            set(value);
        }

        EncryptedVariable(const EncryptedVariable<T>& copy)
        {
            set(copy.get());
        }

        EncryptedVariable(EncryptedVariable<T>&& move)
        {
            set(move.get());
        }

        EncryptedVariable<T>& operator=(const EncryptedVariable<T>& other)
        {
            EncryptedVariable<T> temp(other);

            set(temp.get());

            return *this;
        }

        EncryptedVariable<T>& operator=(const T& value)
        {
            set(value);
            return *this;
        }

        EncryptedVariable<T>& operator=(EncryptedVariable<T>&& other)
        {
            set(other.get());

            return *this;
        }

        operator T() const
        {
            return get();
        }

        void set(const T& value)
        {
            T copy(value);

            uint8_t* ptr = reinterpret_cast<uint8_t*>(&copy);
            uint8_t* local = reinterpret_cast<uint8_t*>(&m_value);

            m_impl.Encrypt(local, ptr, sizeof(T));
            obfuscateData(local, sizeof(T));
        }

        T get() const
        {
            T copy;

            uint8_t* ptr = reinterpret_cast<uint8_t*>(&copy);
            uint8_t* local = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(&m_value));

            obfuscateData(local, sizeof(T));
            m_impl.Decrypt(ptr, local, sizeof(T));
            return copy;
        }

    private:
        void obfuscateData(uint8_t* data, size_t size) const
        {
            for (size_t i = 0; i < size; i++)
            {
                if (i % 2 == 0)
                    data[i] = ~data[i];
            }
        }

        T m_value;
        Encryption m_impl;
    };
}
