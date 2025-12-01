#pragma once
#include "../../../Common/AbstractSingleton.hpp"
#include "../../../Common/Locks.hpp"

namespace NoMercy
{
    class CApcRoutinesStorage : public CSingleton <CApcRoutinesStorage>
    {
    public:
        CApcRoutinesStorage() :
            m_rwLock(), m_usAllowedPtrs(), m_usDeniedPtrs()
        {
        }
        virtual ~CApcRoutinesStorage() = default;

        void AddAllowed(LPCVOID EntryPoint)
        {
            if (EntryPoint)
            {
                m_rwLock.LockExclusive();
                m_usAllowedPtrs.emplace(EntryPoint);
                m_rwLock.UnlockExclusive();
            }
        }

        void AddDenied(LPCVOID EntryPoint)
        {
            if (EntryPoint)
            {
                m_rwLock.LockExclusive();
                m_usDeniedPtrs.emplace(EntryPoint);
                m_rwLock.UnlockExclusive();
            }
        }

        void Clear()
        {
            m_rwLock.LockExclusive();
            m_usAllowedPtrs.clear();
            m_usDeniedPtrs.clear();
            m_rwLock.UnlockExclusive();
        }

        bool IsAllowed(LPCVOID EntryPoint)
        {
            m_rwLock.LockShared();
            const auto Exists = m_usAllowedPtrs.find(EntryPoint) != m_usAllowedPtrs.end();
            m_rwLock.UnlockShared();

            return Exists;
        }

        bool IsDenied(LPCVOID EntryPoint)
        {
            m_rwLock.LockShared();
            const auto Exists = m_usDeniedPtrs.find(EntryPoint) != m_usDeniedPtrs.end();
            m_rwLock.UnlockShared();

            return Exists;
        }

    private:
        mutable CRWLock m_rwLock;

        std::unordered_set <LPCVOID> m_usAllowedPtrs;
        std::unordered_set <LPCVOID> m_usDeniedPtrs;
    };
}
