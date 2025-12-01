#pragma once

namespace NoMercy
{
	enum EMBRParts
	{
		PART_EMPTY = 0,
		PART_GPT = 0xEE,
		PART_HYBRID_GPT = 0xED
	};
	static const uint8_t g_partitionBootableValue = 0x80;

	class MBRPartition
	{
	public:
		MBRPartition() :
			m_num(0)
		{
		}
		MBRPartition(const std::vector<uint8_t>& m_bytes, int m_num) :
			m_bytes(m_bytes), m_num(m_num)
		{
		}

		std::vector <uint8_t> GetBytes() const
		{
			return m_bytes;
		}

		uint32_t GetLBAStart() const
		{
			return __ReadLittleEndianUINT32(m_bytes.data() + 8);
		}
		uint32_t GetLBALen() const
		{
			return __ReadLittleEndianUINT32(m_bytes.data() + 12);
		}
		uint32_t GetLBALast() const
		{
			const auto last = static_cast<uint64_t>(GetLBAStart()) + static_cast<uint64_t>(GetLBALen()) - 1;
			
			if (last > std::numeric_limits<uint32_t>::max())
				throw std::runtime_error(xorstr_("Overflow while calculating last sector. Max sector number in MBR must be less than or equal to 0xFFFFFFFF"));

			return static_cast<uint32_t>(last);
		}

		uint8_t GetType() const
		{
			return m_bytes[4];
		}
		void SetType(uint8_t t)
		{
			m_bytes[4] = t;
		}

		bool IsEmpty() const
		{
			return GetType() == PART_EMPTY;
		}
		bool IsBootable() const
		{
			return m_bytes[0] == g_partitionBootableValue;
		}

	protected:
		uint32_t __ReadLittleEndianUINT32(const uint8_t* buf) const
		{
			return static_cast<uint32_t>(buf[0]) +
				  (static_cast<uint32_t>(buf[1]) << 8) +
				  (static_cast<uint32_t>(buf[2]) << 16) +
				  (static_cast<uint32_t>(buf[3]) << 24);
		}

	private:
		std::vector <uint8_t> m_bytes;
		int m_num;
	};

	class MBR
	{
		const int mbrSignOffset = 510;
		const int mbrFirstPartEntryOffset = 446;
		const int mbrPartEntrySize = 16;
		const int mbrSize = 512;
		const int partitionNumFirst = 1;
		const int partitionNumLast = 4;
		const uint8_t partitionNonBootableValue = 0;
		
	public:
		MBR()
		{
			m_bytes.resize(mbrSize);
		}

		void Read(std::istream& disk)
		{
			disk.read(reinterpret_cast<char*>(m_bytes.data()), mbrSize);
			if (!disk)
				throw std::runtime_error(xorstr_("Failed to read MBR"));
			
			Check();
		}

		void Check() const
		{
			// Check signature
			if (m_bytes[mbrSignOffset] != 0x55 || m_bytes[mbrSignOffset + 1] != 0xAA) {
				throw std::runtime_error(xorstr_("MBR: Bad signature"));
			}

			// Check partitions
			for (int l = partitionNumFirst; l <= partitionNumLast; l++)
			{
				MBRPartition lp = GetPartition(l);
				if (lp.IsEmpty())
					continue;

				// Check if partition last sector out of uint32 bounds
				uint64_t endSector = static_cast<uint64_t>(lp.GetLBAStart()) + static_cast<uint64_t>(lp.GetLBALen()) - 1;
				if (endSector > 0xFFFFFFFF)
					throw std::runtime_error(xorstr_("MBR: Last sector has a very high number"));

				// Check partition bootable status
				uint8_t bootFlag = lp.GetBytes()[0];
				if (bootFlag != g_partitionBootableValue && bootFlag != partitionNonBootableValue)
					throw std::runtime_error(xorstr_("MBR: Bad value in boot flag"));

				// Check if partitions have intersections
				for (int r = partitionNumFirst; r <= partitionNumLast; r++)
				{
					if (l == r)
						continue;
					MBRPartition rp = GetPartition(r);
					if (rp.IsEmpty())
						continue;

					if (lp.GetLBAStart() > rp.GetLBAStart() &&
						static_cast<uint64_t>(lp.GetLBAStart()) < static_cast<uint64_t>(rp.GetLBAStart()) + static_cast<uint64_t>(rp.GetLBALen()))
					{
						throw std::runtime_error(xorstr_("MBR: Partitions have intersections"));
					}
				}
			}
		}

		void FixSignature()
		{
			m_bytes[mbrSignOffset] = 0x55;
			m_bytes[mbrSignOffset + 1] = 0xAA;
		}

		void Write(std::ostream& disk) const
		{
			disk.write(reinterpret_cast<const char*>(m_bytes.data()), mbrSize);
			if (!disk)
				throw std::runtime_error(xorstr_("Failed to write MBR"));
		}

		MBRPartition GetPartition(int num) const
		{
			if (num < partitionNumFirst || num > partitionNumLast)
				return MBRPartition();

			int partStart = mbrFirstPartEntryOffset + (num - 1) * mbrPartEntrySize;
			std::vector <uint8_t> partBytes(m_bytes.begin() + partStart, m_bytes.begin() + partStart + mbrPartEntrySize);
			return MBRPartition(partBytes, num);
		}
		std::vector <MBRPartition> GetAllPartitions() const
		{
			std::vector <MBRPartition> res;
			for (auto i = 0; i < 4; i++)
				res.push_back(GetPartition(i + 1));
			
			return res;
		}

		bool IsGPT() const
		{
			for (const MBRPartition& part : GetAllPartitions())
			{
				if (part.GetType() == PART_GPT || part.GetType() == PART_HYBRID_GPT)
					return true;
			}
			return false;
		}
		
	private:
		std::vector <uint8_t> m_bytes;
	};
}
