#include "../../include/PCH.hpp"
#include "../../include/disassembler.hpp"

namespace NoMercyCore
{
	disassembler::disassembler(ZydisMachineMode mode) :
		m_mode(mode)
	{
		ZydisFormatterInit(&this->m_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		ZydisFormatterSetProperty(&this->m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
		ZydisFormatterSetProperty(&this->m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
		
		if (mode == ZYDIS_MACHINE_MODE_LONG_64)
			ZydisDecoderInit(&this->m_decoder, mode, ZYDIS_STACK_WIDTH_64);
		else if (mode == ZYDIS_MACHINE_MODE_LONG_COMPAT_32)
			ZydisDecoderInit(&this->m_decoder, mode, ZYDIS_STACK_WIDTH_32);
		else
			throw(xorstr_("invalid machine mode"));
	}
	disassembler::~disassembler()
	{
	}

	std::tuple< ZyanStatus, ZydisDecodedInstruction*, ZydisDecodedOperand*> disassembler::disassemble_instruction(void* instruction_address, std::uint32_t instruction_length)
	{
		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
		ZyanStatus status = ZydisDecoderDecodeFull(&this->m_decoder, instruction_address, instruction_length, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);

		return { status, &instruction, operands };
	}

	ZyanU64 disassembler::get_instruction_absolute_address(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands, ZyanU64 runtime_address)
	{
		auto destination = 0ULL;

		for (std::size_t i = 0; i < instruction.operand_count; i++)
		{
			if ((operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative == TRUE) || operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
			{
				ZydisCalcAbsoluteAddress(&instruction, &operands[i], runtime_address, &destination);
				break;
			}

			if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative == FALSE)
			{
				destination = operands[i].imm.value.u;
				break;
			}
		}

		return destination;
	}

	std::uint32_t disassembler::get_mnemonic(void* address)
	{
		const auto& [status, instruction, operands] = disassemble_instruction(address, 16);

		if (ZYAN_SUCCESS(status))
		{
			return instruction->mnemonic;
		}

		return 0;
	}

	std::size_t disassembler::get_size(void* address)
	{
		const auto& [status, instruction, operands] = disassemble_instruction(address, 16);

		if (ZYAN_SUCCESS(status))
		{
			return instruction->length;
		}

		return 0;
	}

	ZydisRegister disassembler::get_instruction_register(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands)
	{
		for (std::size_t i = 0; i < instruction.operand_count; i++)
		{
			if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER)
			{
				return operands[i].reg.value;
			}
		}

		return ZYDIS_REGISTER_NONE;
	}

	std::string disassembler::format_instruction(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands, ZyanU64 runtime_address)
	{
		char buffer[256]{ '\0' };
		ZydisFormatterFormatInstruction(&this->m_formatter, &instruction, operands, instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);

		return buffer;
	}


	std::vector <std::wstring> disassembler::disassemble(void* address, size_t bytes_length)
	{
		std::vector <std::wstring> disassembled_instructions;

		ZyanU64 runtime_address = 0;
		ZyanUSize offset = 0;

		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&this->m_decoder, reinterpret_cast<ZyanU8*>(address) + offset, bytes_length - offset, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
		{
			char buffer[256]{ '\0' };
			ZydisFormatterFormatInstruction(&this->m_formatter, &instruction, operands, instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);

			disassembled_instructions.push_back(stdext::to_wide(buffer));

			offset += instruction.length;
			runtime_address += instruction.length;
		}

		return disassembled_instructions;
	}

	void disassembler::disassemble_buffer(std::uintptr_t runtime_address, ZyanU8* data, ZyanUSize length, std::string& buffer, std::vector <JmpInfo_t>* jmps)
	{
		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
		char tmp[256];

		int nJumpsProcessed{};
		bool bHasJumps = jmps && !jmps->empty();

		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&this->m_decoder, data, length, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY)))
		{
			ZydisFormatterFormatInstruction(&this->m_formatter, &instruction, operands, instruction.operand_count_visible, &tmp[0], sizeof(tmp), runtime_address, ZYAN_NULL);

			if (bHasJumps)
			{
				if (nJumpsProcessed == 0)
				{
#ifdef _WIN64
					buffer.append(fmt::format(xorstr_("{:016X} "), (std::uintptr_t)runtime_address));
#else
					buffer.append(fmt::format(xorstr_("{:08X} "), (std::uintptr_t)runtime_address));
#endif
				}
				else
				{
#ifdef _WIN64
					buffer.append(fmt::format(xorstr_("{:<16} "), xorstr_("FOLLOWED")));
#else
					buffer.append(fmt::format(xorstr_("{:<8} "), xorstr_("FOLLOWED")));
#endif
				}
			}
			else
			{
#ifdef _WIN64
				buffer.append(fmt::format(xorstr_("{:016X} "), (std::uintptr_t)runtime_address));
#else
				buffer.append(fmt::format(xorstr_("{:08X} "), (std::uintptr_t)runtime_address));
#endif
			}

			buffer.append(fmt::format(xorstr_("{:<32}"), stdext::to_ansi(stdext::dump_hex(data, instruction.length))));
			buffer.append(tmp);

			if (jmps && !jmps->empty() && jmps->front().dst_ptr != 0 && instruction.mnemonic == ZYDIS_MNEMONIC_JMP)
			{
				buffer.append(fmt::format(xorstr_(" ; jmp <{}+{:X}>"), jmps->front().dst_module, jmps->front().dst_rva));
				jmps->erase(jmps->begin());
				++nJumpsProcessed;
			}

			if (length - instruction.length > 0)
				buffer.append(xorstr_("\n*** "));
			else
				buffer.push_back('\n');

			data += instruction.length;
			length -= instruction.length;
			runtime_address += instruction.length;
		}
	}
};
