#pragma once
#include <Zydis/Zydis.h>

namespace NoMercyCore
{
	struct jmp_inst_array
	{
		std::uint8_t opcode[ZYDIS_MAX_INSTRUCTION_LENGTH - 1];
	};

	struct JmpInfo_t
	{
		std::uintptr_t dst_ptr;
		std::uintptr_t dst_rva;
		std::string	   dst_module;
	};

	class disassembler
	{
	public:
		disassembler(ZydisMachineMode mode);
		~disassembler();

		std::tuple <ZyanStatus, ZydisDecodedInstruction*, ZydisDecodedOperand*> disassemble_instruction(void* instruction_address, std::uint32_t instruction_length = 16);
		ZyanU64 get_instruction_absolute_address(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands, ZyanU64 runtime_address);
		ZydisRegister get_instruction_register(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands);
		std::string format_instruction(ZydisDecodedInstruction& instruction, ZydisDecodedOperand* operands, ZyanU64 runtime_address);

		std::uint32_t get_mnemonic(void* address);
		std::size_t get_size(void* address);

		std::vector <std::wstring> disassemble(void* address, size_t bytes_length);
		void disassemble_buffer(std::uintptr_t runtime_address, ZyanU8* data, ZyanUSize length, std::string& buffer, std::vector <JmpInfo_t>* jmps = nullptr);

	private:
		ZydisMachineMode	m_mode;
		ZydisFormatter		m_formatter;
		ZydisDecoder		m_decoder;
	};
};
