#ifndef _LDASM_
#define _LDASM_

#include <stdint.h>
#include <string.h>

#ifndef F_INVALID
#define	F_INVALID		0x01
#endif

#ifndef F_PREFIX
#define F_PREFIX		0x02
#endif

#ifndef F_REX
#define	F_REX			0x04
#endif

#ifndef F_MODRM
#define F_MODRM			0x08
#endif

#ifndef F_SIB
#define F_SIB			0x10
#endif

#ifndef F_DISP
#define F_DISP			0x20
#endif

#ifndef F_IMM
#define F_IMM			0x40
#endif

#ifndef F_RELATIVE
#define F_RELATIVE		0x80
#endif

typedef struct _ldasm_data{
	uint8_t		flags;
	uint8_t		rex;
	uint8_t		modrm;
	uint8_t		sib;
	uint8_t		opcd_offset;
	uint8_t		opcd_size;
	uint8_t		disp_offset;
	uint8_t		disp_size;
	uint8_t		imm_offset;
	uint8_t		imm_size;
} ldasm_data;

unsigned int ldasm(void *code, ldasm_data *ld, uint32_t is64);

unsigned long __fastcall SizeOfCode(void *Code, unsigned char **pOpcode);
unsigned long __fastcall SizeOfProc(void *Proc);
char __fastcall IsRelativeCmd(unsigned char *pOpcode);

#endif /* _LDASM_ */