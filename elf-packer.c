#include <stdio.h>
#include <stdint.h>
#include <elf.h>

#define Elf32_Addr uint32_t
#define Elf32_Half uint16_t
#define Elf32_Off uint32_t
#define Elf32_Sword int32_t
#define Elf32_Word uint32_t

// #define EI_NIDENT 16

/*
typedef struct {
	unsigned char e_ident[EI_NIDENT];
	Elf32_Half       e_type;
    Elf32_Half       e_machine;
	Elf32_Word       e_version;
	Elf32_Addr       e_entry;
	Elf32_Off        e_phoff;
	Elf32_Off        e_shoff;
	Elf32_Word       e_flags;
	Elf32_Half       e_ehsize;
	Elf32_Half       e_phentsize;
	Elf32_Half       e_phnum;
	Elf32_Half       e_shentsize;
	Elf32_Half       e_shnum;
	Elf32_Half       e_shstrndx;
} Elf32_Ehdr;
*/

Elf32_Ehdr *get_elf_header(unsigned char *buf){
	Elf32_Ehdr *header = NULL

	header = (Elf32_Ehdr *)buf;
	if(!(header->e_ident[1]=='E' && header->e_ident[2]=='L' && header->e_ident[3]=='F')){
		fprintf(stderr, "non PE file\n");
		header = NULL;
		goto END;
	}

	END:
	return header;
}

void xor_decoder(unsigned char *start, unsigned int size, BYTE encoder){
	unsigned int cnt=0;

	printf("Start Xor Encoder by '0x%X'\n", encoder);
	for(cnt=0; cnt<size; cnt++){
		start[cnt] ^= encoder;
	}

	printf("Encode Done\n");
}

unsigned char decode_stub[] = {
		0x60,				// pushad
		0xBE,0xFF,0xFF,0xFF,0xFF,	// mov esi, decode_start
		0xB9,0xFF,0xFF,0xFF,0xFF,	// mov ecx, decode_size
		0x81,0xC6,0xFF,0xFF,0xFF,0xFF,	// add esi, base_addr 
		0xB0,0xFF,			// mov al, decoder
		0x30,0x06,			// xor byte ptr [esi], al (LOOP)
		0x46,				// inc esi
		0x49,				// dec ecx
		0x75,0xFA,			// jnz LOOP
		0x61,				// popad
		0xE9,0xFF,0xFF,0xFF,0xFF	// jmp OEP
};

unsigned int decode_start_offset = 2;
unsigned int decode_size_offset  = 7;
unsigned int base_address_offset = 13;
unsigned int decoder_offset      = 18;
unsigned int jmp_oep_addr_offset = 27;

void create_decode_stub(unsigned int code_vaddr, unsigned int code_vsize,
		unsigned int base_addr, BYTE decoder, unsigned int oep)
{
		int	cnt=0;
		int	jmp_len_to_oep=0;

		jmp_len_to_oep = oep - (code_vaddr + code_vsize + sizeof(decode_stub));

		printf("start   : 0x%08X\n", code_vaddr);
		printf("size    : 0x%08X\n", code_vsize);
		printf("decoder : 0x%02X\n", decoder);
		printf("oep     : 0x%08X\n", oep);
		printf("jmp len : 0x%08X\n", jmp_len_to_oep);

		memcpy(&decode_stub[decode_start_offset], &code_vaddr, sizeof(DWORD));
		memcpy(&decode_stub[decode_size_offset],  &code_vsize, sizeof(DWORD));
		memcpy(&decode_stub[base_address_offset],  &base_addr, sizeof(DWORD));
		memcpy(&decode_stub[decoder_offset],  &decoder, sizeof(BYTE));
		memcpy(&decode_stub[jmp_oep_addr_offset],  &jmp_len_to_oep, sizeof(DWORD));

		return;

}

Elf32_Shdr *search_oep_include_section_header(Elf32_Ehdr *elf_header, unsigned int oep){
	int section_num;
	int cnt=0;

	Elf32_Ehdr *section_header;
	Elf32_Ehdr *oep_section_header = NULL;
	unsigned int section_vaddr;
	unsigned int section_vsize;

	section_num = //pass
	

}
