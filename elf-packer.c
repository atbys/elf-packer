#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define Elf32_Addr uint32_t
#define Elf32_Half uint16_t
#define Elf32_Off uint32_t
#define Elf32_Sword int32_t
#define Elf32_Word uint32_t

Elf32_Ehdr *get_elf_header(unsigned char *buf){
	Elf32_Ehdr *header = NULL;

	header = (Elf32_Ehdr *)buf;
	if(!(header->e_ident[1]=='E' && header->e_ident[2]=='L' && header->e_ident[3]=='F')){
		fprintf(stderr, "non PE file\n");
		header = NULL;
		goto END;
	}

	END:
	return header;
}

void xor_decoder(unsigned char *start, unsigned int size, unsigned char encoder){
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
		unsigned int base_addr, unsigned char decoder, unsigned int oep)
{
		int	cnt=0;
		int	jmp_len_to_oep=0;

		jmp_len_to_oep = oep - (code_vaddr + code_vsize + sizeof(decode_stub));

		printf("start   : 0x%08X\n", code_vaddr);
		printf("size    : 0x%08X\n", code_vsize);
		printf("decoder : 0x%02X\n", decoder);
		printf("oep     : 0x%08X\n", oep);
		printf("jmp len : 0x%08X\n", jmp_len_to_oep);

		memcpy(&decode_stub[decode_start_offset], &code_vaddr, sizeof(uint32_t));
		memcpy(&decode_stub[decode_size_offset],  &code_vsize, sizeof(uint32_t));
		memcpy(&decode_stub[base_address_offset],  &base_addr, sizeof(uint32_t));
		memcpy(&decode_stub[decoder_offset],  &decoder, sizeof(unsigned char));
		memcpy(&decode_stub[jmp_oep_addr_offset],  &jmp_len_to_oep, sizeof(uint32_t));

		return;

}

Elf32_Shdr *search_oep_include_section_header(Elf32_Ehdr *elf_header, unsigned int oep){
	int section_num;
	int cnt=0;

	Elf32_Shdr *section_header;
	Elf32_Shdr *oep_section_header = NULL;
	unsigned int section_vaddr;
	unsigned int section_vsize;

	section_num = elf_header->e_shnum;
	section_header = (Elf32_Shdr *)((unsigned int)elf_header + elf_header->e_shoff);

	for(cnt=0; cnt < section_num; cnt++){
		section_vaddr = section_header->sh_addr;
		section_vsize = section_header->sh_size;
		printf("%s vaddr:0x%08X vsize:0x%08X oep:0x%08x\n", section_header->sh_name, section_vaddr, section_vsize, oep);

		if(section_vaddr <= oep && oep <= section_vaddr + section_vsize && section_header->sh_flags & SHF_EXECINSTR){
			printf("oep section found\n");
			oep_section_header = section_header;
			break;
		}
		*section_header++;
	}
	return oep_section_header;
}

int main(){
	int ret = 0;
	char *target_filename;
	char *packed_filename;
	Elf32_Ehdr *elf_header;
	Elf32_Shdr *oep_section_header;
	unsigned char encoder;
	unsigned int base_addr;
	unsigned int oep=0;
	unsigned int section_vaddr;
	unsigned int section_vsize;
	unsigned int section_raddr;
	unsigned int section_rsize;
	FILE 	*target_bin;
	unsigned int target_bin_size;
	struct stat stbuf;
	unsigned char *target_bin_buffer;

	target_bin = open(target_filename, O_RDONLY);
	if(target_bin == -1){
		fprintf(stderr, "fopen failed\n");
		ret = -1;
		goto END;
	}

	fstat(target_bin, &stbuf);

	target_bin_size = stbuf.st_size;

	target_bin_buffer = (unsigned char *)malloc(sizeof(unsigned char) * target_bin_size);

	read(target_bin, target_bin_buffer, target_bin_size);

	elf_header = get_elf_header(target_bin_buffer);
	oep = elf_header->e_entry;

	oep_section_header = search_oep_include_section_header(elf_header, oep);
	if(oep_section_header==NULL){
		printf("OEP include section search failed.\n");
		goto END;
	}

	
	return 0;

	END:
	return 0;
}
