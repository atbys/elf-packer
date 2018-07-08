#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
#define Elf32_Addr uint32_t
#define Elf32_Half uint16_t
#define Elf32_Off uint32_t
#define Elf32_Sword int32_t
#define Elf32_Word uint32_t
*/

#define DUMP(x) do {printf("  " #x " = %u(0x%x)\n", (uint32_t)x, (uint32_t)x);} while(0);

Elf32_Ehdr *get_elf_header(unsigned char *buf){
	Elf32_Ehdr *header = NULL;

	header = (Elf32_Ehdr *)buf;

	return header;
}
void dump_ehdr(Elf32_Ehdr *ehdr){
	int i;
    printf("  ehdr->e_ident = ");
    for (i = 0; i < EI_NIDENT; i++) {
  		printf("%02x ", ehdr->e_ident[i]);
	}
	printf("\n");
	DUMP(ehdr->e_type);
	DUMP(ehdr->e_machine);
	DUMP(ehdr->e_version);
	DUMP(ehdr->e_entry);
	DUMP(ehdr->e_phoff);
	DUMP(ehdr->e_shoff);
	DUMP(ehdr->e_flags);
	DUMP(ehdr->e_ehsize);
	DUMP(ehdr->e_phentsize);
	DUMP(ehdr->e_phnum);
	DUMP(ehdr->e_shentsize);
	DUMP(ehdr->e_shnum);
	DUMP(ehdr->e_shstrndx);
	printf("\n");
}

dump_shdr(Elf32_Shdr *shdr, int e_shnum){
    int i;
    for (i = 0; i < e_shnum; i++, shdr++) {
        DUMP(shdr->sh_name);
        DUMP(shdr->sh_type);
        DUMP(shdr->sh_flags);
        DUMP(shdr->sh_addr);
        DUMP(shdr->sh_offset);
        DUMP(shdr->sh_size);
        DUMP(shdr->sh_link);
        DUMP(shdr->sh_info);
        DUMP(shdr->sh_addralign);
        DUMP(shdr->sh_entsize);
        printf("\n");
    }
    printf("\n");
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

Elf32_Shdr *search_oep_include_section_header(Elf32_Ehdr *elf_header, Elf32_Shdr *section_header, unsigned int oep){
	int section_num;
	int cnt=0;

	Elf32_Shdr *oep_section_header = NULL;
	unsigned int section_vaddr;
	unsigned int section_vsize;

	section_num = elf_header->e_shnum;
	printf("section_num = %08x\n", section_num);
	//section_header = (Elf32_Shdr *)(&elf_header[elf_header->e_shoff]); //(elf_header + elf_header->e_shoff);

	printf("section_header = %08x\n", section_header);
	
	printf("Search!\n");
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

int main(int argc, char *argv[]){
	int ret = 0;
	char *target_filename;
	char *packed_filename;
	Elf32_Ehdr *elf_header;
	Elf32_Shdr *section_header;
	Elf32_Shdr *oep_section_header;
	unsigned char encoder;
	unsigned int base_addr;
	unsigned int oep=0;
	unsigned int section_vaddr;
	unsigned int section_vsize;
	unsigned int section_raddr;
	unsigned int section_rsize;
	int fd;
	FILE 	*target_bin;
	unsigned int target_bin_size;
	struct stat stbuf;
	//unsigned char *target_bin_buffer = NULL;

	target_filename = argv[1];
	packed_filename = argv[2];

	fd= open(target_filename, O_RDONLY);
	target_bin = fdopen(fd, "rb");

	fstat(fd, &stbuf);

	//target_bin_size = stbuf.st_size;
	//printf("target_bin_size = %08x\n", target_bin_size);

	//target_bin_buffer = (unsigned char *)malloc(sizeof(unsigned char)*stbuf.st_size);
	
	unsigned char target_bin_buffer[stbuf.st_size];

	//read(target_bin, target_bin_buffer, target_bin_size);
	fread(target_bin_buffer, 1, sizeof(target_bin_buffer), target_bin);
	//elf_header = get_elf_header(target_bin_buffer);
	elf_header = (Elf32_Ehdr *)target_bin_buffer;
	section_header = (Elf32_Shdr *)(&target_bin_buffer[elf_header->e_shoff]);
	
	dump_ehdr(elf_header);
	dump_shdr(section_header, elf_header->e_shnum);

	oep = elf_header->e_entry;
	fclose(target_bin);

	oep_section_header = search_oep_include_section_header(elf_header, section_header, oep);
	if(oep_section_header==NULL){
		printf("OEP include section search failed.\n");
		goto END;
	}

	END:
	if(target_bin != -1){
		close(target_bin);
	}
/*
	if(target_bin_buffer){
		free(target_bin_buffer);
		target_bin_buffer = NULL;
	}
*/
	return 0;
}
