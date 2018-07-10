#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DUMP(x) do {printf("  " #x " = %u(0x%x)\n", (uint32_t)x, (uint32_t)x);} while(0);

#define DWORD uint32_t

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

void dump_shdr(Elf32_Shdr *shdr, int e_shnum){
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

void xor_encoder(unsigned char *start, unsigned int size, unsigned char encoder)
{
	unsigned int	cnt=0;

	printf("Start Xor Encode by '0x%X'\n", encoder);
	for(cnt=0; cnt<size; cnt++){
		start[cnt] ^= encoder;
	}
	printf("Encode Done\n");
}

unsigned char decode_stub[] = {
	0x60,				// pushad
	0xBE,0xFF,0xFF,0xFF,0xFF,	// mov esi, decode_start
	0xB9,0xFF,0xFF,0xFF,0xFF,	// mov ecx, decode_size
//	0x81,0xC6,0xFF,0xFF,0xFF,0xFF,	// add esi, base_addr 
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
unsigned int base_address_offset = 13 - 6;
unsigned int decoder_offset      = 18 - 6;
unsigned int jmp_oep_addr_offset = 27 - 6;

void create_decode_stub(unsigned int code_vaddr, unsigned int code_vsize,
		unsigned char decoder, unsigned int oep)
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
	//memcpy(&decode_stub[base_address_offset],  &base_addr, sizeof(DWORD));
	memcpy(&decode_stub[decoder_offset],  &decoder, sizeof(unsigned char));
	memcpy(&decode_stub[jmp_oep_addr_offset],  &jmp_len_to_oep, sizeof(DWORD));

	return;

}

Elf32_Shdr *search_oep_include_section_header(
	Elf32_Shdr *shdr, unsigned int oep, unsigned int shnum){

	Elf32_Shdr *oep_shdr = NULL;
	unsigned int section_addr;
	unsigned int section_size;

	printf("search oep include section header\n");

	for(int i=0; i < shnum; i++, shdr++){
		//section_addr = shdr->sh_addr;
		//section_size = shdr->sh_size;
		printf("addr:0x%08X size:0x%08X oep:0x%08x\n", shdr->sh_addr, shdr->sh_size, oep);
		
		if(section_addr <= oep && 
			oep <= shdr->sh_addr + shdr->sh_size){
			printf("oep section found!\n");
			oep_shdr = shdr;
			break;
		}
	}

	return oep_shdr;

}

int main(int argc, char *argv[]){
	//header 
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	Elf32_Shdr *oep_shdr;
	
	//address and size
	unsigned int section_vaddr;
	unsigned int section_vsize;
	unsigned int section_raddr;
	unsigned int section_rsize;
	
	//file buffer
	char *target_filename;
	char *packed_filename;
	int fd;
	FILE *target_bin;
	FILE *packed_bin;
	unsigned int target_bin_size;
	struct stat stbuf;

	unsigned char encoder;

	if(argc < 3){
		printf("usage: ./a.out target_file packed_file");
		return -1;
	}

	target_filename = argv[1];
	packed_filename = argv[2];

	fd = open(target_filename, O_RDONLY);
	target_bin = fdopen(fd, "rb");

	fstat(fd, &stbuf);

	unsigned char target_bin_buffer[stbuf.st_size];

	fread(target_bin_buffer, 1, sizeof(target_bin_buffer), target_bin);
	
	fclose(target_bin);

	ehdr = (Elf32_Ehdr *)target_bin_buffer;
	shdr = (Elf32_Shdr *)(&target_bin_buffer[ehdr->e_shoff]);

	/*
	//dump header
	dump_ehdr(ehdr);
	dump_shdr(shdr, ehdr->e_shnum);
	*/

	//oep include section search
	oep_shdr = search_oep_include_section_header(shdr, ehdr->e_entry, ehdr->e_shnum); 
	printf("oep section address -> 0x%08x\n", oep_shdr->sh_addr);

	//get oep include section values
	section_vaddr = oep_shdr->sh_addr;
	section_vsize = oep_shdr->sh_size;
	section_raddr = oep_shdr->sh_offset;
	section_rsize = oep_shdr->sh_size;

	//xor encode
	encoder = 0xFF;
	xor_encoder((unsigned char *)(oep_shdr->sh_offset + target_bin_buffer), oep_shdr->sh_size, encoder);

	//create xor decode
	create_decode_stub(section_vaddr, section_vsize, encoder, ehdr->e_entry);
	memcpy((unsigned char *)(section_raddr + section_vsize + target_bin_buffer), decode_stub, sizeof(decode_stub));

	oep_shdr->sh_size = section_rsize;

	ehdr->e_entry = section_vaddr + section_vsize;
	//add write attr code section
	oep_shdr->sh_flags |= SHF_WRITE;

	
	packed_bin = fopen(packed_filename, "wb");
	
	fwrite(target_bin_buffer, sizeof(target_bin_buffer), 1, packed_bin);	
	

	return 0;
}
