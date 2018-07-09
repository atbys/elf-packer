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
	unsigned int section_addr;
	unsigned int section_size;
	
	//file buffer
	char *target_filename;
	int fd;
	FILE *target_bin;
	unsigned int target_bin_size;
	struct stat stbuf;

	target_filename = argv[1];

	fd = open(target_filename, O_RDONLY);
	target_bin = fdopen(fd, "rb");

	fstat(fd, &stbuf);

	unsigned char target_bin_buffer[stbuf.st_size];

	fread(target_bin_buffer, 1, sizeof(target_bin_buffer), target_bin);
	
	fclose(target_bin);

	ehdr = (Elf32_Ehdr *)target_bin_buffer;
	shdr = (Elf32_Shdr *)(&target_bin_buffer[ehdr->e_shoff]);
	
	//dump header
	/*
	dump_ehdr(ehdr);
	dump_shdr(shdr, ehdr->e_shnum);
	*/

	//oep include section search
	oep_shdr = search_oep_include_section_header(shdr, ehdr->e_entry, ehdr->e_shnum); 
	return 0;
}
