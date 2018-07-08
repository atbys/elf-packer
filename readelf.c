#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
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

int main(int argc, char *argv[]){
	int fd;
	FILE *f;
	unsigned char *filename;
	//unsigned char *buf;
	struct stat stbuf;
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	unsigned char *bin_buffer;

	filename = argv[1];

	fd = open(filename, O_RDONLY);
	f = fdopen(fd, "rb");

	fstat(fd, &stbuf);
	
	//buf = (unsigned char *)malloc(sizeof(unsigned char)*stbuf.st_size); 
	unsigned char buf[stbuf.st_size];
	fread(buf, 1, sizeof(buf), f);
	ehdr = (Elf32_Ehdr *)buf;
	dump_ehdr(ehdr);

	shdr = (Elf32_Shdr *)(&buf[ehdr->e_shoff]);
	dump_shdr(shdr, ehdr->e_shnum);

	fclose(f);
	return 0;

}	
