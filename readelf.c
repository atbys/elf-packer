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

int main(int argc, char *argv[]){
	int fd;
	FILE *f;
	unsigned char *filename;
	unsigned char buf[1024];
	struct stat stbuf;
	Elf32_Ehdr *header;
	unsigned char *bin_buffer;

	filename = argv[1];

	fd = open(filename, O_RDONLY);
	f = fdopen(fd, "rb");

	fstat(fd, &stbuf);
	
	bin_buffer =(unsigned char *)malloc(stbuf.st_size); 
	//unsigned char buf[stbuf.st_size];
	fread(buf, 1, sizeof(buf), f);
	header = (Elf32_Ehdr *)buf;
	dump_ehdr(header);
	if(header == NULL){
		printf("failed!\n");
	}else{
		printf("success\n");
	}
	
	fclose(header);
	return 0;

}	
