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

int main(){
	FILE *f;
	unsigned char buf[1024];
	Elf32_Ehdr *header;
	f = fopen("hello", "rb");
	
	fread(buf, 1024, 1, f);
	header = get_elf_header(buf);
	if(header == NULL){
		printf("failed!\n");
	}else{
		printf("success\n");
	}

	return 0;

}	
