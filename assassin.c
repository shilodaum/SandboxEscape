#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include "sys/syscall.h"
#include <sys/uio.h>
#include <linux/elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <math.h>
#include <string.h>
#include "find_pid.c"
//#include <linux/user.h>   /* For constants ORIG_EAX etc */

#define MAX_MMAPS_LINE 1000
#define MAX_DATA_COPY 1000


char* message="Hacked by epipen\n\0";
int text_len=19;



void brutal_kill(pid_t);
void clean_kill(pid_t);
void get_syscall(pid_t);
void change_syscall(pid_t);
void force_print(pid_t);
void change_print(pid_t);

long get_address_maps(pid_t);
long get_exec_address_maps(pid_t);
void ptraceRead(int, unsigned long long, void*, int);
void ptraceWrite(int, unsigned long long, void*, int);
void inject_syscall(void);
void inject_code_and_kill(pid_t);
void inject_code_and_cont(pid_t beauty);

int main()
{
    pid_t beauty = find_pid();
    inject_code_and_cont(beauty);
    return 0;
}

void brutal_kill(pid_t beauty)
{
    long orig_eax;
       
    //pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    int status = ptrace(PTRACE_ATTACH, beauty, NULL,NULL); 
    printf("The status is %d\n", status);
    waitpid(beauty, &status, 0);
    orig_eax = ptrace(PTRACE_KILL, beauty, NULL);
    
    printf("The ptrace func returned with: %ld\n", orig_eax);
}
void get_syscall(pid_t beauty)
{
    int status;
    struct user_regs_struct regs; 
    long syscall; 
    //pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    status = ptrace(PTRACE_ATTACH, beauty, NULL,NULL); 
    printf("The status is %d\n", status);

    waitpid(beauty, 0, 0);
    status = ptrace(PTRACE_SYSCALL, beauty, NULL, NULL);
        printf("Syscall returned with %d\n", status);

    waitpid(beauty, 0, 0);
    
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
    syscall = regs.orig_rax; 
    printf("%ld(rdi:%ld, rsi:%ld, rdx:%ld, r10:%ld, r8:%ld, r9:%ld)", syscall,
        (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
        (long)regs.r10, (long)regs.r8,  (long)regs.r9);
        status=ptrace(PTRACE_DETACH, beauty, 0, 0);
    printf("Detach status is %d\n", status);
}
void clean_kill(pid_t beauty)
{
    sleep(1);

    int status;
    struct user_regs_struct regs; 
    long syscall; 

    //pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    status = ptrace(PTRACE_ATTACH, beauty, 0, 0); 
    printf("Attach status is %d\n", status);
    
    waitpid(beauty, 0, 0);
    status = ptrace(PTRACE_SYSCALL, beauty, 0, 0);
    printf("Syscall status is %d\n", status); 
    
    waitpid(beauty, 0, 0);
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
    syscall = regs.orig_rax; 
    printf("syscall code: %ld with rdi: %ld and rsi: %ld\n", syscall,(long)regs.rdi,(long)regs.rsi);
    
    regs.orig_rax=60;
    regs.rax=60;
    // regs.rdi = 54;
    // regs.rsi = 140737150243488;

    status=ptrace(PTRACE_SETREGS, beauty, NULL, &regs);
    printf("Setregs status is %d\n", status); 
    
    status=ptrace(PTRACE_SYSCALL, beauty, 0, 0);
    printf("Ptrace status is %d\n", status);
    waitpid(beauty,0, 0);
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
    syscall = regs.rax; 
    printf("syscall code: %ld with rdi: %ld and rsi: %ld\n", syscall,(long)regs.rdi,(long)regs.rsi);
    sleep(2);

    status=ptrace(PTRACE_DETACH, beauty, 0, 0);
    printf("Detach status is %d\n", status);
}
void force_print(pid_t beauty)
{
    sleep(1);

    int status;
    char* str="hey there";
    struct user_regs_struct regs; 
    long syscall; 

    //pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    status = ptrace(PTRACE_ATTACH, beauty, 0, 0); 
    printf("Attach status is %d\n", status);
    
    waitpid(beauty, 0, 0);
    status = ptrace(PTRACE_SYSCALL, beauty, 0, 0);
    printf("Syscall status is %d\n", status); 
    
    waitpid(beauty, 0, 0);
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
    syscall = regs.orig_rax; 
    printf("syscall code: %ld with rdi: %ld and rsi: %ld\n", syscall,(long)regs.rdi,(long)regs.rsi);
    
    regs.orig_rax=1;
    regs.rax = 1;
    regs.rdi = 1;
    regs.rdx=30;
    //mmap((void*)94357078200324,);
    regs.rsi = (long)0x560f8bb4b000;
    status=ptrace(PTRACE_SETREGS, beauty, NULL, &regs);
    printf("Setregs status is %d\n", status); 
    
    status=ptrace(PTRACE_SYSCALL, beauty, 0, 0);


    printf("Ptrace status is %d\n", status);



    waitpid(beauty,0, 0);
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
    syscall = regs.orig_rax; 
    printf("syscall code: %ld with rdi: %ld and rsi: %ld\n", syscall,(long)regs.rdi,(long)regs.rsi);
    sleep(2);
    status=ptrace(PTRACE_DETACH, beauty, 0, 0);
    printf("Detach status is %d\n", status);
}
void change_print(pid_t beauty)
{
    sleep(1);

    int i=0;
    int text_len=19;
    int status;
    char* str="hey there";
    struct user_regs_struct regs; 
    long syscall; 

    //pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    status = ptrace(PTRACE_ATTACH, beauty, 0, 0); 
    printf("Attach status is %d\n", status);
    
    waitpid(beauty, 0, 0);
    status = ptrace(PTRACE_SYSCALL, beauty, 0, 0);
    printf("Syscall status is %d\n", status); 
    
    waitpid(beauty, 0, 0);
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
    syscall = regs.orig_rax; 
    printf("syscall code: %ld with rdi: %ld and rsi: %ld\n", syscall,(long)regs.rdi,(long)regs.rsi);
    
    regs.orig_rax=1;
    regs.rax = 1;
    regs.rdi = 1;
    regs.rdx=text_len;
    //mmap((void*)94357078200324,);
    regs.rsi = (long)get_address_maps(beauty);
    printf("address is: %lld\n",regs.rsi);
    //regs.rsi = (long)0x55bdc9330000;
    // word is 4 bytes
    // also check for /proc/<pid>/mem
    for(i=0;i<text_len;)
    {
        status=ptrace(PTRACE_POKEDATA, beauty, regs.rsi+i, (*(long long*)(message+i)));
        i+=4;
    }
    printf("Poking status is %d\n", status); 


    status=ptrace(PTRACE_SETREGS, beauty, NULL, &regs);
    printf("Setregs status is %d\n", status); 
    
    status=ptrace(PTRACE_SYSCALL, beauty, 0, 0);


    printf("Ptrace status is %d\n", status);



    waitpid(beauty,0, 0);
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
    syscall = regs.orig_rax; 
    printf("syscall code: %ld with rdi: %ld and rsi: %ld\n", syscall,(long)regs.rdi,(long)regs.rsi);
    
    sleep(2);
    status=ptrace(PTRACE_DETACH, beauty, 0, 0);
    printf("Detach status is %d\n", status);
}

long get_address_maps(pid_t beauty)
{
    //void * mmap (void *address, size_t length, int protect, int flags, int filedes,off_t offset)
    char proc_path_maps[20];
    char maps[100];
    char buffer[13];
    long addr;
    int fd;
    int i=0;
    printf("looking for address...\n");
    sprintf(proc_path_maps, "/proc/%d/maps", beauty);
    fd=open(proc_path_maps,O_RDONLY);
    if(fd < 0)
        printf("error when opening file!\n");
    else
    {
        read(fd,buffer,12);

        addr=strtol(buffer,NULL,16);
        printf("adress: %ld\n\n",addr);
        return addr;
    }
}
long get_exec_address_maps(pid_t beauty)
{
    //void * mmap (void *address, size_t length, int protect, int flags, int filedes,off_t offset)
    char proc_path_maps[20];
    char maps[100];
    char buffer[MAX_MMAPS_LINE];
    char* next_line;
    char perms[5];
    long addr;
    int fd;
    int i=0;
    printf("looking for address...\n");
    sprintf(proc_path_maps, "/proc/%d/maps", beauty);
    fd=open(proc_path_maps,O_RDONLY);
    if(fd < 0)
        printf("error when opening file!\n");
    else
    {
        
           i=0;
           while(read(fd,buffer,MAX_MMAPS_LINE-1)!=-1)
           {
            next_line=strchr(buffer,'\n');
            *next_line='\0';
            i+=strlen(buffer);
            sscanf(buffer,"%lx-%*lx %s %*s",&addr,perms);
            lseek(fd,i+1,SEEK_SET);
            if(perms[2]=='x')
            {
                break;
            }
           }
        return addr;
    }
}


void ptraceRead(int pid, unsigned long long addr, void *data, int len) {
long word = 0;
int i = 0;
char *ptr = (char *)data;

	for (i=0; i < len; i+=sizeof(word), word=0) {
		if ((word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL)) == -1) {;
			printf("[!] Error reading process memory\n");
			exit(1);
		}
		ptr[i] = word;
	}
}

void ptraceWrite(int pid, unsigned long long addr, void *data, int len) {
    long word = 0;
    int i=0;

	for(i=0; i < len; i+=sizeof(word), word=0) {
		memcpy(&word, data + i, sizeof(word));
		if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1) {;
			printf("[!] Error writing to process memory\n");
			exit(1);
		}
	}
}

void inject_syscall(void) {
	asm(
        "syscall\n"
	);
}

void inject_code_and_kill(pid_t beauty)
{
    int i=0;
    
    int status;
    char* str="hey there";
    struct user_regs_struct old_regs, regs; 
    long syscall; 
    long long fword;
    char * filename;
    long inject_addr;
    unsigned char * oldcode = (unsigned char *)malloc(9076);
    //pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    status = ptrace(PTRACE_ATTACH, beauty, 0, 0); 
    printf("Attach status is %d\n", status);
    
    waitpid(beauty, 0, 0);

    ptrace(PTRACE_GETREGS, beauty, 0, &old_regs);
	memcpy(&regs, &old_regs, sizeof(struct user_regs_struct));
   
	inject_addr = get_exec_address_maps(beauty);

	ptraceRead(beauty, inject_addr, oldcode, 9076);

	ptraceWrite(beauty, inject_addr, (&inject_syscall), 32);

	regs.rip = inject_addr;

    regs.orig_rax=1;
    regs.rax = 1;
    regs.rdi = 1;
    regs.rdx=text_len;
    regs.rsi = (long)get_address_maps(beauty);
    printf("address is: %lld\n",regs.rsi);

    for(i=0;i<text_len;)
    {
        status=ptrace(PTRACE_POKEDATA, beauty, regs.rsi+i, (*(long long*)(message+i)));
        i+=4;
    }
    printf("Poking status is %d\n", status); 

    status=ptrace(PTRACE_SETREGS, beauty, NULL, &regs);
    printf("Setregs status is %d\n", status); 
    status=ptrace(PTRACE_CONT, beauty, 0, 0);

    waitpid(beauty,0,0);

    regs.rip = inject_addr;
    regs.orig_rax=60;
    regs.rax = 60;
    status=ptrace(PTRACE_SETREGS, beauty, NULL, &regs);


    sleep(2);
    status=ptrace(PTRACE_DETACH, beauty, 0, 0);
    printf("Detach status is %d\n", status);
}


void inject_code_and_cont(pid_t beauty)
{
    int i=0;
    
    int status;
    char message_old_data[MAX_DATA_COPY];
    long long message_address;
    struct user_regs_struct old_regs, regs; 
    long syscall; 
    long long fword;
    long inject_addr;
    unsigned char * oldcode = (unsigned char *)malloc(MAX_DATA_COPY);
    //pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    status = ptrace(PTRACE_ATTACH, beauty, 0, 0); 
    printf("Attach status is %d\n", status);
    
    waitpid(beauty, 0, 0);

    ptrace(PTRACE_GETREGS, beauty, 0, &old_regs);
	memcpy(&regs, &old_regs, sizeof(struct user_regs_struct));
   
	inject_addr = get_exec_address_maps(beauty);

	ptraceRead(beauty, inject_addr, oldcode, MAX_DATA_COPY);

	ptraceWrite(beauty, inject_addr, (&inject_syscall), 32);

	regs.rip = inject_addr;

    regs.orig_rax=1;
    regs.rax = 1;
    regs.rdi = 1;
    regs.rdx=text_len;
    regs.rsi = (long)get_address_maps(beauty);
    message_address = (long)get_address_maps(beauty);
    printf("address is: %lld\n",message_address);
    
    ptraceRead(beauty,message_address,message_old_data,text_len);
    ptraceWrite(beauty,message_address,message,text_len);

    printf("Poking status is %d\n", status); 

    status=ptrace(PTRACE_SETREGS, beauty, NULL, &regs);
    printf("Setregs status is %d\n", status); 
        
    status=ptrace(PTRACE_CONT, beauty, 0, 0);

    waitpid(beauty,0,0);

    status=ptrace(PTRACE_SETREGS, beauty, NULL, &old_regs);
    
    ptraceWrite(beauty, inject_addr, oldcode, 32);
    ptraceWrite(beauty,message_address,message_old_data,text_len);

    sleep(2);
    status=ptrace(PTRACE_DETACH, beauty, 0, 0);
    printf("Detach status is %d\n", status);
}
