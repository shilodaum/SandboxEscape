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
#include "find_pid.c"
//#include <linux/user.h>   /* For constants ORIG_EAX etc */

void brutal_kill();
void clean_kill();
void get_syscall();
void change_syscall();


int main()
{
    //brutal_kill();
    change_syscall();
    return 0;
}

void brutal_kill()
{
    long orig_eax;
       
    pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    int status = ptrace(PTRACE_ATTACH, beauty, NULL,NULL); 
    printf("The status is %d\n", status);
    waitpid(beauty, &status, 0);
    orig_eax = ptrace(PTRACE_KILL, beauty, NULL);
    
    printf("The ptrace func returned with: %ld\n", orig_eax);
}

 void clean_kill()
{
    long orig_eax;
       
    pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    int status = ptrace(PTRACE_ATTACH, beauty, NULL,NULL); 
    printf("The status is %d\n", status);
    waitpid(beauty, &status, 0);
    orig_eax = ptrace(PTRACE_SETOPTIONS, beauty, 0, PTRACE_O_TRACEEXIT);    
    printf("The ptrace func returned with: %ld\n", orig_eax);
    ptrace(PTRACE_CONT, beauty, 0, 0);
}
void get_syscall()
{
   long status;
    struct user_regs_struct regs; 
    long syscall; 
    pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    status = ptrace(PTRACE_ATTACH, beauty, NULL,NULL); 
    printf("The status is %ld\n", status);
    waitpid(beauty, 0, 0);
    status = ptrace(PTRACE_SYSCALL, beauty, NULL, NULL);
        printf("Syscall returned with %ld\n", status); 

    waitpid(beauty, 0, 0);
    
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
    syscall = regs.orig_rax; 
    fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)", syscall,
        (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
        (long)regs.r10, (long)regs.r8,  (long)regs.r9);

}
void change_syscall()
{
    long status;
    struct user_regs_struct regs; 
    long syscall; 

    pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    status = ptrace(PTRACE_ATTACH, beauty, NULL, NULL); 
    printf("Attach status is %ld\n", status);
    waitpid(beauty, 0, 0);

    status = ptrace(PTRACE_SYSCALL, beauty, 0, 0);
    printf("Syscall returned with %ld\n", status); 
    waitpid(beauty, 0, 0);
    
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
    syscall = regs.orig_rax; 
    printf("%ld (%ld, %ld, %ld, %ld, %ld, %ld)\n", syscall,
        (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
        (long)regs.r10, (long)regs.r8,  (long)regs.r9);

    printf("before set\n");
    regs.orig_rax=60;
    regs.rdi = 0;
    status=ptrace(PTRACE_SETREGS, beauty, 0, &regs);
    printf("Setregs returned with %ld\n", status);
     
    status = ptrace(PTRACE_CONT, beauty, 0, 0);
    printf("Continue returned with %ld\n", status);


    status = ptrace(PTRACE_SYSCALL, beauty, 0, 0); 
    ptrace(PTRACE_GETREGS, beauty, 0, &regs);
   syscall = regs.orig_rax; 
  printf("%ld (%ld, %ld, %ld, %ld, %ld, %ld)\n", syscall,
       (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
       (long)regs.r10, (long)regs.r8,  (long)regs.r9);
   // ptrace(PTRACE_CONT, beauty, 0, 0);
    ptrace(PTRACE_DETACH, beauty, 0, 0);

}