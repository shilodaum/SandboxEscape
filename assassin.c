#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include "find_pid.c"
//#include <linux/user.h>   /* For constants ORIG_EAX etc */
int main()
{
    long orig_eax;
       
    pid_t beauty = find_pid();
    printf("The tracee id is %d\n", beauty);

    int status = ptrace(PTRACE_SEIZE, beauty, NULL); 
    printf("The status is %d\n", status);

    orig_eax = ptrace(PTRACE_KILL, beauty, NULL);
    
    printf("The tracee made a system call %ld\n", orig_eax);
    return 0;
}