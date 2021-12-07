#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
//#include <linux/user.h>   /* For constants ORIG_EAX etc */
int main()
{
    long orig_eax;
    pid_t child = fork();
    if(child==0){
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/sleep", "sleep", "99999",NULL); 
    }
    else{
        wait(NULL);
        sleep(15);
        orig_eax = ptrace(PTRACE_KILL, child, NULL);
        printf("The child made a system call %ld\n", orig_eax);
    }
    return 0;
}