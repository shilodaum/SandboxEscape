#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
//#include <linux/user.h>   /* For constants ORIG_EAX etc */
int main()
{   long orig_eax;
    pid_t dest_pid  = 641;
    orig_eax = ptrace(PTRACE_O_EXITKILL, dest_pid, NULL);
    printf("The child made a system call %ld\n", orig_eax);
    return 0;
}