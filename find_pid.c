#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#define MAX_LENGTH 10
//#include <linux/user.h>   /* For constants ORIG_EAX etc */
int find_pid()
{   
    char pid[10];
    FILE * file;
    file = popen("pgrep sleeping_beauty", "r");
    fgets(pid, MAX_LENGTH, file);
    return atoi(pid);
    //printf("%s", pid );
    //return 0;
}
/*int main()
{
    int pid = find_pid();
    printf("%d\n", pid);
    return 0;
}*/