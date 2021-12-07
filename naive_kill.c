

#include <string.h>
#include <stdlib.h>
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
    char buffer [MAX_LENGTH];
    pid_t beauty = find_pid();
    snprintf(buffer, 20, "kill %d", beauty);
   // itoa(beauty, buffer, MAX_LENGTH);
    popen(buffer, "r");
    return 0;
}
