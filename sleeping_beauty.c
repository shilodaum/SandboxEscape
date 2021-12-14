#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
//#include <linux/user.h>   /* For constants ORIG_EAX etc */
int main()
{
    int i;
    // pid_t child = fork();
    // if(child==0){
        for( i=0;;++i)
        {
            sleep(1);
            sleep(1);
            //nanosleep(1);
            printf("%d\n", i);
        }
   // }


    exit(0);
    
    return 0;
}