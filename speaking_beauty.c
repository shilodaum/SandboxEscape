#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
int main()
{
    int i=0;
        for ( ; ;++i ){
            sleep(1);
            printf("hi %d\n",i);
        }
        

    
    return 0;
}