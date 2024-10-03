#include <stdlib.h>
#include <stdio.h>

int main(){
    char flag[256];
    FILE *f = fopen("/flag.txt","r");
    if (f == NULL){
        puts("Flag file not found.");
        exit(0);
    }
    fgets(flag,sizeof(flag),f);
    puts(flag);
    return 0;
}