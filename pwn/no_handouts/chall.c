#include <stdlib.h>
#include <stdio.h>

void setup(){
        setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int vuln(){
        char response[0x20];

        puts("system() only works if there's a shell in the first place!");
        printf("Don't believe me? Try it yourself: it's at %p\n",system);
        puts("Surely that's not enough information to do anything else.");
        gets(response);
        return 0;
}

int main(){
        setup();
        vuln();
        return 0;
}
