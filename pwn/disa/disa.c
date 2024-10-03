#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "disa.h"

void win(int x) {
    if (x != 0) {
        puts("cheater");
        execve("/bin/sh", 0, 0);
    }
}

void interpreter() {
    char buf[MAX_LEN];
    int16_t cells[MAX_VAL_UNSIGNED + 1];
    int16_t addr, dat = 0;
    int16_t tmp;

    while (1) {
        fgets(buf, MAX_LEN, stdin);
        
        if (strncmp(buf, "NOP", 3) == 0) {
            // nofin
        } else if (strncmp(buf, "ST", 2) == 0) {
            cells[addr] = dat;
        } else if (strncmp(buf, "LD", 2) == 0) {
            dat = cells[addr];
        } else if (strncmp(buf, "PUT", 3) == 0) {
            tmp = atoi(buf + 4);
            if (tmp >= MIN_VAL_SIGNED && tmp <= MAX_VAL_SIGNED) {
                dat = tmp;
            } else {
                puts("nuh uh uh");
            }
        } else if (strncmp(buf, "JMP", 3) == 0) {
            addr = dat;
        } else if (strncmp(buf, "ADD", 3) == 0) {
            cells[addr] += dat;
        } else if (strncmp(buf, "RD", 2) == 0) {
            printf("%d\n", dat);
        } else if (strncmp(buf, "END", 3) == 0) {
            break;
        } else {
            puts("???");
        }
    }

    puts("cya");
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    puts("D.I.S.A. (Dumb Instruction Set Architecture) Interpreter");
    puts("Send your .nut program:");

    interpreter();
}
