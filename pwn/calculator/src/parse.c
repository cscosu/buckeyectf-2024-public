#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "pi.h"
#include "parse.h"
#include <math.h>
#include <stdio.h>

double parse_operand(char *op) {
    if (strcmp(op, "pi\n") == 0) {
        request_pi_precision();
        return M_PI;
    } else {
        char *leftover;
        double num = strtod(op, &leftover);
        if (*leftover == '\n') {
            return num;
        } else {
            fprintf(stderr, "That's not an integer or pi! >:(\n");
            exit(-1);
        }
    }
}