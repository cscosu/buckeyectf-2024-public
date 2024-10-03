#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include "pi.h"
#include "parse.h"

int execute_expression(double op1, double op2, char operator);

int win() {
    puts("Congratulations! Here is your shell:");

    system("/bin/sh");
}

int main() {
    char operator_buf[2];
    char op1_buf[20];
    char op2_buf[20];

    char therapy_buffer[40];

    printf("Welcome to the calculator!\n");
    printf("This is a simple calculator, you can only perform +, -, *, and / operations on two operands.\n");
    printf("Give it a go!\n");

    printf("Enter the first operand: ");
    fflush(stdout);
    fgets(op1_buf, 20, stdin);
    double op1 = parse_operand(op1_buf);

    printf("Enter the operator: ");
    fflush(stdout);
    fgets(operator_buf, 2, stdin);
    getchar(); // consume newline
    if (operator_buf[0] != '+' && operator_buf[0] != '-' && operator_buf[0] != '*' && operator_buf[0] != '/') {
        fprintf(stderr, "That's not a valid operator! >:(\n");
        exit(-1);
    }

    printf("Enter the second operand: ");
    fflush(stdout);
    fgets(op2_buf, 100, stdin);
    double op2 = parse_operand(op2_buf);

    execute_expression(op1, op2, operator_buf[0]);

    printf("Bonus feature! This calculator also works as a therapy tool. Feel free to talk out anything you need to here: ");
    fflush(stdout);

    fgets(therapy_buffer, 100, stdin);
    
    return 0;
}

int execute_expression(double op1, double op2, char operator) {
    double result;
    switch (operator) {
        case '+':
            result = op1 + op2;
            break;
        case '-':
            result = op1 - op2;
            break;
        case '*':
            result = op1 * op2;
            break;
        case '/':
            result = op1 / op2;
            break;
        default:
            fprintf(stderr, "That's not a valid operator! >:(\n");
            exit(-1);
    }

    printf("Result: %f\n\n", result);
    return 0;
}