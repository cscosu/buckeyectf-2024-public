#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define ARRLEN(x) (sizeof(x) / sizeof(*x))
#define CMD_SIZE 0x10

char CMD_BUF[CMD_SIZE] = { 0 };

void handle_echo();
void handle_dish();
void handle_engines();
void handle_shields();
void handle_status();
void handle_help();

struct {
    char *cmdName;
    void (*handler)();
} CMD_HANDLERS[] = {
    "help", handle_help,
    "echo", handle_echo,
    "dish", handle_dish,
    "engines", handle_engines,
    "shields", handle_shields,
    "status", handle_status,
};

void get_command() {
    memset(CMD_BUF, 0, CMD_SIZE);
    printf("COMMAND> ");
    if (!fgets(CMD_BUF, 0x20, stdin)) {
        exit(1);
    }
}

void flush_input() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void handle_echo() {
    printf("%s\n", CMD_BUF + strlen("echo "));
}

float DISH_X, DISH_Y = 0;
void handle_dish() {
    printf("ENTER COORDINATES: ");
    if (scanf("%f %f", &DISH_X, &DISH_Y) == 2) {
        printf("DISH ADJUSTED TO %f %f\n\n", DISH_X, DISH_Y);
    } else {
        puts("ERROR\n");
    }
    flush_input();
}

int ENGINE_POWER = 5;
void handle_engines() {
    printf("ENTER POWER (0-10): ");
    if (scanf("%d", &ENGINE_POWER) == 1 && ENGINE_POWER >= 0 && ENGINE_POWER <= 10) {
        printf("ENGINE POWER SET TO %d\n\n", ENGINE_POWER);
    } else {
        puts("ERROR\n");
    }
    flush_input();
}

int SHIELDS = 1;
void handle_shields() {
    int sz;
    char buf[4];
    printf("CHOOSE (on/off): ");
    if (!fgets(buf, 4, stdin)) {
        puts("ERROR\n");
        return;
    }

    if (strncmp(buf, "off", 3) == 0) {
        SHIELDS = 0;
        puts("SHIELDS OFF\n");
    } else if (strncmp(buf, "on", 2) == 0) {
        SHIELDS = 1;
        puts("SHIELDS ON\n");
    } else {
        puts("ERROR\n");
    }

    for (int i = 0; i < 4; i++) {
        if (buf[i] == '\n') {
            return;
        }
    }
    flush_input();
}

void handle_status() {
    puts("STATUS");
    printf("DISH: %f %f\n", DISH_X, DISH_Y);
    printf("ENGINES: %d\n", ENGINE_POWER);
    if (SHIELDS) {
        puts("SHIELDS: ON");
    } else {
        puts("SHIELDS: OFF");
    }
    puts("");
}

void handle_help() {
    puts("AVAILABLE COMMANDS:");
    for (int i = 0; i < ARRLEN(CMD_HANDLERS); i++) {
        puts(CMD_HANDLERS[i].cmdName);
    }
    puts("quit\n");
}

void handle_unknown() {
    if (*CMD_BUF != '\0' && *CMD_BUF != '\n') {
        printf("UNKNOWN COMMAND: %s\n", CMD_BUF);
    }
}

void sys_run() {
    char user[0x30];
    printf("LOGIN: ");      
    fgets(user, 0x30, stdin);
    puts("AUTHORIZED\n");

    void (*handler)();
    while (1) {
        get_command();
        if (strncmp(CMD_BUF, "quit", 4) == 0) {
            break;
        }

        handler = handle_unknown;
        for (int i = 0; i < ARRLEN(CMD_HANDLERS); i++) {
            if (strncmp(CMD_BUF, CMD_HANDLERS[i].cmdName, strlen(CMD_HANDLERS[i].cmdName)) == 0) {
                handler = CMD_HANDLERS[i].handler;
                break;
            }
        }
        (handler)();
    }
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    puts("###################################");
    puts("# SPACEMAN CONTROL CENTER v0.69.1 #");
    puts("###################################\n");

    sys_run();            
    
    puts("GOODBYE");
}
