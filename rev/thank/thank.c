#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

void cleanupInput(char *buf) {
    buf[strcspn(buf, "\r\n")] = '\0';
}

FILE *makeFile(char *filename) {
    FILE *f;

    f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        exit(1);
    }
    return f;
}

int readSize() {
    char buf[32];

    printf("What is the size of your file (in bytes)? ");
    if (!fgets(buf, 32, stdin)) {
        perror("fgets");
        exit(1);
    }
    cleanupInput(buf);
    return atoi(buf);
}

char *allocate(int sz) {
    char *buf;

    buf = malloc(sz);
    if (!buf) {
        perror("malloc");
        exit(1);
    }
    return buf;
}

void readBytes(char *buf, int sz) {
    printf("Send your file!\n");
    if (fread(buf, 1, sz, stdin) < sz) {
        perror("fread");
        exit(1);
    }
}

void genHash(char *buf, int sz, char *hashStr, int len) {
    int i, hash;

    hash = 0;
    for (i = 0; i < sz; i++) {
        hash += buf[i];
    }
    snprintf(hashStr, len - 8, "/tmp/%x.so", hash);
}

void writeBytes(char *buf, int sz, FILE *f) {
    if (fwrite(buf, 1, sz, f) < sz) {
        perror("fwrite");
        exit(1);
    }
}

void thank(char *filename) {
    char pathBuf[32];
    void *so;
    void (*thanker)();

    snprintf(pathBuf, 32, "%s", filename);
    so = dlopen(pathBuf, RTLD_LAZY);
    if (!so) {
        goto def;
    }
    thanker = dlsym(so, "thank");
    if (thanker) {
        thanker();
        return;
    }

def:
    printf("Thanks for your file!\n");
}

void main(void) {
    char filename[32];
    FILE *f;
    int sz;
    char *buf;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    sz = readSize();
    buf = allocate(sz);
    readBytes(buf, sz);
    genHash(buf, sz, filename, 32);

    f = makeFile(filename);
    writeBytes(buf, sz, f);
    fclose(f);
    free(buf);

    thank(filename);
    remove(filename);
}
