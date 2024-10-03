#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>


int prepare(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
	malloc(0x100);
}

int sail(){
	void *location = 0;
	while (1) {
		puts("Where to, captain?");
		scanf("%zu", &location);
		if (!location) { break; }
		printf("Good choice! We gathered %zu gold coins.\n",*(uint64_t *)location);
	}
	puts("Back home? Hopefully the king will be pleased...");
	sleep(2);
	return 0;
}

int report(){
	FILE* fp;
	char prev[0x100] = {};
	char line[0x200] = {};
	uint64_t base, response;
	
	puts("\n                     .\n                    / \\\n                   _\\ /_\n         .     .  (,'v`.)  .     .\n         \\)   ( )  ,' `.  ( )   (/\n          \\`. / `-'     `-' \\ ,'/\n           : '    _______    ' :\n           |  _,-'  ,-.  `-._  |\n           |,' ( )__`-'__( ) `.|\n           (|,-,'-._   _.-`.-.|)\n           /  /<( o)> <( o)>\\  \\\n           :  :     | |     :  :\n           |  |     ; :     |  |\n           |  |    (.-.)    |  |\n           |  |  ,' ___ `.  |  |\n           ;  |)/ ,'---'. \\(|  :\n       _,-/   |/\\(       )/\\|   \\-._\n _..--'.-(    |   `-'''-'   |    )-.`--.._\n          `.  ;`._________,':  ,'\n         ,' `/               \\'`.\n              `------.------'          \n                     '\n\n");
	sleep(2);
	puts("While I am impressed with these riches.. you still must prove you sailed the world.");
	sleep(2);
	
	fp = fopen("/proc/self/maps","r");
	while(fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = 0;
		char *filename = strrchr(line,' ')+1;
		if (line[strlen(line)-1] != ' ' && strcmp(filename,prev)){
			strcpy(prev,filename);
			base = strtoull(strtok(line, "-"), NULL, 16);
			printf("Where in the world is %s?\n",filename);
			scanf("%zu", &response);
			if (response == base){
				puts("Correct!");
			} else {
				puts("It seems you are not worthy of flaghood.");
				exit(1);
			}
		}
	}
	return 0;
}

int accolade(){
	FILE* fp;
	char flag[0x100];
	
	puts("You have been blessed with flaghood.");
	fp = fopen("./flag.txt","r");
	fgets(flag,sizeof(flag),fp);
	puts(flag);
}

int main(){
	prepare();
	sail();
	report();
	accolade();
	return 0;
}