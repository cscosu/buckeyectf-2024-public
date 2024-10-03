#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// gcc infrequent.c -o infrequentc

int main(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
	long largest = 0;
	long counts[256] = {0};
	char *text = malloc(600);
	char filepath[] = "/home/corgo/stats/stats.txt"; // default file to save to

	char *filename = strrchr(filepath,'/')+1;
	
	puts("Enter text to perform frequency analysis on:");
	fgets(text,600,stdin);
	text[strcspn(text, "\n")] = 0;
	
	for(int i = 0; i < strlen(text); i++){
		counts[text[i]]++;
	}

	for (int i = 0; i < 256; i++){
		if (counts[i] == 0) {continue;}
		if (counts[i] > counts[largest]) {largest = i;}
		printf("Character '%c' showed up %ld times\n",i,counts[i]);
	}	
	
	printf("The most frequent character was '%c', showing up %ld time(s).\n",(char)largest,counts[largest]);
	// TODO: save stats to file
	puts("Enter filename to save file to (leave blank for default)");
	fgets(filename,9,stdin);
	return 0;
}