#include<stdio.h>
#include<stdlib.h>
#include<time.h>
int gogo();
int gogo(){
	srand(time(NULL));
	int aa = rand();
	return aa;
}