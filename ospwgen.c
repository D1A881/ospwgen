    ///////////////////////////////////////////////
   // ospwgen.c - old school password generator //
  //              billy@slack.net              //
 // 5.5.22; 3.16.25; 5.9.25; 8.11.25; 10.7.25 //
///////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_PASSWORD_LENGTH 128
#define DEFAULT_PASSWORD_LENGTH 14

void usage(char* cmd) {
        printf("\n");
        printf(",-. ,-. ;-. , , , ,-: ,-. ;-.\n");
        printf("| | `-. | | |/|/  | | |-' | |\n");
        printf("`-' `-' |-' ' '   `-| `-' ' '\n");
        printf("        '         `-'        \n");
        printf("Usage: %s <format string> [h]\n\n", cmd);
        printf("Format string characters:\n");
        printf(" u = uppercase letter\n");
        printf(" l = lowercase letter\n");
        printf(" c = consonant\n");
        printf(" v = vowel\n");
        printf(" C = uppercase consonant\n");
        printf(" V = uppercase vowel\n");
        printf(" d = digit\n");
        printf(" s = symbol\n");
        printf(" r = random printable character\n\n");
        printf(" Optional second argument:\n");
        printf(" h = show output in hex also\n");
        printf(" H = show output in uppercase hex also\n");
        printf(" h0 = show output in hex only\n");
        printf(" H0 =  show output in uppercase hex only\n\n");
        printf(" Random passwords:\n");
        printf("%s R = Generate a random password of 14 characters\n",cmd);
        printf("%s R <n> = Generate a random password of <n> characters\n",cmd);
        printf("%s R <n1> <n2> = Generate <n2> random passwords of <n1> characters\n",cmd);
        exit(0);
}

int main(int  argc, char* argv[])
{
	int rn = 0;
	int alength = 0;
        long val2 = 0;
	long val3 = 0;
	char c = 0x00;
	char* cmd = argv[0];
	char o_str[129] = {0};
	char a_upper[]	= "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int l_upper = sizeof(a_upper) - 1;
	char a_upperc[]	= "BCDFGHJKLMNPQRSTVWXYZ";
	int l_upperc = sizeof(a_upperc) - 1;
	char a_upperv[]	= "AEIOU";
	int l_upperv = sizeof(a_upperv) - 1;
	char a_lower[]	= "abcdefghijklmnopqrstuvwxyz";
	int l_lower = sizeof(a_lower) - 1;
	char a_lowerc[]	= "bcdfghjklmnpqrstvwxyz";
	int l_lowerc = sizeof(a_lowerc) - 1;
	char a_lowerv[]	= "aeiou";
	int l_lowerv = sizeof(a_lowerv) - 1;
	char a_digit[]	= "0123456789";
	int l_digit = sizeof(a_digit) - 1;
	char a_symbl[]	= "!@#$%^&*()-+;:,.";
	int l_symbl = sizeof(a_symbl) - 1;
	char a_all[]	= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-+;:,.";
	int l_all = sizeof(a_all) - 1;
        char a_fstr[]   = "ulcvCVdsr";

if (!argv[1]){
        printf("ERROR: Format string required as argument! Exiting.\n");
	usage(cmd);
}

//get length of first arg
alength = strlen(argv[1]);

	//handle R args and exit
	if (strcmp(argv[1],"R")==0){

	// Validate argv[2] if present
	if (argv[2]){
        char* endptr;
	val2 = strtol(argv[2], &endptr, 10);
        	if (*endptr != '\0' || val2 < 1 || val2 > MAX_PASSWORD_LENGTH) {
		printf("ERROR: Arguments for R must be an INTEGER value between 1 and %d!\n", MAX_PASSWORD_LENGTH);
		usage(cmd);
        	}
	}

	// Validate argv[3] if present
	if (argv[3]){
        char* endptr;
        val3 = strtol(argv[3], &endptr, 10);
		if (*endptr != '\0' || val3 < 1 || val3 > MAX_PASSWORD_LENGTH) {
		printf("ERROR: Arguments for R must be an INTEGER value between 1 and %d!\n", MAX_PASSWORD_LENGTH);
		usage(cmd);
		}
	}

//input ok, generate randoms 
	if (argv[2]==0){
		for (int j=0;j<DEFAULT_PASSWORD_LENGTH;j++){
		rn = arc4random_uniform(l_all);
		o_str[j] = a_all[rn];
        	}
	printf("%s\n", o_str);
	}

	if (argv[2] && !argv[3]){
        	for (int j=0;j<val2;j++){
		rn = arc4random_uniform(l_all);
		o_str[j] = a_all[rn];
		}
	printf("%s\n", o_str);
	}

	if (argv[2] && argv[3]){
		for (int i=0;i<val3;i++){
			for (int j=0;j<val2;j++){
			rn = arc4random_uniform(l_all);
			o_str[j] = a_all[rn];
        		}
		printf("%s\n", o_str);
		}
	}
	return 0;
}

//check format string for invalid length
	char *result;
	if (alength > MAX_PASSWORD_LENGTH){
                printf("ERROR: Format string must be %d bytes or LESS! Exiting.\n", MAX_PASSWORD_LENGTH);
		usage(cmd);
        }

//check format string for invalid characters, i.e: anything not in a_fstr
       	for (int i=0;i<alength;i++){
		result = strchr(a_fstr, argv[1][i]);
	
		if (result != NULL) ; // format char found in a_fstr, next char
		else {
			printf("ERROR: INVALID CHARACTER '%c' at position %d! Exiting.\n", argv[1][i],i+1);
			usage(cmd);
		}	
	}

//input ok, parse format string bytes and generate output string (o_str)
for (int i = 0; i < alength; i++) {
	c = argv[1][i];
	switch (c){
	case 'u':
		o_str[i] = a_upper[arc4random_uniform(l_upper)];
		break;
	case 'l':
		o_str[i] = a_lower[arc4random_uniform(l_lower)];
		break;
	case 'c':
		o_str[i] = a_lowerc[arc4random_uniform(l_lowerc)];
		break;
	case 'v':
		o_str[i] = a_lowerv[arc4random_uniform(l_lowerv)];
		break;
	case 'C':
		o_str[i] = a_upperc[arc4random_uniform(l_upperc)];
		break;
	case 'V':
		o_str[i] = a_upperv[arc4random_uniform(l_upperv)];
		break;
	case 'd':
		o_str[i] = a_digit[arc4random_uniform(l_digit)];
		break;
	case 's':
		o_str[i] = a_symbl[arc4random_uniform(l_symbl)];
		break;
	case 'r':
		o_str[i] = a_all[arc4random_uniform(l_all)];
		break;
	}
}

//parse and handle h/H args and exit
if (argv[2] && strcmp(argv[1],"R")!=0) {
		
	if (strcmp(argv[2],"h")== 0){
		printf("%s\n",o_str);
		for (int i=0;i<alength;i++){
		printf("%x",o_str[i]);
		}
		printf("\n");
	}

	if (strcmp(argv[2],"H")== 0){
		printf("%s\n",o_str);
		for (int i=0;i<alength;i++){
		printf("%X",o_str[i]);
		}
		printf("\n");
	}
		
	if (strcmp(argv[2],"h0")== 0){
		for (int i=0;i<alength;i++){
		printf("%x",o_str[i]);
		}
		printf("\n");
	}

	if (strcmp(argv[2],"H0")== 0){
		for (int i=0;i<alength;i++){
		printf("%X",o_str[i]);
		}
		printf("\n");
	}
	return 0;
}

printf("%s\n",o_str);
return 0;
}
