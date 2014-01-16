#ifndef SECURITY_H
#define SECURITY_H

#define DEFAULT_Q 353
#define DEFAULT_A 3
#define DEFAULT_X 7

typedef struct Diffie_Hellman{
	int q;	/*The prime number q*/
	int a;	/*root of q*/
	int x;	/*random number*/
}D_H;

#endif
