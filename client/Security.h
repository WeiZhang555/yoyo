#ifndef SECURITY_H
#define SECURITY_H

#define DEFAULT_Q 353
#define DEFAULT_A 3
#define DEFAULT_X 7

typedef struct Diffie_Hellman{
	int sid;/*Every dh meet a file request, sid=request id*/
	int q;	/*The prime number q*/
	int a;	/*root of q*/
	int x;	/*random number*/
	int yb;	/*Y received from server*/
	int K;	/*K=yb^x mod q*/
}D_H;

extern int PickDH(D_H *dh);

#endif
