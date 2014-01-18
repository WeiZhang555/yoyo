#include <math.h>
#include <stdio.h>
#include <stdlib.h>

/*compute a^x mod q*/
int ComputeY(int q, int a, int x)
{
	int i=0;
	int base = 1;
	for(i=0; i<x; i++)
	{
		base = (base*a)%q;
	}
	return base;
}
