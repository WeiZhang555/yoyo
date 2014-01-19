#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "Security.h"

int Get_Random(int max)
{
	return DEFAULT_X;
}

int PickDH(D_H *dh)
{
	if(!dh)
		return -1;
	dh->q = DEFAULT_Q;
	dh->a = DEFAULT_A;
	dh->x = Get_Random(dh->q);
}

