#ifndef HELPERS_H 
#define HELPERS_H

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include "NTL/ZZ_p.h"
#include "NTL/ZZ_pX.h"
#include "NTL/ZZ_pXFactoring.h"

void vli_print(uint8_t *vli, unsigned int size);

void swap_endian(uint8_t* buffer, size_t size);

NTL::ZZ_p squareRoot(NTL::ZZ_p n, NTL::ZZ p);

uint8_t* find_string(NTL::ZZ_p val1, NTL::ZZ_p val2, int size, int mode=0);

#endif