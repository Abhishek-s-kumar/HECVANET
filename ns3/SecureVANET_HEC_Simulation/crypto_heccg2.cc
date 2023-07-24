#include "crypto_heccg2.h"

tuple<divisor, divisor> CryptoHECCg2::encrypt_ElGamal(divisor pub, divisor mess)
{
    ZZ k;
    RandomBnd(k, p*p);
    divisor a = k * base;
    divisor b = k * pub + mess;
    return tuple<divisor, divisor>(a, b);
}

divisor CryptoHECCg2::decrypt_ElGamal(ZZ priv, divisor a, divisor b)
{
    return (b - priv * a);
}