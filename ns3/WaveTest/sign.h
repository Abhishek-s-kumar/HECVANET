#ifndef HEADERS_H 
#define HEADERS_H

#include "encoding.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"

#endif

#define f3g2 "2682810822839355644900736"
#define f2g2 "226591355295993102902116"
#define f1g2 "2547674715952929717899918"
#define f0g2 "4797309959708489673059350"
#define pg2 "5000000000000000008503491"
#define Ng2 "24999999999994130438600999402209463966197516075699"

#define gu1g2 "409749322465428199289370"
#define gu0g2 "1500254891071677800292861"
#define gv1g2 "2946046430909971157752018"
#define gv0g2 "165511752575791314109190"

#define xpk "8163892367034733443576960192244419582898514854451"

int sign_genus2 (uint8_t *asig, ZZ& b, uint8_t *mess, int size, ZZ pch);

int verify_sig2(uint8_t *siga, ZZ sigb, uint8_t *mess, int size, uint8_t *pk);

int sign_ec(std::string &sig, CryptoPP::Integer kecc, uint8_t *message, int size);

int verify_ec(std::string sig, Element Pk, uint8_t *message, int size);