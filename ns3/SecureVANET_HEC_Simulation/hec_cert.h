#ifndef HEC_CERT_H 
#define HEC_CERT_H

#include "encoding.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"


class g3HECQV {
    private:
        g3HEC::g3hcurve curve;
        ZZ p, capriv, ku, r, du;
        g3HEC::g3divisor G, capk, pu, qu;
        std::string name, issued_by, issued_on, expires_on;
    public:
        g3HECQV(g3HEC::g3hcurve curve, ZZ p, g3HEC::g3divisor G);
        int encode_to_bytes(uint8_t *buff);
        int cert_generate(uint8_t *encoded, std::string uname, g3HEC::g3divisor ru, ZZ capriv1);
        int cert_pk_extraction(uint8_t *cert, g3HEC::g3divisor capk1);
        int cert_reception(uint8_t *cert, ZZ ku);
        g3HEC::g3divisor get_calculated_Qu();
        ZZ get_extracted_du();
        std::string get_name();
        std::string get_issued_by();
        std::string get_issued_on();
        std::string get_expires_on();
};

#endif