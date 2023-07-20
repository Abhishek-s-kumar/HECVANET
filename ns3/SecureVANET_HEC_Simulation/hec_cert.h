#ifndef HEC_CERT_H 
#define HEC_CERT_H

#include "encoding.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"

class ECQV {
    private:
        GroupParameters group;
        Element capk, pu, qu;
        CryptoPP::Integer capriv, ku, r, du;
        CryptoPP::AutoSeededRandomPool prng;
        std::string name, issued_by, issued_on, expires_on;
    public:
        ECQV(GroupParameters group);
        int encode_to_bytes(uint8_t *buff);
        int cert_generate(uint8_t *encoded, std::string uname, Element ru, CryptoPP::Integer capriv);
        int cert_pk_extraction(uint8_t *cert, Element capk1);
        int cert_reception(uint8_t *cert, CryptoPP::Integer ku);
        Element get_calculated_Qu();
        CryptoPP::Integer get_extracted_du();
        std::string get_name();
        std::string get_issued_by();
        std::string get_issued_on();
        std::string get_expires_on();
};


class g2HECQV {
    private:
        NS_G2_NAMESPACE::g2hcurve curve;
        ZZ p, capriv, ku, r, du;
        NS_G2_NAMESPACE::divisor G, capk, pu, qu;
        std::string name, issued_by, issued_on, expires_on;
    public:
        g2HECQV(NS_G2_NAMESPACE::g2hcurve curve, ZZ p, NS_G2_NAMESPACE::divisor G);
        int encode_to_bytes(uint8_t *buff);
        int cert_generate(uint8_t *encoded, std::string uname, NS_G2_NAMESPACE::divisor ru, ZZ capriv);
        int cert_pk_extraction(uint8_t *cert, NS_G2_NAMESPACE::divisor capk1);
        int cert_reception(uint8_t *cert, ZZ ku);
        NS_G2_NAMESPACE::divisor get_calculated_Qu();
        ZZ get_extracted_du();
        std::string get_name();
        std::string get_issued_by();
        std::string get_issued_on();
        std::string get_expires_on();
};

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