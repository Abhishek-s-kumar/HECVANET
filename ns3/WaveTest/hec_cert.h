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
        int cert_pk_extraction(uint8_t *cert);
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
        int cert_pk_extraction(uint8_t *cert);
        int cert_reception(uint8_t *cert, ZZ ku);
        NS_G2_NAMESPACE::divisor g2HECQV::get_calculated_Qu();
        ZZ get_extracted_du();
        std::string get_name();
        std::string get_issued_by();
        std::string get_issued_on();
        std::string get_expires_on();
};
