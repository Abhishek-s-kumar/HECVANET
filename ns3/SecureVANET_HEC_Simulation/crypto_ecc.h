#ifndef CRYPTO_ECC_H 
#define CRYPTO_ECC_H

#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"
#include "cryptopp/integer.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"

#include "hec_cert.h"
#include "helpers.h"
#include "encoding.h"

#include <tuple>
#include <vector>

using namespace CryptoPP;

typedef DL_GroupParameters_EC<CryptoPP::ECP> GroupParameters;
typedef DL_GroupParameters_EC<CryptoPP::ECP>::Element Element;

/**
 * @brief Class for ECC cryptographic operations. ECQV Certificates, ECDSA signatures, ElGamal Encryption/Decription, Koblitz Encodings, Serialize
*/
class CryptoECC {
    
    private:
        GroupParameters _group;
        ECQV cert;
        AutoSeededRandomPool prng;
    public:
        /**
         * @brief Constructor
         * @param group Group Parameters: Curve, Base Element etc.
        */
        CryptoECC(GroupParameters group) : _group(group), cert(group)
        {}

        /**
         * @brief Enrypt message using ElGamal
         * @param pub The public key
         * @param mess The message as Element
         * @return a tuple with encrypted message Elements a, b
        */
        tuple<Element, Element> encrypt_ElGamal(Element pub, Element mess);

        /**
         * @brief Decrypt message using ElGamal
         * @param priv The private key
         * @param a,b The encrypted message 
         * @return The decrypted message as an Element
        */
        Element decrypt_ElGamal(Integer priv, Element a, Element b);

        /**
         * @brief Encode an Integer x to an EC Point
         * @param f The f polyonym of the EC equation: y^2 = f(x)
         * @param x The Integer to encode
         * @param k The parameter k for Koblitz encoding procedure
         * @param p The field characteristic
        */
        tuple<ZZ_p, ZZ_p> encode_koblitz(poly_t f, ZZ x, ZZ k, ZZ p);

        /**
         * @brief Convert to text to an Elliptic Curve Point using koblitz's method.
         * @param txt The text to convert, passed as string.
        */
        Element encode(std::string txt);

        /**
         * @brief Convert an Elliptic Curve Point to text using koblitz's method.
         * @param point The point to convert.
         * @param k The parameter k for Koblitz encoding procedure.
        */
        string decode(Element point, Integer k);

        /**
         * @brief Produce ECDSA signature.
         * @param priv The private key.
         * @param mess The message to sign as a vector of unsigned chars.
        */
        string sign(Integer priv, vector<unsigned char> mess);

        /**
         * @brief Verify ECDSA signature.
         * @param sig The signature as a string.
         * @param Pk The public key.
         * @param mess The message to sign as a vector of unsigned chars.
        */
        bool verify(string sig, Element Pk, vector<unsigned char> mess);

        /**
         * @brief Serialize a point. Bytes are pushed back on buff vector.
         * @param point The point to serialize.
         * @param buff The vector to push the serialized point.
        */
        void serialize(Element point, vector<unsigned char> &buff);

        /**
         * @brief Deserialize a point from bytes.
         * @param buff The vector that contains the point in serialized form.
        */
        Element deserialize(vector<unsigned char> buff);
};

#endif