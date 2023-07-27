#ifndef CRYPTO_HECC_G2_H
#define CRYPTO_HECC_G2_H

#include <g2hec_nsfieldtype.h>
#include <assert.h>
#include <g2hec_Genus2_ops.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>

#include "hec_cert.h"
#include "encoding.h"

#include <tuple>
#include <vector>

using namespace NS_G2_NAMESPACE;

#define MAX_ENCODING_LEN_G2 26
#define u_param 10
#define w_param 4

/* Signature curve params */
#define f3g2 "2682810822839355644900736"
#define f2g2 "226591355295993102902116"
#define f1g2 "2547674715952929717899918"
#define f0g2 "4797309959708489673059350"
#define pg2 "5000000000000000008503491"
#define Ng2 "24999999999994130438600999402209463966197516075699"

/* Signature base element, generated randomly */
#define gu1g2 "409749322465428199289370"
#define gu0g2 "1500254891071677800292861"
#define gv1g2 "2946046430909971157752018"
#define gv0g2 "165511752575791314109190"

/* Random private key for signing, same for every node
See explenation on README.md */
#define priv_g2 "8163892367034733443576960192244419582898514854451"

/**
 * @brief Class representing the genus 2 HECQV certificate structure and operations.
 * For the simulation the chosen format is: Name, Issued By, Issued On, Expires On, Public key.
 * Based on: https://www.secg.org/sec4-1.0.pdf
*/
class g2HECQV {
    private:
        g2hcurve curve;
        ZZ p, capriv, ku, r, du;
        divisor G, capk, pu, qu;
        std::string name, issued_by, issued_on, expires_on;
        CryptoPP::SHA3_256 hash;
    protected:
        void encode_to_bytes(uint8_t *buff);
    public:
        g2HECQV(g2hcurve curve, ZZ p, divisor G);
        vector<unsigned char> cert_generate(std::string uname, divisor ru);
        divisor cert_pk_extraction(vector<unsigned char> cert);
        ZZ cert_reception(vector<unsigned char> cert, ZZ ku);
        divisor get_calculated_Qu();
        ZZ get_extracted_du();
        std::string get_name();
        std::string get_issued_by();
        std::string get_issued_on();
        std::string get_expires_on();
};

class CryptoHECCg2 {

    private:
        ZZ p;
        g2hcurve curve;
        divisor base;
        g2HECQV cert;
        CryptoPP::SHA3_224 hash;

    protected:
        static ZZ from_divisor_to_ZZ(const divisor& div, const ZZ& n);

    public:
        /**
         * @brief Type alias used for generalization of cryptographic methods so that 
         * they can be used with an abstract class.
        */
        using element_type = divisor;

        /**
         * @brief Constructor
         * @param _p The field characteristic p.
         * @param crv The used curve.
         * @param g The base element/divisor.
        */
        CryptoHECCg2(ZZ _p, g2hcurve crv, divisor g): p(_p), curve(crv), base(g), cert(crv, p, g)
        {}

        /**
         * @brief Enrypt message using ElGamal
         * @param pub The public key.
         * @param mess The message as a genus 2 divisor.
         * @return a tuple with encrypted message divisors a, b.
        */
        tuple<divisor, divisor> encrypt_ElGamal(divisor pub, divisor mess);

        /**
         * @brief Decrypt message using ElGamal
         * @param priv The private key.
         * @param a,b The encrypted message.
         * @return The decrypted message as a genus 2 divisor.
        */
        divisor decrypt_ElGamal(ZZ priv, divisor a, divisor b);

        /**
         * @brief Method for converting two points to a valid genus 2 divisor.
         * @param x1,y1 First HEC point.
         * @param x2,y2 Second HEC point.
         * @return A valid genus 2 divisor.
        */
        divisor points_to_divisor(ZZ_p x1, ZZ_p y1, ZZ_p x2, ZZ_p y2);

        /**
         * @brief Method for converting a genus 2 divisor to two HEC points.
         * @param D The divisor
         * @param x1,y1 First HEC point.
         * @param x2,y2 Second HEC point.
        */
        void divisor_to_points (divisor D, ZZ_p &x1, ZZ_p &y1, ZZ_p &x2, ZZ_p &y2);

        /**
         * @brief Encode text to a valid genus 2 divisor. This method uses UnifiedEncodings
         * to encode an integer as a HEC point and then uses points_to_divisor to create the
         * divisor.
         * @param txt The text to encode.
         * @return A valid genus 2 divisor. 
        */
        divisor encode(string txt);

        /**
         * @brief Decode a valid divisor to text. This method uses divisor_to_points method to
         * convert a divisor to 2 HEC points and then the points are converted to text using the
         * UnifiedEncoding method.
         * @param D The divisor to decode.
         * @return The decoded text. 
        */
        string decode(divisor D);
        
        /**
         * @brief Serialize a genus 2 divisor to a vector of bytes (unsigned char).
         * By default the curve and the characteristic of this instance are used.
         * @param D The divisor.
         * @param buff The output buffer.
        */
        void serialize(divisor D, vector<unsigned char> &buff);
        
        /**
         * @brief Deserialize a genus 2 divisor from a vector of bytes (unsigned char).
         * By default the curve and the characteristic of this instance are used.
         * @param buff The input buffer.
         * @return A valid genus 2 divisor.
        */
        divisor deserialize(vector<unsigned char> buff);

        /**
         * @brief Produce an ElGamal signature.
         * @param priv The private key.
         * Note: a standard private key is used since a different curve is required for
         * signatures for simulation purposes. The parameter is used for compatibility with CryptoECC.
         * @param mess The message to sign as a vector of unsigned chars.
         * @return The signature as a string.
        */
        string sign(ZZ priv, vector<unsigned char> mess);

        /**
         * @brief Verify the ElGamal signature.
         * @param sig The signature string.
         * @param Pk The public key. 
         * Note: a standard public key is used since a different curve is required for
         * signatures for simulation purposes. The parameter is used for compatibility with CryptoECC.
         * @param mess The message to verify as a vector of unsigned chars.
         * @return True if the verification succeeds, false otherwise.
        */
        bool verify(string sig, divisor Pk, vector<unsigned char> mess);

        /**
         * @brief Wrapper for generating a new certificate and obtaining the key-pair.
         * @param gen_cert The certificate that is generated as a vector of unsigned chars.
         * @param uname The name to include to the certificate. Must be 7 characters exactly.
         * @return A tuple containing the private and public keys.
        */
        tuple<ZZ, divisor> generate_cert_get_keypair(vector<unsigned char> &gen_cert, string uname);

        /**
         * @brief Wrapper for obtaining the public key of a certificate, so that the user
         * does not have to use an HECQV instance.
         * @param rec_cert The received certificate as a vector of unsigned chars.
         * @return The extracted public key. 
        */
        divisor extract_public(vector<unsigned char> rec_cert);
};


#endif