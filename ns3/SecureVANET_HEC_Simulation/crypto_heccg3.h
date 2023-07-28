#ifndef CRYPTO_HECC_G3_H
#define CRYPTO_HECC_G3_H

#include "g3hec_ops.h"
#include "hec_cert.h"

using namespace g3HEC;

#define MAX_ENCODING_LEN_G3 27
#define u_param 10
#define w_param 4

/* Genus 3 curve field characteristic */
#define pg3 "77371252455336267181195223"

/* Signature curve parameters */
#define f5g3 "1"
#define f3g3 "6218231719898953"
#define f1g3 "8683773159487505"
#define psign3 "99037184507501969"
#define Nsign3 "971392753190745941126493757635007515188486994011624"

/* Signature base element, generated randomly */
#define gu2g3 "58357352621437838"
#define gu1g3 "21425791699477544"
#define gu0g3 "20774870158739"
#define gv2g3 "86441353997400432"
#define gv1g3 "56397561880067344"
#define gv0g3 "98926713531841630"

/* Random private key for signing, same for every node
See explenation on README.md */
#define priv_g3 "27042584100361508324090725462401442475697463425802"


class CryptoHECCg3 {

    private:
        ZZ p;
        g3hcurve curve;
        g3divisor base;
        g3HECQV cert;
        CryptoPP::SHA3_224 hash;

    protected:
        static ZZ from_divisor_to_ZZ(const g3divisor& div, const ZZ& n);

    public:
        /**
         * @brief Type alias used for generalization of cryptographic methods so that 
         * they can be used with an abstract class.
        */
        using element_type = g3divisor;

        /**
         * @brief Constructor
         * @param _p The field characteristic p.
         * @param crv The used curve.
         * @param g The base element/divisor.
        */
        CryptoHECCg3(ZZ _p, g3hcurve crv, g3divisor g): p(_p), curve(crv), base(g), cert(crv, p, g)
        {}

        /**
         * @brief Enrypt message using ElGamal
         * @param pub The public key.
         * @param mess The message as a genus 3 divisor.
         * @return a tuple with encrypted message divisors a, b.
        */
        tuple<g3divisor, g3divisor> encrypt_ElGamal(g3divisor pub, g3divisor mess);

        /**
         * @brief Decrypt message using ElGamal
         * @param priv The private key.
         * @param a,b The encrypted message.
         * @return The decrypted message as a genus 3 divisor.
        */
        g3divisor decrypt_ElGamal(ZZ priv, g3divisor a, g3divisor b);

        /**
         * @brief Method for converting three points to a valid genus 3 divisor.
         * @param x1,y1 First HEC point.
         * @param x2,y2 Second HEC point.
         * @return A valid genus 3 divisor.
        */
        g3divisor points_to_divisor(ZZ_p x1, ZZ_p y1, ZZ_p x2, ZZ_p y2, ZZ_p x3, ZZ_p y3);

        /**
         * @brief Method for converting a genus 3 divisor to three HEC points.
         * @param D The divisor
         * @param x1,y1 First HEC point.
         * @param x2,y2 Second HEC point.
         * @param x3,y3 Third HEC point.
        */
        void divisor_to_points (g3divisor D, ZZ_p &x1, ZZ_p &y1, ZZ_p &x2, ZZ_p &y2, ZZ_p &x3, ZZ_p &y3);

        /**
         * @brief Encode text to a valid genus 3 divisor. This method uses UnifiedEncodings
         * to encode an integer as a HEC point and then uses points_to_divisor to create the
         * divisor.
         * @param txt The text to encode.
         * @return A valid genus 3 divisor. 
        */
        g3divisor encode(string txt);

        /**
         * @brief Decode a valid divisor to text. This method uses divisor_to_points method to
         * convert a divisor to 3 HEC points and then the points are converted to text using the
         * UnifiedEncoding method.
         * @param D The divisor to decode.
         * @return The decoded text. 
        */
        string decode(g3divisor D);

        /**
         * @brief Serialize a genus 3 divisor to a vector of bytes (unsigned char).
         * By default the curve and the characteristic of this instance are used.
         * @param D The divisor.
         * @param buff The output buffer.
        */
        void serialize(g3divisor D, vector<unsigned char> &buff);

        /**
         * @brief Deserialize a genus 3 divisor from a vector of bytes (unsigned char).
         * By default the curve and the characteristic of this instance are used.
         * @param buff The input buffer.
         * @return A valid genus 3 divisor.
        */
        g3divisor deserialize(vector<unsigned char> buff);

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
        bool verify(string sig, g3divisor Pk, vector<unsigned char> mess);

};

#endif