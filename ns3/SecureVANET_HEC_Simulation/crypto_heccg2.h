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

// template<typename T>
// class Test final{
//     public:
//         Test(const T &inst){
//             typename T::element_type p;
//         }
// };

class CryptoHECCg2 {

    private:
        ZZ p;
        g2hcurve curve;
        divisor base;
        g2HECQV cert;

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
};


#endif