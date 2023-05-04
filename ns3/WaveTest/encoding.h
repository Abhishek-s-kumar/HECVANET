#include <g2hec_nsfieldtype.h>
#include <assert.h>
#include <g2hec_Genus2_ops.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include "cryptopp/integer.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"

#include "g3hec_ops.h"

#define ps "5000000000000000008503491"
#define N "24999999999994130438600999402209463966197516075699"
#define pt "340282366920938463463374607431768211223"

#define str_to_ZZ_p(x) to_ZZ_p(to_ZZ(x))

#define msg1 "Accept"
#define msg2 "Join"
#define msg3 "Leader"

typedef CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> GroupParameters;
typedef CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element Element;

void swap_endian(uint8_t* buffer, size_t size);

/* Compute on of the square roots of the quadratic residue only if
p = 3 mod 4 */
ZZ_p squareRoot(ZZ_p n, ZZ p);


/* Class for encoding integers in HEC of genus 1-3. Field should be of
characteristic p = 7 mod 8 and p = 3 mod 4. */
class UnifiedEncoding {
    private:
        int inu, inw, ing;
        ZZ p, g, alpha_g, beta_g, gamma_g, mg, ng;
        ZZ_p u, w, s;
        poly_t fpoly1;
        NS_G2_NAMESPACE::g2hcurve curve2;
        g3HEC::g3hcurve curve3;
    public:
        UnifiedEncoding(ZZ p, int u, int w, int g=2, ZZ_p s = ZZ_p::zero());
        void checkParams();
        void checkSParam();
        int isquadratic(ZZ_p a);
        void create_curve();
        int encode(ZZ val, ZZ_p &x, ZZ_p &y);
        int decode(ZZ_p& val1, ZZ_p& val2, ZZ_p x, ZZ_p y);
        NS_G2_NAMESPACE::g2hcurve getcurve();
        g3HEC::g3hcurve getcurveg3();
};

int try_koblitz (poly_t f, int x, ZZ_p &x1, ZZ_p &y1, ZZ k, ZZ p);


NS_G2_NAMESPACE::divisor points_to_divisor (ZZ_p x1, ZZ_p y1, ZZ_p x2, ZZ_p y2, NS_G2_NAMESPACE::g2hcurve curve);
g3HEC::g3divisor points_to_divisorg3 (ZZ_p x1, ZZ_p y1, ZZ_p x2, ZZ_p y2, ZZ_p x3, ZZ_p y3, g3HEC::g3hcurve curveg3);

void divisor_to_points (NS_G2_NAMESPACE::divisor D, ZZ_p &x1, ZZ_p &y1, ZZ_p &x2, ZZ_p &y2, ZZ p);
void divisorg3_to_points(g3HEC::g3divisor D, ZZ_p &x1, ZZ_p &y1, ZZ_p &x2, ZZ_p &y2, ZZ_p &x3, ZZ_p &y3, ZZ p);

int text_to_divisor (NS_G2_NAMESPACE::divisor &D, std::string txt, ZZ p, NS_G2_NAMESPACE::g2hcurve &curve, UnifiedEncoding enc);
int text_to_divisorg3 (g3HEC::g3divisor &D, std::string txt, ZZ p, g3HEC::g3hcurve &curve, UnifiedEncoding enc);

int divisor_to_text(std::string &txt, NS_G2_NAMESPACE::divisor D, ZZ p, UnifiedEncoding enc);
int divisorg3_to_text(std::string &txt, g3HEC::g3divisor D, ZZ p, UnifiedEncoding enc);

Element text_to_ecpoint(std::string txt, int len, GroupParameters group, int size);

std::string ecpoint_to_text(Element pointl, int size);

int divisor_to_bytes(uint8_t *buff, NS_G2_NAMESPACE::divisor D, NS_G2_NAMESPACE::g2hcurve curve, ZZ p);
int divisorg3_to_bytes(uint8_t *buff, g3HEC::g3divisor D, g3HEC::g3hcurve curve, ZZ p);

int bytes_to_divisor(NS_G2_NAMESPACE::divisor &D, uint8_t *buff, NS_G2_NAMESPACE::g2hcurve curve, ZZ p);
int bytes_to_divisorg3(g3HEC::g3divisor &D, uint8_t *buff, g3HEC::g3hcurve curve, ZZ p);