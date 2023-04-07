/* This implementation is based on the implementation of the Genus 2
HECC library, libg2hec. */

#include <NTL/ZZ_pXFactoring.h>
#include <assert.h>
#include "fieldtype.h"

/* Some types */
//enum bool_t { FALSE = 0, TRUE = 1};
//typedef enum bool_t bool_t;
typedef bool bool_t;
#define FALSE 0
#define TRUE 1

typedef long ndeg_t;


using namespace std;
using namespace NTL;

/* Decleration of classes used in genus 3 HECC:
    1. Genus 3 Hyperelliptic Curves 
    2. Divisor class for Genus 3 HECC
    3. Arithmetic operations for g3 HEC: addition, subtraction, negation,
                                         scalar mult, comparisons, printing*/

namespace g3HEC {
    /* Genus 3 HECC */
    const long genus = 3;

    /* Pretty print polynomials */
    void print_poly(poly_tc& poly, std::ostream *s);

    /* Non Adjacent Form Class based on libg2hec */
    class N_A_F {
        private:
            ZZ naf; // Use two bits to store -1, 0, and 1: 
            // 00 -> 0, 10 -> -1, 01 ->1

        public:
            long get(long i) 
                // Get i-th position id
            {
                if ( bit(naf, 2*i) ) return 1; // bit 2*i is set, must be case: 01
                if ( bit(naf, 2*i + 1) ) return -1; // case: 10
                return 0;  // case: 00
            }

        void set(long i, long id)
            // Set i-th position id
        {
            switch( id ) {
            case 1:
                SetBit(naf, 2*i);  
                if ( bit(naf, 2*i + 1) ) SwitchBit(naf, 2*i + 1); // Set 01
                break;

            case -1:
                SetBit(naf, 2*i + 1);  
                if ( bit(naf, 2*i) ) SwitchBit(naf, 2*i); // Set 10
                break;

            case 0:
                if ( bit(naf, 2*i) ) SwitchBit(naf, 2*i); 
                if ( bit(naf, 2*i + 1) ) SwitchBit(naf, 2*i + 1); // Set 00
                break;
            }
        }
    }; // End of class N_A_F

    /* Genus 3 Hyperelliptic Curve Class */
    class g3hcurve{
        private:
            poly_t fpoly;
            poly_t hpoly;
            bool_t is_nonsingular;
            bool_t is_genus_3;
        public:
            g3hcurve(): is_nonsingular(FALSE), is_genus_3(FALSE){
                //Default constructor
            }

            g3hcurve(const poly_tc& poly1, const poly_tc& poly2)
            : fpoly(poly1), hpoly(poly2)
            {
                //Constructor
            }

            g3hcurve(const g3hcurve& hcurve)
            : fpoly(hcurve.fpoly), hpoly(hcurve.hpoly),
              is_nonsingular(hcurve.is_nonsingular), 
              is_genus_3(hcurve.is_genus_3)
              {
                  //Copy constructor
              }

            g3hcurve& operator=(const g3hcurve& hcurve)
            {
                fpoly = hcurve.fpoly;
                hpoly = hcurve.hpoly;
                is_nonsingular = hcurve.is_nonsingular;
                is_genus_3 = hcurve.is_genus_3;
                return *this;
            }

            ~g3hcurve() {} //Destructor

            void set_f(const poly_tc& poly); //Set f(x)
            void set_h(const poly_tc& poly); //Set h(x)
            void update(); //Check validity and set nonsingular and genus 3 flags
            const poly_tc& get_f() const;
            const poly_tc& get_h() const;
            bool_t is_valid_curve() const; //Return TRUE is is_nonsingular and is_genus_3
            g3hcurve& random(); //Generate a random valid curve
    };
    
    /* Mumford representation of divisor class of a genus 3 curve. Deg(u) at most 3
        and deg(v) at most 2. */
    class g3divisor {
        private:
            poly_t upoly;
            poly_t vpoly;
            static g3hcurve curve_g3;
            bool_t is_valid;
        public:
            g3divisor(): is_valid(FALSE)
            {
                NTL::set(upoly);
                clear(vpoly);
            }

            g3divisor(const poly_tc& polyu, const poly_tc& polyv, const g3hcurve& curve):
                upoly(polyu), vpoly(polyv), is_valid(FALSE)
                {
                    curve_g3 = curve;
                }
            
            g3divisor& operator=(const g3divisor& div)
            {
                if (this == &div) return *this;
                upoly = div.upoly;
                vpoly = div.vpoly;
                is_valid = div.is_valid;
                return *this;
            }

            ~g3divisor() {};

            void set_upoly(poly_tc& poly) {upoly = poly;}
            void set_vpoly(poly_tc& poly) {vpoly = poly;}

            void set_curve(const g3hcurve& curve) {g3divisor::curve_g3 = curve;}
            void update();
            const poly_tc& get_upoly() const // Get upoly
                { return upoly; }

            const poly_tc& get_vpoly() const // Get vpoly
                { return vpoly; }

            const g3hcurve& get_curve() const // Return curve
                { return curve_g3; }

            bool_t is_valid_divisor() const;

            bool_t is_unit();
            void set_unit();
            g3divisor& random();            
    };

    bool_t add_cantor_g3(g3divisor& x, const g3divisor& a, const g3divisor& b);
    bool_t add(g3divisor& x, const g3divisor& a, const g3divisor& b);
    bool_t sub(g3divisor& x, const g3divisor& a, const g3divisor& b);


    bool_t dnegate_g3(g3divisor& x, const g3divisor& a);
     // x + a = [1, 0]

    bool_t scalar_mul(g3divisor& x, const g3divisor& a, const ZZ& n, 
                    bool_t (*method)(g3divisor&, const g3divisor&, const ZZ&));
    // x = [n]*a. The following methods are exported: 
    // (1) Square and multiply: SAM
    // (2) Non-adjacent form: NAF
    // (3) Montgomery's ladder: ML
    // When no method is specified, SAM is used as default.

    bool_t scalar_mul(g3divisor& x, const g3divisor& a, long n, 
                    bool_t (*method)(g3divisor&, const g3divisor&, const ZZ&));

    /* Supported scalar multiplication methods */
    bool_t SAM(g3divisor& x, const g3divisor& a, const ZZ& n);
        // Square and multiply

    bool_t NAF(g3divisor& x, const g3divisor& a, const ZZ& n);
    // Non-adjacent form

    bool_t ML(g3divisor& x, const g3divisor& a, const ZZ& n);
    // Montgomery's ladder

    inline bool_t operator==(const g3hcurve& a, const g3hcurve& b)
    {
        return (a.get_f() == b.get_f() && a.get_h() == b.get_h());
    }

    inline bool_t operator!=(const g3hcurve& a, const g3hcurve& b)
    {
        return (!(a==b));
    }

    inline g3divisor operator+(const g3divisor& a, const g3divisor& b)
    {g3divisor x; add(x, a, b); return x;}

    inline g3divisor operator-(const g3divisor& a, const g3divisor& b)
    {g3divisor x; sub(x, a, b); return x;}

    inline g3divisor operator-(const g3divisor& a)
    {g3divisor x; dnegate_g3(x, a); return x;}

    inline g3divisor operator*(long n, const g3divisor& a)
    {g3divisor x; scalar_mul(x, a, n, NULL); return x;}

    inline g3divisor operator*(const g3divisor& a, long n)
    {g3divisor x; scalar_mul(x, a, n, NULL); return x;}

    inline g3divisor operator*(const ZZ& n, const g3divisor& a)
    {g3divisor x; scalar_mul(x, a, n, NULL); return x;}

    inline g3divisor operator*(const g3divisor& a, const ZZ& n)
    {g3divisor x; scalar_mul(x, a, n, NULL); return x;}

    inline bool_t operator==(const g3divisor& a, const g3divisor& b)
    {
        return (
            a.get_upoly() == b.get_upoly() && 
                a.get_vpoly() == b.get_vpoly());
    }

    inline bool_t operator!=(const g3divisor& a, const g3divisor& b)
    {
        return ( !(a == b) );
    }

    std::ostream& operator<<(std::ostream& s, const g3hcurve& a);
    std::ostream& operator<<(std::ostream& s, const g3divisor& a);
}
