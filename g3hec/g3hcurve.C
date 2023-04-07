/* Implementation of curve routines with the use of NTL library */

#include "g3hec_ops.h"
#include <assert.h>

using namespace std;

namespace g3HEC {

    /* Pretty print polynomials */
    void print_poly(poly_tc& poly, std::ostream *s) {
        ndeg_t degree = deg(poly);

        if (degree >=0){
            for (ndeg_t i = degree ; i > 0; i-- ) {

                if ( IsZero(coeff(poly, i)) ) {

                // do nothing 

                } else if ( IsOne(coeff(poly, i)) ) {

                    if (i == 1)
                    *s << (i == degree ? "" : " + ") << "x" ;
                    else 
                    *s << (i == degree ? "" : " + ") << "x^" << i;

                } else {

                    if (i == 1)
                    *s << (i == degree ? "" : " + ") << coeff(poly, i) << "*x";
                    else 
                    *s << (i == degree ? "" : " + ") << coeff(poly, i) << "*x^" << i;

                }

            } // endfor 

            if (!IsZero(coeff(poly, 0)))
                *s << (degree == 0 ? "" : " + ") << coeff(poly, 0);
            cout << endl;

        }
        else { // 0 polynomial
            *s << 0 << endl;
        }
    }

    bool_t dnegate_g3(g3divisor& x, const g3divisor& a)
    {
        bool_t OK = a.is_valid_divisor();

        assert(OK);

        poly_t u = a.get_upoly(), v = a.get_vpoly();

        x.set_upoly(u);

        x.set_vpoly( (-v - a.get_curve().get_h()) % u );

        x.update();

        assert(x.is_valid_divisor());

        return OK;
    }

    /* Addition based on the Cantor algorithm for the cases that are not 
    handled by the explicit addition (Algorithm 14.52). Implemented from libg2hec
    as Cantor's algorithm is irrelevant of genus. */
    bool_t add_cantor_g3(g3divisor& x, const g3divisor& a, const g3divisor& b)
    {
        bool_t OK = TRUE;

        if (!a.is_valid_divisor() || !b.is_valid_divisor()) {
            OK = FALSE;
        } else {
            poly_tc u1 = a.get_upoly();
            poly_tc v1 = a.get_vpoly(); 
            poly_tc u2 = b.get_upoly(); 
            poly_tc v2 = b.get_vpoly();
            poly_tc f = x.get_curve().get_f();
            poly_tc h = x.get_curve().get_h();
            poly_t d1, d, e1, e2, c1, c2, temp1, temp2, u, v;

            // Step 1: d1 = gcd(u1, u2) 
            //[extended Euclid's algorithm gives d1 = e1*u1 + e2*u2 ]
            XGCD(d1, e1, e2, u1, u2);

            // Step 2: d = gcd(d1, v1+v2+h)
            // [d = c1*d1 + c2*(v1 + v2 + h)]
            temp1 = v1 + v2 + h;
            XGCD(d, c1, c2, d1, temp1);

            // Step 3: s1 = c1*e1, s2 = c1*e2, s3 = c2
            // Step 4: u = u1*u2/d^2
            // v= (s1*u1*v2 + s2*u2*v1 + s3*(v1*v2 + f))/d mod u

            u = (u1 * u2)/(d*d);

            temp1 = (c1*e1*u1*v2 + c1*e2*u2*v1 + c2*(v1*v2 + f))/d;

            v = temp1 % u;

            // Step 5-8:
            // 5. repeat
            // 6. u' = (f - v*h -v^2)/u, v' = -(h+v) mod u'
            // 7. u = u', v = v'
            // 8. until deg u <= genus = 3
            for ( ;deg(u) > genus; ) {
                temp1 = (f - v*h - v*v)/u;
                temp2 = (-h - v) % temp1;
                u = temp1; v = temp2;
            } // endfor

            // Step 9: make u monic
            MakeMonic(u);

            // Step 10: return [u, v]
            x.set_upoly(u);
            x.set_vpoly(v);
            x.update();
            assert(x.is_valid_divisor());
        }

        return OK;
    }

    /* Addition of Divisor classes based on the algorithm 14.52 of Handbook of EAHCC
    for better performance. Total complexity I + 70M + 6S for the most common case. 
    Assumes that the 2 Divisors are not the same, they are both of degree 3 and have no
    common factor. */
    static bool_t add_diff(g3divisor& x, const g3divisor& a, const g3divisor& b) {
        //Algorithm 14.52 of Handbook of EAHCC

        bool_t OK = TRUE;

        const field_t h3 = coeff(a.get_curve().get_h(), 3),
                      h2 = coeff(a.get_curve().get_h(), 2),
                      h1 = coeff(a.get_curve().get_h(), 1),
                      h0 = coeff(a.get_curve().get_h(), 0),
                      f6 = coeff(a.get_curve().get_f(), 6),
                      f5 = coeff(a.get_curve().get_f(), 5),
                      f4 = coeff(a.get_curve().get_f(), 4),
        u12 = coeff(a.get_upoly(), 2), u11 = coeff(a.get_upoly(), 1), u10 = coeff(a.get_upoly(), 0), 
        u22 = coeff(b.get_upoly(), 2), u21 = coeff(b.get_upoly(), 1), u20 = coeff(b.get_upoly(), 0), 
        v12 = coeff(a.get_vpoly(), 2), v11 = coeff(a.get_vpoly(), 1), v10 = coeff(a.get_vpoly(), 0), 
        v22 = coeff(b.get_vpoly(), 2), v21 = coeff(b.get_vpoly(), 1), v20 = coeff(b.get_vpoly(), 0);

        field_t t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, r, inv2, inv1, inv0,
                t12, t13, t14, t15, t16, t17, r0p, r1p, r2p, r3p, r4p, t18, s0p, s1p, s2p,
                w1, w2, w3, w4, w5, s0, s1, z0, z1, z2, z3, z4, u3p, u2p, u1p, u0p, 
                v0p, v1p, v2p, v3p, u2pp, u1pp, u0pp, v2pp, v1pp, v0pp;

        /* Algorithm */

        /* Step 1: */
        t1 = u12*u21;
        t2 = u11*u22;
        t3 = u11*u20;
        t4 = u10*u21;
        t5 = u12*u20;
        t6 = u10*u22;
        t7 = sqr(u20-u10);
        t8 = sqr(u21-u11);
        t9 = (u22-u12)*(t3-t4);
        t10 = (u22-u12)*(t5-t6);
        t11 = (u21-u11)*(u20-u10);
        r = (u20-u10 + t1 - t2)*(t7-t9) + (t5-t6)*(t10 - 2*t11) + t8*(t3-t4);
        if(IsZero(r)) {
            return add_cantor_g3(x, a, b);
        }

        /* Step 2: */
        inv2 = (t1 - t2 - u10 + u20)*(u22 - u12)-t8;
        inv1 = inv2*u22 - t10 + t11;
        inv0 = inv2*u21 - u22*(t10-t11) + t9 - t7;

        /* Step 3: */
        t12 = (inv1+inv2)*(v22-v12+v21-v11);
        t13 = (v21 - v11)*inv1;
        t14 = (inv0+inv2)*(v22-v12 + v20-v10);
        t15 = (v20-v10)*inv0;
        t16 = (inv0+inv1)*(v21-v11 + v20-v10);
        t17 = (v22-v12)*inv2;
        r0p = t15;
        r1p = t16-t13-t15;
        r2p = t13+t14-t15-t17;
        r3p = t12-t13-t17;
        r4p = t17;
        t18 = u22*r4p - r3p;
        t15 = u20*t18;
        t16 = u21*r4p;
        s0p = r0p + t15;
        s1p = r1p - (u21 + u20)*(r4p - t18) + t16 - t15;
        s2p = r2p - t16 + u22*t18;
        if(IsZero(s2p)) {
            return add_cantor_g3(x, a, b);
        }

        /* Step 4: */
        w1 = 1/(r*s2p);
        w2 = r*w1;
        w3 = sqr(s2p)*w1;
        w4 = r*w2;
        w5 = sqr(w4);
        s0 = w2*s0p;
        s1 = w2*s1p;

        /* Step 5: */
        z0 = s0*u10;
        z1 = s1*u10 + s0*u11;
        z2 = s0*u12 + s1*u11 + u10;
        z3 = s1*u12 + s0 + u11;
        z4 = u12 + s1;

        /* Step 6: */
        u3p = z4 + s1 - u22;
        u2p = -u22*u3p - u21 + z3 + s0 + w4*h3 + s1*z4;
        u1p = w4*(h2 + 2*v12 + s1*h3) + s1*z3 + s0*z4 + z2 - w5 - u22*u2p - u21*u3p - u20;
        u0p = w4*(s1*h2 + h1 + 2*v11 + 2*s1*v12 + s0*h3) + s1*z2 + z1 + s0*z3 + w5*(u12 - f6) - u22*u1p - u21*u2p - u20*u3p;

        /* Step 7: */
        t1 = u3p - z4;
        v0p = -w3*(u0p*t1 + z0) - h0 - v10;
        v1p = -w3*(u1p*t1 - u0p + z1) - h1 - v11;
        v2p = -w3*(u2p*t1 - u1p + z2) - h2 - v12;
        v3p = -w3*(u3p*t1 - u2p + z3) - h3;

        /* Step 8: */
        u2pp = f6 - u3p - sqr(v3p) - v3p*h3;
        u1pp = -u2p - u2pp*u3p + f5 - 2*v2p*v3p - v3p*h2 - v2p*h3;
        u0pp = -u1p - u2pp*u2p - u1pp*u3p + f4 - 2*v1p*v3p - sqr(v2p) - v2p*h2 - v3p*h1 - v1p*h3;

        /* Step 9: */
        v2pp = -v2p + (v3p + h3)*u2pp - h2;
        v1pp = -v1p + (v3p + h3)*u1pp - h1;
        v0pp = -v0p + (v3p + h3)*u0pp - h0;

        /* Step 10: */
        poly_t upp, vpp;

        SetCoeff(upp, 3, 1);
        SetCoeff(upp, 2, u2pp);
        SetCoeff(upp, 1, u1pp);
        SetCoeff(upp, 0, u0pp);

        SetCoeff(vpp, 2, v2pp);
        SetCoeff(vpp, 1, v1pp);
        SetCoeff(vpp, 0, v0pp);

        x.set_upoly(upp);
        x.set_vpoly(vpp);
        x.update();

        assert(OK = ( OK && x.is_valid_divisor()) );
        return OK;
    }

    /* Doubling of Divisor class, e.g. D' = [2]D based on algorithm 14.53 of 
    Handbook of EAHCC. Total complexity I + 69M + 10S in the most common case.*/
    static bool_t doubling(g3divisor& x, const g3divisor& a) {
        /* Algorithm 14.53 of Handbook of EAHCC */

        bool_t OK = TRUE;

        const field_t f6 = coeff(a.get_curve().get_f(), 6),
                      f5 = coeff(a.get_curve().get_f(), 5),
                      f4 = coeff(a.get_curve().get_f(), 4),
                      f3 = coeff(a.get_curve().get_f(), 3),
                      h3 = coeff(a.get_curve().get_h(), 3),
                      h2 = coeff(a.get_curve().get_h(), 2),
                      h1 = coeff(a.get_curve().get_h(), 1),
                      h0 = coeff(a.get_curve().get_h(), 0),
            u2 = coeff(a.get_upoly(), 2), u1 = coeff(a.get_upoly(), 1), 
            u0 = coeff(a.get_upoly(), 0), v2 = coeff(a.get_vpoly(), 2), 
            v1 = coeff(a.get_vpoly(), 1), v0 = coeff(a.get_vpoly(), 0);

        field_t t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, r, inv2, inv1, inv0,
                t12, z3p, z2p, z1p, z2, z1, z0, t13, t14, t15, t16, t17, r0p, r1p, r2p,
                r3p, r4p, t18, s0p, s1p, s2p, w1, w2, w3, w4, w5, s0, s1, g0, g1, g2, g3, g4,
                u3p, u2p, u1p, u0p, v3p, v2p, v1p, v0p, u2pp, u1pp, u0pp, v2pp, v1pp, v0pp;
        
        poly_t upp, vpp;

        poly_t h = a.get_curve().get_h(), v = a.get_vpoly();
        poly_t hr = h + 2*v;

        field_t h0r, h1r, h2r;

        h0r = coeff(hr, 0);
        h1r = coeff(hr, 1);
        h2r = coeff(hr, 2);

        /* Step 1: */
        t1 = u2*h1r;
        t2 = u1*h2r;
        t3 = u1*h0r;
        t4 = u0*h1r;
        t5 = u2*h0r;
        t6 = u0*h2r;
        t7 = sqr(h0r - h3*u0);
        t8 = sqr(h1r - h3*u1);
        t9 = (h2r - h3*u2)*(t3-t4);
        t10 = (h2r - h3*u2)*(t5-t6);
        t11 = (h1r - h3*u1)*(h0r - h3*u0);
        r = (h0r - h3*u0 + t1-t2)*(t7-t9) + (t5-t6)*(t10 - 2*t11) + t8*(t3-t4);
        if(IsZero(r)) {
            return add_cantor_g3(x, a, a);
        }

        /* Step 2: */
        inv2 = -(t1-t2-h3*u0+h0r)*(h2r - h3*u2) + t8;
        inv1 = inv2*u2 + t10 - t11;
        inv0 = inv2*u1 + u2*(t10 - t11) - t9 + t7;

        /* Step 3: */
        t12 = sqr(v2);
        z3p = f6 - u2;
        t13 = z3p*u1;
        z2p = f5 - h3*v2 - u1 - u2*f6 + sqr(u2);
        z1p = f4 - h2*v2 - h3*v1 - t12 - u0 - t13 - z2p*u2;
        z2 = f5 - h3*v2 - 2*u1 + u2*(u2 - 2*z3p);
        z1 = z1p - t13 + u2*u1 - u0;
        z0 = f3 - h2*v1 - h1*v2 - 2*v2*v1 - h3*v0 + u0*(u2 - 2*z3p) - z2p*u1 - z1p*u2;

        /* Step 4: */
        t12 = (inv1 + inv2)*(z1 + z2);
        t13 = z1*inv1;
        t14 = (inv0 + inv2)*(z0 + z2);
        t15 = z0*inv0;
        t16 = (inv0 + inv1)*(z0 + z1);
        t17 = z2*inv2;
        r0p = t15;
        r1p = t16 - t13 - t15;
        r2p = t13 + t14 - t15 - t17;
        r3p = t12 - t13 - t17;
        r4p = t17;
        t18 = u2*r4p - r3p;
        t15 = u0*t18;
        t16 = u1*r4p;
        s0p = r0p + t15;
        s1p = r1p - (u1+u0)*(r4p-t18) + t16 - t15;
        s2p = r2p - t16 + u2*t18;
        if(IsZero(s2p)){
            return add_cantor_g3(x, a, a);
        }

        /* Step 5: */
        w1 = 1/(r*s2p);
        w2 = w1*r;
        w3 = sqr(s2p)*w1;
        w4 = w2*r;
        w5 = sqr(w4);
        s0 = w2*s0p;
        s1 = w2*s1p;

        /* Step 6: */
        g0 = s0*u0;
        g1 = s1*u0 + s0*u1;
        g2 = s0*u2 + s1*u1 + u0;
        g3 = s1*u2 + s0 + u1;
        g4 = u2 + s1;

        /* Step 7: */
        u3p = 2*s1;
        u2p = sqr(s1) + 2*s0 + w4*h3;
        u1p = 2*s0*s1 + w4*(2*v2 + h3*s1 + h2 -h3*u2) - w5;
        u0p = w4*(2*v1 + h1 + h3*s0 - h3*u1 + 2*v2*s1 + u2*(u2*h3 - 2*v2 - h2 -s1*h3) + h2*s1);
        u0p = u0p + w5*(-f6 + 2*u2) + sqr(s0);

        /* Step 8: */
        t1 = u3p - g4;
        v3p = -(t1*u3p - u2p + g3)*w3 - h3;
        v2p = -(t1*u2p - u1p + g2)*w3 - h2 - v2;
        v1p = -(t1*u1p - u0p + g1)*w3 - h1 - v1;
        v0p = -(t1*u0p + g0)*w3 - h0 -v0;

        /* Step 9: */
        u2pp = f6 - u3p - sqr(v3p) - v3p*h3;
        u1pp = -u2p - u2pp*u3p + f5 - 2*v2p*v3p - v3p*h2 - v2p*h3;
        u0pp = -u1p - u2pp*u2p - u1pp*u3p + f4 - 2*v1p*v3p - sqr(v2p) - v2p*h2 - v3p*h1 - v1p*h3;

        /* Step 10: */
        v2pp = -v2p + (v3p + h3)*u2pp - h2;
        v1pp = -v1p + (v3p + h3)*u1pp - h1;
        v0pp = -v0p + (v3p + h3)*u0pp - h0;

        /* Step 11: */
        SetCoeff(upp, 3, 1);
        SetCoeff(upp, 2, u2pp);
        SetCoeff(upp, 1, u1pp);
        SetCoeff(upp, 0, u0pp);

        SetCoeff(vpp, 2, v2pp);
        SetCoeff(vpp, 1, v1pp);
        SetCoeff(vpp, 0, v0pp);

        x.set_upoly(upp);
        x.set_vpoly(vpp);
        x.update();

        assert(OK = OK && x.is_valid_divisor());
        return OK;

    }

    /* Wrap up the addition methods, so that the most common cases are handled by
    add_diff and doubling methods and for all other cases the addition is performed by
    Cantor's algorithm. */
    bool_t add(g3divisor& x, const g3divisor& a, const g3divisor& b) {
        bool_t OK = TRUE;

        /* Reduce overhead of checking with NDEBUG flag */
        assert(OK = OK && a.is_valid_divisor() && b.is_valid_divisor());

        if (deg(a.get_upoly()) == genus && deg(b.get_upoly()) == genus) {

            if (a == - b) {
                x.set_unit();
                OK = TRUE;
                return OK;
            }

            if (a != b && IsOne(GCD(a.get_upoly(), b.get_upoly()))) { 
                // Addition 
                OK = OK && add_diff(x, a, b);
                return OK;

            } else if (a == b && IsOne(GCD(a.get_curve().get_h() + 
                                    2*a.get_vpoly(), a.get_upoly())) ) { 
                // Doubling
                // Exclude the case when one point of the divisor is equal to 
                // its opposite

                OK = OK && doubling(x, a);
                return OK;
            }
        }

        OK = OK && add_cantor_g3(x, a, b);
        return OK;
    }

    bool_t scalar_mul(g3divisor& x, const g3divisor& a, const ZZ& n, 
                    bool_t (*method)(g3divisor&, const g3divisor&, const ZZ&))
    {
        bool_t (*op)(g3divisor&, const g3divisor&, const ZZ&) 
            = ( method == NULL ? SAM : method );

        return op(x, a, n);
    }
 

    bool_t scalar_mul(g3divisor& x, const g3divisor& a, long n, 
                    bool_t (*method)(g3divisor&, const g3divisor&, const ZZ&))
    {
        return scalar_mul(x, a, to_ZZ(n), method);
    }


    /* Supported scalar multiplication methods. From libg2hec */

    bool_t SAM(g3divisor& x, const g3divisor& a, const ZZ& n)
        // Square and multiply
        // cf. Pg 146, Alg. 9.1 of HOEHCC
    {
        assert(a.is_valid_divisor());

        bool_t OK = TRUE;

        long nbits;

        g3divisor b;

        if (n < 0) { // n < 0
            OK = OK && SAM(x, a, -n);
            OK = OK && dnegate_g3(x, x);
            return OK;
        }

        // n >= 0
        nbits = NumBits(n);
        b.set_unit(); // Set x = unit

        for( --nbits; nbits >= 0; --nbits) {
            OK = OK && add(b, b, b);

            if ( bit(n, nbits) ) 
            OK = OK && add(b, a, b);
        }

        assert(b.is_valid_divisor());

        x = b;  
        return OK;

    }

    bool_t NAF(g3divisor& x, const g3divisor& a, const ZZ& n)
    // Non-adjacent form
    // cf. Alg. 9.14 of HOEHCC
    {
        assert(a.is_valid_divisor());

        bool_t OK = TRUE;

        long nbits = NumBits(n), ibit;

        long c1, c2, n1, n2;

        g3divisor b;

        N_A_F naf;

        if ( !nbits ) { // n = 0
            x.set_unit();
            return OK;
        }

        if ( n < 0) {
            OK = OK && NAF(x, a, -n);
            OK = OK && dnegate_g3(x, x);
        } else {
            /* Get NAF first */

            c2 = 0;
            n2 = bit(n, 0);

            for ( ibit = 0; ibit <= nbits; ibit++ ){
                c1 = c2;
                n1 = n2;

                if (ibit == nbits -1 || ibit == nbits)
                    n2 = 0;
                else
                    n2 = bit(n, ibit + 1);

                c2 = (c1 + n1 + n2)/2;

                naf.set(ibit, c1 + n1 - 2*c2);

            }

            /* Use NAF for computation */
            b.set_unit();

            for ( ibit = nbits; OK && ibit >= 0; --ibit ) {
                OK = OK && add(b, b, b);

                if (naf.get(ibit) == 1)
                    OK = OK && add(b, b, a); // b = a + b
                else if (naf.get(ibit) == -1)
                    OK = OK && sub(b, b, a); // b = b - a
                // Do nothing otherwise

            } //endfor ibit

            assert(b.is_valid_divisor());

            x = b;

        }

        return OK;

    }

    bool_t ML(g3divisor& x, const g3divisor& a, const ZZ& n)
        // Montgomery's ladder: used to defend side channel attacks
        // cf. Alg. 13.35 of HOEHCC
    {
        assert(a.is_valid_divisor());

        bool_t OK = TRUE;

        long nbits = NumBits(n);

        g3divisor b1, b2;


        if ( !nbits ) { // n = 0
            x.set_unit();
            return OK;
        }

        if ( n < 0) {
            OK = OK && ML(x, a, -n);
            OK = OK && dnegate_g3(x, x);
            return OK;
        }

        // Case n > 0
        b1 = a; b2 = a + a;     
        for ( --nbits; OK && nbits > 0; --nbits) {
            if ( !bit(n, nbits - 1) ) {
            OK = OK && add(b2, b1, b2); // b2 = b1 + b2
            OK = OK && add(b1, b1, b1); // b1 = [2]*b1

            } else { 
            OK = OK && add(b1, b1, b2); // b1 = b1 + b2;
            OK = OK && add(b2, b2, b2); // b2 = [2]*b2;

            assert(OK);  

            }

        }

        assert(b1.is_valid_divisor());
        x = b1;

        return OK;

    }

    bool_t sub(g3divisor& x, const g3divisor& a, const g3divisor& b)
    {
        g3divisor c;
        return ( dnegate_g3(c, b) && add(x, a, c) );
    }

    void g3hcurve :: set_f (const poly_tc& poly) 
    {
        fpoly = poly;
    }

    void g3hcurve :: set_h (const poly_tc& poly)
    {
        hpoly = poly;
    }

    void g3hcurve :: update ()
    {
        //Set is_genus_3
        if( deg(fpoly) == 7 && deg(hpoly) <= 3)
            is_genus_3 = TRUE;
        else
            is_genus_3 = FALSE;
        
        // Set is_nonsingular
        /* Curve y^2 + h(x)*y = f(x) is nonsingular if and only if
        no point on the curve over alg closure satisfies 
        (1) 2*y + h(x) = 0 and (2) f' - h'*y = 0.
        For odd characteristic, this means the function 
            f(x) + ( h(x)/2 )^2 
        has no multiple root.

        For characteristic 2, this requires h(x) <> 0 (c.f. Example 14.9 of 
        HOEHCC). It is not supported.
        */
        #if ( _FLD_TYPE == ZZ_p ) || (  _FLD_TYPE == ZZ_pE )
        do {
            poly_t testpoly = fpoly + hpoly*hpoly/4, testpoly_diff;

            // testpoly_diff = testpoly's derivative
            diff(testpoly_diff, testpoly);

            is_nonsingular = IsOne( GCD(testpoly, testpoly_diff) );

        } while (0);
        #elif ( _FLD_TYPE == GF2 ) || ( _FLD_TYPE == GF2E )
            #error "Characteristic 2 not yet supported"

        #else
            #error "Unsupported field type"

        #endif
    }

    const poly_tc& g3hcurve :: get_f() const 
    {
        return fpoly;
    }

    const poly_tc& g3hcurve :: get_h() const
    {
        return hpoly;
    }

    bool_t g3hcurve :: is_valid_curve() const
    {
    /* Returns TRUE only if curve is nonsingular, of genus 3 and
    has leading coefficient 1
    */
        return (is_nonsingular && is_genus_3 && IsOne(LeadCoeff(fpoly)));
    }

    g3hcurve& g3hcurve :: random()
    {
        // Set number of trials to 100. This should suffice most of the time.

        for (long ntrial = 100; ntrial > 0; ntrial--) {
            NTL_NNS random(fpoly, 8);
            SetCoeff(fpoly, 7, 1); // Make sure of degree 5 and monic
            NTL_NNS random(hpoly, 4);
            update();

            if (is_valid_curve())
                return *this;
        }
        
        cerr << "Random genus 3 curve not generated" << endl;
        abort();
    }

    std::ostream& operator<<(std::ostream& s, const g3hcurve& a)
    {
        s << "Curve: y^2 + h(x)*y = f(x)" << endl;

        // print h(x)
        s << "       h(x) = ";

        print_poly(a.get_h(), &s);

        // Print f(x)
        s << "       f(x) = ";

        print_poly(a.get_f(), &s);


        // Print curve info
        if (a.is_valid_curve())
            s << "       Genus 3 curve is nonsingular" << endl;
        else
            s << "       Curve is singular, or not genus 3, or f(x) is not monic" 
            << endl;
        return s;
    }

    g3hcurve my_curve;
    g3hcurve g3divisor::curve_g3 = my_curve;

    void g3divisor::update() {
        bool_t OK = TRUE;

        OK = OK && curve_g3.is_valid_curve();

        /* Check if [u, v] belongs to Jacobian of genus 3 curve
            It is so if
            (1) u is monic
            (2) deg(v) < deg(u) <= genus = 3
            (3) u | v^2 + v*h - f
        */
        OK = OK && IsOne( LeadCoeff(upoly) ); // (1)

        OK = OK && ( deg(upoly) <= genus ) && ( deg(vpoly) < deg(upoly) ); // (2)

        OK = OK && IsZero(( vpoly*(vpoly + curve_g3.get_h()) 
                            - curve_g3.get_f() ) % upoly ); // (3)
        // Set is_valid flag
        is_valid = OK;    
           
    }

    bool_t g3divisor::is_valid_divisor() const {
        return is_valid;
    }

    bool_t g3divisor::is_unit(){
        assert(is_valid); // Invalid divisor is checked runtime error

        return ( IsOne(upoly) && IsZero(vpoly) );
    }

    void g3divisor::set_unit() {
        assert(curve_g3.is_valid_curve()); // Invalid curve is checked runtime error

        clear(vpoly); // vpoly = 0
        set(upoly); // upoly = 1
        update();
    }

    g3divisor& g3divisor::random() {
        assert(curve_g3.is_valid_curve());

        // A random valid divisor is generated by the following algorithm:
        // generate a degree 1 divisor [x - a1, b1] by choosing a1 by random
        // then trying to solve quadratic equation
        // x^2 + h(a1)*x - f(a1) for b1.
        // Note that finding a root of an equation by calling routine
        // FindRoot(root, poly) may go into an infinite loop if poly does
        // not split completely.  We avoid this by calling irreducibility 
        // test routine DetIrredTest(poly).  After a degree 1 divisor is
        // found, this divisor is doubled by calling add_cantor() to return
        // a degree 3 polynomial.

        field_t a1, b1, f_of_a1, h_of_a1;

        poly_t poly;  // polynomial x^2 + h(a1)*x - f(a1)

        SetCoeff(poly, 2); // set degree 2 leading term to 1

        do {
            do{
                NTL_NNS random(a1);

                eval(f_of_a1, curve_g3.get_f(), a1);

                eval(h_of_a1, curve_g3.get_h(), a1);

                SetCoeff(poly, 1, h_of_a1);
                SetCoeff(poly, 0, - f_of_a1);

            } while ( DetIrredTest(poly) );

            FindRoot(b1, poly);

            // Set upoly = x - a1
            SetX(upoly);
            SetCoeff(upoly, 0, -a1);

            // Set vpoly = b1
            vpoly = b1;

            update();
        } while (*this == -*this); // Avoid getting unit after doubling


        // Compute [3]D, where D is the divisor [x-a1, y]
        g3divisor x;
        add_cantor_g3(x, *this, *this);
        add_cantor_g3(*this, *this, x);

        if (is_valid_divisor())
            return *this;

        cerr << "Random divisor failed to generate" << endl;
        abort();

    }

    std::ostream& operator<<(std::ostream& s, const g3divisor& a)
    {
        s << "###" << endl;

        s << "Divisor [u(x), v(x)] for Jacobian group of curve y^2 + h(x)*y = f(x)." 
        << endl;

        // print curve info
        s << a.get_curve();

        // print u, v
        s << "[u(x), v(x)]:" << endl;

        s << "       u(x) = ";

        print_poly(a.get_upoly(), &s);

        s << "       v(x) = ";
        print_poly(a.get_vpoly(), &s); 

        // Is divisor valid?
        if (a.is_valid_divisor())
        s << "       Divisor is valid" << endl;
        else
        s << "       Divisor is invalid" << endl;

        s << "###" << endl;

        return s;
    }
}

// int main() {
//     /* Set PRNG seed */
//   SetSeed(to_ZZ(19800729));

//   char p[300];

//   cout << "Please choose your modulus p (up to " 
//        << 300 << " decimal digits):" << endl;
//   cout << "p = ";
//   cin.getline(p, 300);

//   ZZ pZZ = to_ZZ(p);

//   field_t::init(pZZ); // define GF(p)

//   ZZ x, k;

//   g3HEC::g3hcurve curve;

//   g3HEC::g3divisor m, g, h, a, b;

//   curve.random();

//    /* private key x */
//   RandomBnd(x, pZZ*pZZ);
//    /* random number k */
//   RandomBnd(k, pZZ*pZZ);

//   m.set_curve(curve);
//    /* random message m as divisor */
//   m.random();

//   std::cout << m << std::endl;
//    /* random base point */
//   g.random();

//    /* public key h */
//   h = x * g;

//    /* cipher text (a, b) */
//   a = k * g;
//   b = k * h + m;

//   /* message decryption  */

//   if ( b - x * a == m )
//     cout << "ElGamal decryption succeeded!" << endl;
//   else
//     cout << "ElGamal decryption failed!" << endl;

//    return 0;
    
// }