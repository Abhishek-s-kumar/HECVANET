
#include "g3hec_ops.h"
#include <unistd.h>

#include <NTL/pair.h>
#include <NTL/vector.h>

/* Based on "A class of hyperelliptic CM-curves of genus three" by Annegret Weng*/
#define f5 "7"
#define f3 "14"
#define f1 "7"
#define ps "123456776543211236173"
#define N "1881675801864379891114339535564538805274692594768590688211848"

#define str_to_ZZ_p(x) to_ZZ_p(to_ZZ(x))

using namespace g3HEC;

/* An almost bijection from Jacobian to {1, 2, ..., n-1} 
 * which maps [u(x), v(x)] to u0^2 + u1^2 + u2^2 mod n.
*/
static ZZ from_divisor_to_ZZ(const g3divisor& div, const ZZ& n)
{
  poly_t u = div.get_upoly();
  ZZ temp = AddMod(sqr(rep(u.rep[0])), sqr(rep(u.rep[1])), n);
  temp = AddMod(temp, sqr(rep(u.rep[2])), n);
  return ( IsZero(temp) ? to_ZZ(1) : temp );
}

int main() 
{
  /* Set PRNG seed */
  SetSeed(to_ZZ(1234567890));

  /* Set prime */
  ZZ p = to_ZZ(ps);

  field_t::init(p); // define GF(p)

  std::cout << "Size of p: " << NumBits(p) << " bits" << std::endl;
  
  /* N is an "almost" prime (8q where q is a prime). The order is set to N/8 */
  ZZ order = to_ZZ(N);
  order = order/8;
  std::cout << "Size of group: " << NumBits(order) << " bits" << std::endl;

  ZZ x, r, s, m; // Private key x, random number r, parameter s, message m

  ZZ f_e; // f(e) from divisor to ZZ

  g3hcurve curve;

  g3divisor g, h, e; // Base divisor g, public key h, divisor e

  poly_t f;

  /* Set the genus three curve of known almost prime order */
  SetCoeff(f, 7, 1);
  SetCoeff(f, 6, 0);
  SetCoeff(f, 5, str_to_ZZ_p(f5));
  SetCoeff(f, 4, 0);
  SetCoeff(f, 3, str_to_ZZ_p(f3));
  SetCoeff(f, 2, 0);
  SetCoeff(f, 1, str_to_ZZ_p(f1));
  SetCoeff(f, 0, 0);
  curve.set_f(f);
  curve.update();

  g.set_curve(curve);

  /* Base point g. It is mandatory for g to generate a Group of order elements. */
  do {
    g.random();
  } while (g.is_unit() || !(g*order).is_unit());

  /* message m */
  RandomBnd(m, order);

  /* private key x <> 0 */
  do {
    RandomBnd(x, order);
  } while (IsZero(x));

  /* random number r <> 0*/
  do {
    RandomBnd(r, order);
  } while (IsZero(r));

  cout << "Generating HECC ElGamal signature..." << endl;

  e = r * g;
  h = x*g;

  f_e = from_divisor_to_ZZ(e, order);

  /* Using MulMod here for faster calculation seems to have a bug. Need to investigate. */
  s = ((m - x*f_e)*InvMod(r, order))%order;

  cout << "HECC ElGamal signature generated!" << endl;
  
  /* Signature verification */
  if ( f_e*h + s*e == m*g )
    cout << "HECC ElGamal signature verification succeeded!" << endl;
  else
    cout << "HECC ElGamal signature verification failed!" << endl;

   return 0;
}