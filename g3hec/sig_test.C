
#include "g3hec_ops.h"
#include <unistd.h>

#include <NTL/pair.h>
#include <NTL/vector.h>

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
  temp = AddMod(temp, rep(u.rep[2]), n);
  return ( IsZero(temp) ? to_ZZ(1) : temp );
}

int main() 
{
  /* Set PRNG seed */
  SetSeed(to_ZZ(1234567890));

  /* Set prime */
  ZZ p = to_ZZ(ps);

  field_t::init(p); // define GF(p)

  std::cout << "Size of p: " << NumBytes(p) << " bytes" << std::endl;
  

  ZZ order = to_ZZ(N);
  std::cout << "Size of group: " << NumBytes(order) << " bytes" << std::endl;

  ZZ x, k, b, m; // Private key x, random number k, parameter b, message m

  ZZ f_a;

  g3hcurve curve;

  g3divisor g, h, a;

  poly_t f;

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

  /* Base point g */
  do {
    g.random();
  } while (g.is_unit());

  /* message m */
  RandomBnd(m, order);

  /* private key x <> 0 */
  do {
    RandomBnd(x, order);
  } while (IsZero(x));

  /* public key h = [x]g */
  h = x * g;

  /* random number k <> 0*/
  do {
    RandomBnd(k, order);
  } while (IsZero(k));

  cout << "Generating ElGmal signature..." << endl;
  sleep(3);

  a = k * g;

  f_a = from_divisor_to_ZZ(a, order);

  /* b = (m - x*f(a))/k mod N */
  b = MulMod(m - x * f_a, InvMod(k, order), order);

  cout << "ElGmal signature generated!" << endl;
  sleep(3);

  /* Signature verification */
  if ( f_a * h + b * a == m * g )
    cout << "ElGamal signature verification succeeded!" << endl;
  else
    cout << "ElGamal signature verification failed!" << endl;

   return 0;
}
