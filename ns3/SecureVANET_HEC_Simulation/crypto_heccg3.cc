#include "crypto_heccg3.h"
#include "helpers.h"

/* --------------------------- Serialize helper --------------------------- */


void serialize_generic(g3divisor D, vector<unsigned char> &buff, g3hcurve crv, ZZ p)
{
    int size = NTL::NumBytes(p);
    
    /* Get divisor polys */
    poly_t u = D.get_upoly();
    poly_t v = D.get_vpoly();

    /* u and v poly coefficients to bytes */
    ZZ_p u2, u1, u0;
    GetCoeff(u2, u, 2);
    GetCoeff(u1, u, 1);
    GetCoeff(u0, u, 0);
    ZZ_p v2, v1, v0;
    GetCoeff(v2, v, 2);
    GetCoeff(v1, v, 1);
    GetCoeff(v0, v, 0);

    uint8_t *u2z, *u1z, *u0z;
    u2z = new uint8_t[size];
    NTL::BytesFromZZ(u2z, rep(u2), size);
    u1z = new uint8_t[size];
    NTL::BytesFromZZ(u1z, rep(u1), size);
    u0z = new uint8_t[size];
    NTL::BytesFromZZ(u0z, rep(u0), size);

    buff.insert(buff.end(), u2z, u2z+size);
    buff.insert(buff.end(), u1z, u1z+size);
    buff.insert(buff.end(), u0z, u0z+size);

    /* No compression is used so v coefficients are all stored */
    uint8_t *v2z, *v1z, *v0z;
    v2z = new uint8_t[size];
    NTL::BytesFromZZ(v2z, rep(v2), size);
    v1z = new uint8_t[size];
    NTL::BytesFromZZ(v1z, rep(v1), size);
    v0z = new uint8_t[size];
    NTL::BytesFromZZ(v0z, rep(v0), size);

    buff.insert(buff.end(), v2z, v2z+size);
    buff.insert(buff.end(), v1z, v1z+size);
    buff.insert(buff.end(), v0z, v0z+size);
}


g3divisor deserialize_generic(vector<unsigned char> buff, g3hcurve crv, ZZ p)
{
    int size = NTL::NumBytes(p);

    ZZ u2, u1, u0, v2, v1, v0;
    u2 = NTL::ZZFromBytes(buff.data(), size);
    u1 = NTL::ZZFromBytes(buff.data()+size, size);
    u0 = NTL::ZZFromBytes(buff.data()+2*size, size);

    v2 = NTL::ZZFromBytes(buff.data()+3*size, size);
    v1 = NTL::ZZFromBytes(buff.data()+4*size, size);
    v0 = NTL::ZZFromBytes(buff.data()+5*size, size);
    poly_t u,v;
    SetCoeff(u,3,1);
    SetCoeff(u,2,to_ZZ_p(u2));
    SetCoeff(u,1,to_ZZ_p(u1));
    SetCoeff(u,0,to_ZZ_p(u0));

    SetCoeff(v,2,to_ZZ_p(v2));
    SetCoeff(v,1,to_ZZ_p(v1));
    SetCoeff(v,0,to_ZZ_p(v0));

    g3divisor D;
    D.set_curve(crv);
    D.set_upoly(u);
    D.set_vpoly(v);
    D.update();
    return D;
}


/* --------------------------- Crypto HECC genus 3 methods --------------------------- */


tuple<g3divisor, g3divisor> CryptoHECCg3::encrypt_ElGamal(g3divisor pub, g3divisor mess)
{
    ZZ k;
    RandomBnd(k, p*p*p);
    g3divisor a = k * base;
    g3divisor b = k * pub + mess;
    return tuple<g3divisor, g3divisor>(a, b);
}

g3divisor CryptoHECCg3::decrypt_ElGamal(ZZ priv, g3divisor a, g3divisor b)
{
    return (b - priv * a);
}

g3divisor CryptoHECCg3::points_to_divisor(ZZ_p x1, ZZ_p y1, ZZ_p x2, ZZ_p y2, ZZ_p x3, ZZ_p y3)
{
    g3divisor D;
    ZZ_p a,b,c;
    a = -x1-x2-x3;
    b = x1*x2 + x1*x3 + x2*x3;
    c = -x1*x2*x3;

    poly_t u,v;
    SetCoeff(u, 3, 1);
    SetCoeff(u, 2, a);
    SetCoeff(u, 1, b);
    SetCoeff(u, 0, c);

    ZZ_p e = ((y2-y3)*(x1*x1 - x2*x2) - (y1-y2)*(x2*x2 - x3*x3))/((x2-x3)*(x1*x1 - x2*x2) - (x1-x2)*(x2*x2 - x3*x3));
    ZZ_p d = (y1 - y2 - e*(x1-x2))/(x1*x1 - x2*x2);
    ZZ_p f = y3 - e*x3 - d*x3*x3;
    SetCoeff(v, 2, d);
    SetCoeff(v, 1, e);
    SetCoeff(v, 0, f);

    D.set_curve(curve);
    D.set_upoly(u);
    D.set_vpoly(v);
    D.update();
    return D;
}

void CryptoHECCg3::divisor_to_points (g3divisor D, ZZ_p &x1, ZZ_p &y1, ZZ_p &x2, ZZ_p &y2, ZZ_p &x3, ZZ_p &y3)
{
    poly_t u, v;
    u = D.get_upoly();
    v = D.get_vpoly();

    if(DetIrredTest(u)) {
        throw std::runtime_error("Irreducible polyonym u for converting divisor to points.");
    }

    vec_ZZ_p roots = FindRoots(u);
    x1 = roots[0];
    x2 = roots[1];
    x3 = roots[2];

    ZZ_p d,e,f;
    y1 = eval(v, x1);
    y2 = eval(v, x2);
    y3 = eval(v, x3);
}

g3divisor CryptoHECCg3::encode(string txt)
{
    int maxlen = MAX_ENCODING_LEN_G3;
    int len = txt.length();
    UnifiedEncoding enc(p, u_param, w_param, 3);

    if(len > maxlen) {
        throw std::runtime_error("Length of text to be encoded must be at maximum SIZE-4 bytes");
    }

    /* Pad the message to maxlen size with zeros-null bytes */
    uint8_t chk[maxlen];
    memcpy(chk, txt.c_str(), len);
    for(int i =0; i < maxlen - len; i++) {
        chk[maxlen-1-i] = '\0';
    }
    ZZ chkzz = NTL::ZZFromBytes(chk, len);
    
    /* Split the message in three equal parts and set the first bytes as 1,2 and 3 to distinguish the correct order of the text parts */
    uint8_t *str1, *str2, *str3;
    ZZ msgzz1, msgzz2, msgzz3;
    str1 = new uint8_t [maxlen/3+1];
    str2 = new uint8_t [maxlen/3+1];
    str3 = new uint8_t [maxlen/3+1];
    str1[0] = '1';
    memcpy(str1+1, chk, maxlen/3);
    str2[0] = '2';
    memcpy(str2+1, chk + maxlen/3, maxlen/3);
    str3[0] = '3';
    memcpy(str3+1, chk + 2*maxlen/3, maxlen/3);

    /* Convert text to ZZ type */
    msgzz1 = NTL::ZZFromBytes(str1, maxlen/3+1);
    msgzz2 = NTL::ZZFromBytes(str2, maxlen/3+1);
    msgzz3 = NTL::ZZFromBytes(str3, maxlen/3+1);

    if(msgzz1 >= p || msgzz2 >= p || msgzz3 >=p) {
        throw std::runtime_error("Message too big to encode. Please segment the message.");
    }
   
    /* Encode ZZs to HEC points using the UnifiedEncoding method */
    ZZ_p x1, y1, x2, y2, x3, y3;
    curve = enc.getcurveg3();

    int fl = enc.encode(msgzz1, x1, y1);
    if(fl) {
        throw std::runtime_error("Could not encode message to HEC point");
    }

    fl = enc.encode(msgzz2, x2, y2);

    if(fl){
        throw std::runtime_error("Could not encode message to HEC point");
    }

    fl = enc.encode(msgzz3, x3, y3);

    if(fl){
        throw std::runtime_error("Could not encode message to HEC point");
    }

    g3divisor D = points_to_divisorg3(x1, y1, x2, y2, x3, y3, curve);
    free(str1);
    free(str2);
    free(str3);

    return D;
}

string CryptoHECCg3::decode(g3divisor D)
{
    int maxlen = MAX_ENCODING_LEN_G3;
    UnifiedEncoding enc(p, u_param, w_param, 3);

    /* Zero buffer for error checking the ret value of find_string */
    uint8_t *zer = new uint8_t[maxlen/3+1];
    memset(zer, '0', maxlen/3+1);

    /* Convert divisor to points in the HEC */
    ZZ_p x1, y1, x2, y2, x3, y3;
    divisor_to_points(D, x1, y1, x2, y2, x3, y3);
    
    /* Decode each point to 2 values, find_string is used to determine which one is the correct one */
    ZZ_p val1, val2, val3, val4, val5, val6;
    int fl = enc.decode(val1, val2, x1, y1);
    fl = enc.decode(val3, val4, x2, y2);
    fl = enc.decode(val5, val6, x3, y3);

    if(fl) {
        throw std::runtime_error("Could not decode points");
    }

    /* Find the correct string from the first point. A pointer to a uint8_t buffer is returned */
    /* find_string is not safe to use. Needs to be refactored to use vectors */
    uint8_t *str1;

    str1 = find_string(val1, val2, maxlen/3+1, 1);

    if(memcmp(str1, zer, maxlen/3+1) == 0) {
        throw std::runtime_error("Could not find string");
    }

    uint8_t *str2;

    str2 = find_string(val3, val4, maxlen/3+1, 1);

    if(memcmp(str2, zer, maxlen/3+1) == 0) {
        throw std::runtime_error("Could not find string");
    }

    uint8_t *str3;

    str3 = find_string(val5, val6, maxlen/3+1, 1);

    if(memcmp(str3, zer, maxlen/3+1) == 0) {
        throw std::runtime_error("Could not find string");
    }

    /* After finding the correct strings, each first byte is either 1 or 2 indicating the order 
    they should be placed */
    int p1, p2, p3;
    p1 = str1[0] - 49;
    p2 = str2[0] - 49;
    p3 = str3[0] - 49;

    if(p1 != 1 && p1 != 2 && p1 != 3)
        throw std::runtime_error("Valid string was not found.");
    
    if(p2 != 1 && p2 != 2 && p2 != 3)
        throw std::runtime_error("Valid string was not found.");

    if(p3 != 1 && p3 != 2 && p3 != 3)
        throw std::runtime_error("Valid string was not found.");
    
    uint8_t *ret = new uint8_t[maxlen+1];
    memcpy(ret+p1*maxlen/3, str1+1, maxlen/3);
    memcpy(ret+p2*maxlen/3, str2+1, maxlen/3);
    memcpy(ret+p3*maxlen/3, str3+1, maxlen/3);
    ret[maxlen] = '\0';

    string txt = (char*)ret;

    free(zer);
    free(str1);
    free(str2);
    free(str3);
    
    return txt;
}

ZZ CryptoHECCg3::from_divisor_to_ZZ(const g3divisor& div, const ZZ& n)
{
    poly_t u = div.get_upoly();
    ZZ temp = AddMod(sqr(rep(u.rep[0])), sqr(rep(u.rep[1])), n);
    temp = AddMod(temp, sqr(rep(u.rep[2])), n);
    return ( IsZero(temp) ? to_ZZ(1) : temp );
}

void CryptoHECCg3::serialize(g3divisor D, vector<unsigned char> &buff)
{
    serialize_generic(D, buff, this->curve, this->p);
}

g3divisor CryptoHECCg3::deserialize(vector<unsigned char> buff)
{
    return deserialize_generic(buff, this->curve, this->p);
}

string CryptoHECCg3::sign(ZZ priv, vector<unsigned char> mess)
{
    /* Save the NTL field context, because arithmetic here is done on a different field */
    NTL::ZZ_pContext context;
    context.save();

    /* Calculate hash digest */
    hash.Update(mess.data(), mess.size());
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);
    
    /* Convert hash digest to ZZ big integer of 28 bytes (224 bits) */
    ZZ m;
    m = ZZFromBytes((unsigned char*)digest.data(), 28);
    
    /* Initialize NTL field */
    SetSeed(to_ZZ(1234567890));
    ZZ p = to_ZZ(psign3); 
    field_t::init(p); 

    /* The Group Order is an almost prime - 8q where q is a prime. So the order to be
    used in arithmetic is the order/8 */
    ZZ order = to_ZZ(Nsign3)/8;
    int order_size = NTL::NumBytes(order);

    // Private key x, random number k, parameter b, message m
    ZZ x, k; 

    // f(a), bijection of divisor a to ZZ
    ZZ f_a;

    // The signature curve
    g3hcurve crv;
    
    // The divisor a of the signature, the base element g, the public key h
    g3divisor g, h, a;

    // Construct the f polyonym of the curve
    poly_t f;

    SetCoeff(f, 7, 1);
    SetCoeff(f, 6, 0);
    SetCoeff(f, 5, str_to_ZZ_p(f5g3));
    SetCoeff(f, 4, 0);
    SetCoeff(f, 3, str_to_ZZ_p(f3g3));
    SetCoeff(f, 2, 0);
    SetCoeff(f, 1, str_to_ZZ_p(f1g3));
    SetCoeff(f, 0, 0);

    /* Construct the curve */
    crv.set_f(f);
    crv.update();

    /* Construct the base element that produces the Group Order of q */
    g.set_curve(crv);
    poly_t gu, gv;
    SetCoeff(gu, 3, 1);
    SetCoeff(gu, 2, str_to_ZZ_p(gu2g3));
    SetCoeff(gu, 1, str_to_ZZ_p(gu1g3));
    SetCoeff(gu, 0, str_to_ZZ_p(gu0g3));
    SetCoeff(gv, 2, str_to_ZZ_p(gv2g3));
    SetCoeff(gv, 1, str_to_ZZ_p(gv1g3));
    SetCoeff(gv, 0, str_to_ZZ_p(gv0g3));
    g.set_upoly(gu);
    g.set_vpoly(gv);
    g.update();

    /* private key x <> 0 */
    x = to_ZZ(priv_g3);

    /* The public key */
    h = x * g;

    /* random number k <> 0*/
    do {
        RandomBnd(k, order);
    } while (IsZero(k));

    /* Divisor a of the signature */
    a = k * g;

    /* f(a) */
    f_a = from_divisor_to_ZZ(a, order);

    /* ZZ b = (m - x*f(a))/k mod N of the signature */
    ZZ b = ((m - x*f_a)*InvMod(k, order))%order;
    
    /* Signature verification */
    if ( f_a * h + b * a == m * g ) {
        vector<unsigned char> sig;
        serialize_generic(a, sig, crv, p);

        byte bsig[order_size];
        BytesFromZZ(bsig, b, order_size);
        sig.insert(sig.end(), bsig, bsig+order_size);

        string ret((char*)sig.data(), sig.size());

        context.restore();
        return ret;
    }
    else { 
        throw std::runtime_error("Could not create signature on message");
    }
}


bool CryptoHECCg3::verify(string sig, g3divisor Pk, vector<unsigned char> mess)
{
    /* Save the NTL field context, because arithmetic here is done on a different field */
    NTL::ZZ_pContext context;
    context.save();
    
    /* Calculate hash digest */
    hash.Update(mess.data(), mess.size());
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);
    
    /* Convert hash digest to ZZ big integer of 28 bytes (224 bits) */
    ZZ m;
    m = ZZFromBytes((unsigned char*)digest.data(), 28);
    
    /* Initialize NTL field */
    SetSeed(to_ZZ(1234567890));
    ZZ p = to_ZZ(psign3); 
    field_t::init(p); 
    ZZ order = to_ZZ(Nsign3)/8;
    int order_size = NTL::NumBytes(order);

    // Private key x
    ZZ x;

    // f(a), bijection of divisor a to ZZ
    ZZ f_a;

    // The signature curve
    g3hcurve crv;

    // The divisor a of the signature, the base element g, the public key h
    g3divisor g, h, a;

    // Construct the f polyonym of the curve
    poly_t f;

    SetCoeff(f, 7, 1);
    SetCoeff(f, 6, 0);
    SetCoeff(f, 5, str_to_ZZ_p(f5g3));
    SetCoeff(f, 4, 0);
    SetCoeff(f, 3, str_to_ZZ_p(f3g3));
    SetCoeff(f, 2, 0);
    SetCoeff(f, 1, str_to_ZZ_p(f1g3));
    SetCoeff(f, 0, 0);

    /* Construct the curve */
    crv.set_f(f);
    crv.update();

    /* Construct the base element */
    g.set_curve(curve);
    poly_t gu, gv;
    SetCoeff(gu, 3, 1);
    SetCoeff(gu, 2, str_to_ZZ_p(gu2g3));
    SetCoeff(gu, 1, str_to_ZZ_p(gu1g3));
    SetCoeff(gu, 0, str_to_ZZ_p(gu0g3));
    SetCoeff(gv, 2, str_to_ZZ_p(gv2g3));
    SetCoeff(gv, 1, str_to_ZZ_p(gv1g3));
    SetCoeff(gv, 0, str_to_ZZ_p(gv0g3));
    g.set_upoly(gu);
    g.set_vpoly(gv);
    g.update();

    /* Extract a divisor and b big integer of the signature */
    vector<unsigned char> siga(sig.begin(), sig.end()-order_size);
    byte sigb[order_size];
    memcpy(sigb, sig.data()+sig.size()-order_size, order_size);

    a = deserialize_generic(siga, crv, p);
    ZZ b = ZZFromBytes(sigb, order_size);

    /* Reconstruct the public key from the private key for simulation purposes */
    x = to_ZZ(priv_g3);
    h = x*g;

    f_a = from_divisor_to_ZZ(a, order);

    if ( f_a * h + b * a == m * g ) {
        context.restore();
        return true;
    }
    else {
        cout << "ElGamal signature verification did not succeed!" << endl;
        context.restore();
        return false;
    }
}