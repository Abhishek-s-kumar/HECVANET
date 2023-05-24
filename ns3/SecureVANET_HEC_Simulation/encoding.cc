#include "encoding.h"

void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
}

void swap_endian(uint8_t* buffer, size_t size) {
    size_t i = 0;
    size_t j = size - 1;
    while (i < j) {
        uint8_t tmp = buffer[i];
        buffer[i] = buffer[j];
        buffer[j] = tmp;
        i++;
        j--;
    }
}

ZZ_p squareRoot(ZZ_p n, ZZ p)
{
    if (p % 4 != 3) {
        cout << "Invalid Input";
        return to_ZZ_p(to_ZZ(0));
    }

    bool ok1 = false;
 
    ZZ_p x1 = power(n, (p + 1) / 4);
    if ((x1 * x1) == n) {
        //cout << "Square root is " << x;
        ok1 = true;
    }
 
    // Try "-(n ^ ((p + 1)/4))"
    ZZ_p x2 = - x1;
    if(ok1 && rep(x1) < rep(x2))
        return x1;

    if ((x2 * x2) == n) {
        //cout << "Square root is " << x; 
        return x2;
    }

    return to_ZZ_p(to_ZZ(0));
 
    // If none of the above two work, then
    // square root doesn't exist
    //cout << "Square root doesn't exist ";
}



UnifiedEncoding::UnifiedEncoding(ZZ p, int u, int w, int g, ZZ_p s) {
    this->inu = u;
    this->inw = w;
    this->ing = g;
    this->p = p;
    field_t::init(p);
    this->u = to_ZZ_p(to_ZZ(u));
    this->w = to_ZZ_p(to_ZZ(w));
    this->s = s;
    this->g = to_ZZ(g);
    this->alpha_g = to_ZZ(pow(2, (2*g - 1)) - 1);
    this->beta_g = 4*g*g + 2*g;
    this->gamma_g = pow((2*g*g+g), 2);
    if(this->g%2 == 0) {
        this->mg = (this->alpha_g*this->beta_g)/4;
    }
    else {
        this->mg = (this->alpha_g*this->beta_g)/2;
    }

    if(this->g%2 == 0) {
        this->ng = pow((2*g*g+g),2)/2;
    }
    else {
        this->ng = pow((2*g*g+g),2);
    }
    checkParams();
    checkSParam();
    create_curve();
}

void UnifiedEncoding::checkParams() {
    if(p%2 == 0 || (2*g*g +g)%p == 0) {
        std::cout << "Error:\n\tWrong input for field characteristic p!" << std::endl;
        exit(1);
    }
    if(p%8 != 7) {
        std::cout << "Error:\n\tField q is not 7 modulo 8!" << std::endl;
        exit(1);
    }
    if(w==0 || u==0) {
        std::cout << "Error:\n\tu or w is zero!" << std::endl;
        exit(1); 
    }
    ZZ_p check = squareRoot(u, p);
    if(check != 0) {
        std::cout << "Error:\n\tu is a square!" << std::endl;
        exit(1);
    }
    if(g >= 6){
        std::cout << "Error:\n\tGenus out of range!" << std::endl;
        exit(1);
    }
}

void UnifiedEncoding::checkSParam() {
    if (s==0) {
        if(alpha_g%p == 0)
            s = to_ZZ_p(gamma_g/beta_g);
        else {
            ZZ_p delta_s = to_ZZ_p(beta_g*beta_g + 4*alpha_g*gamma_g);
            s = (-to_ZZ_p(beta_g)+squareRoot(delta_s, p))/(to_ZZ_p(2*alpha_g));
        }
    }
}

int UnifiedEncoding::isquadratic(ZZ_p a){
    if(a == 0)
        return 0;
    else if(squareRoot(a, p) != 0)
        return 1;
    else 
        return -1;
}

void UnifiedEncoding::create_curve() {
    ZZ_p a0, a2g, a1, a3;
    a0 = (s-(to_ZZ_p(2*g*g +g)))/(to_ZZ_p(2*g*g+g));
    a0 = a0*pow(inw, 2*ing+1);
    a2g = s*w*w;
    a1 = (s*pow(inw, 2*ing))/to_ZZ_p(g);
    SetCoeff(fpoly1, 0, a0);
    SetCoeff(fpoly1, 1, a1);
    SetCoeff(fpoly1, 2*ing-1, a2g);
    if(ing == 3) {
        a3 = ((2*ing-1)*s*w*w*w*w)/3;
        SetCoeff(fpoly1, 3, a3);
    }
    SetCoeff(fpoly1, 2*ing+1, 1);
    if(ing == 2) {
        curve2.set_f(fpoly1);
        curve2.update();
    }
    if(ing == 3) {
        curve3.set_f(fpoly1);
        curve3.update();
    }
} 

int UnifiedEncoding::encode(ZZ val, ZZ_p &x, ZZ_p &y) {
    ZZ_p r = to_ZZ_p(val);
    ZZ_p check = eval(fpoly1, r);
    if(check == 0) {
        std::cout << "Value: " << r << "is not in the supported range, maybe increase by 1." << std::endl;
        return 1;
    }
    ZZ_p v = w*(u*r*r*(to_ZZ_p(-mg)*s+to_ZZ_p(-ng)) + to_ZZ_p(-1));
    int e = isquadratic(eval(fpoly1, v));
    ZZ_p x1 = to_ZZ_p((1+e)/2)*v + to_ZZ_p((1-e)/2)*(w*(-v+w)/(v+w));
    y = to_ZZ_p(-e)*squareRoot(eval(fpoly1, x1),p);
    x = x1;
    return 0;
}

int UnifiedEncoding::decode(ZZ_p &val1, ZZ_p &val2, ZZ_p x, ZZ_p y){
    
    if(eval(fpoly1, x) != y*y) {
        std::cout << "Point given is not a point of the hyperelliptic curve!" << std::endl;
        return 1;
    }
    if(isquadratic(u*w*(x+w)*(to_ZZ_p(-ng) + to_ZZ_p(-mg)*s)) != 1) {
        std::cout << "u*w*(x+w)*(-ng-mg*s) is not a square in Fq" << std::endl;
        return 1;
    }
    ZZ_p hlp = u*w*(to_ZZ_p(-ng)+ to_ZZ_p(-mg)*s);
    ZZ_p hlp2 = u*(x+w)*(to_ZZ_p(-ng) + to_ZZ_p(-mg)*s);
    val1 = squareRoot((x+w)/hlp, p);
    val2 = squareRoot(2*w/hlp2, p);
    
    return 0;
}

NS_G2_NAMESPACE::g2hcurve UnifiedEncoding::getcurve() {
    return curve2;
}

g3HEC::g3hcurve UnifiedEncoding::getcurveg3() {
    return curve3;
}

int try_koblitz (poly_t f, ZZ x, ZZ_p &x1, ZZ_p &y1, ZZ k, ZZ p) {
  ZZ_p cand_y;
  ZZ_p yfound;
  for (int i=0; i < k; i++) {
    x1 = to_ZZ_p(x*k + i);
    cand_y = eval(f, x1);
    yfound = squareRoot(cand_y, p);
    if(yfound != 0) {
      y1 = yfound;
      return 0;
    }
  }
  return 1;
}

NS_G2_NAMESPACE::divisor points_to_divisor (ZZ_p x1, ZZ_p y1, ZZ_p x2, ZZ_p y2, NS_G2_NAMESPACE::g2hcurve curve) {
  NS_G2_NAMESPACE::divisor D;
  ZZ_p a = -x1 -x2;
  ZZ_p b = x1*x2;
  poly_t u,v;
  SetCoeff(u, 2, 1);
  SetCoeff(u, 1, a);
  SetCoeff(u, 0, b);

  ZZ_p c = (y1-y2)/(x1-x2);
  ZZ_p d = y1 - c*x1;
  SetCoeff(v, 1, c);
  SetCoeff(v, 0, d);

  D.set_curve(curve);
  D.set_upoly(u);
  D.set_vpoly(v);
  D.update();
  return D;
}

g3HEC::g3divisor points_to_divisorg3 (ZZ_p x1, ZZ_p y1, ZZ_p x2, ZZ_p y2, ZZ_p x3, ZZ_p y3, g3HEC::g3hcurve curveg3) {
    g3HEC::g3divisor D;
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

    D.set_curve(curveg3);
    D.set_upoly(u);
    D.set_vpoly(v);
    D.update();
    return D;
}

void divisor_to_points (NS_G2_NAMESPACE::divisor D, ZZ_p &x1, ZZ_p &y1, ZZ_p &x2, ZZ_p &y2, ZZ p) {
  poly_t u,v;
  u = D.get_upoly();
  v = D.get_vpoly();

  ZZ_p a,b,c,d;
  GetCoeff(a,u,1);
  GetCoeff(d,v,0);
  GetCoeff(c,v,1);
  
  if(DetIrredTest(u)){
    std::cout << "Sth is wrong.." << std::endl;
    exit(1);
  }
  x1 = FindRoot(u);
  x2 = -x1 - a;

  y1 = d + c*x1;
  y2 = y1 - c*(x1-x2);
}

void divisorg3_to_points(g3HEC::g3divisor D, ZZ_p &x1, ZZ_p &y1, ZZ_p &x2, ZZ_p &y2, ZZ_p &x3, ZZ_p &y3, ZZ p){
    poly_t u, v;
    u = D.get_upoly();
    v = D.get_vpoly();

    if(DetIrredTest(u)) {
        std::cout << "Invalid divisor of genus 3 for converting to text" << std::endl;
        exit(1);
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


int text_to_divisor (NS_G2_NAMESPACE::divisor &D, std::string txt, ZZ p, NS_G2_NAMESPACE::g2hcurve &curve, UnifiedEncoding enc) {
    int maxlen = 26;
    int len = txt.length();
    if(len > maxlen) {
        return 1;
    }
    uint8_t chk[maxlen];
    memcpy(chk, txt.c_str(), len);
    for(int i = 0; i < maxlen - len; i++) {
        chk[maxlen-1-i] = '\0';
    }
    ZZ chkzz = NTL::ZZFromBytes(chk, len);

    uint8_t *str1, *str2;
    str1 = new uint8_t [maxlen/2+1];
    str2 = new uint8_t [maxlen/2+1];
    str1[0] = '1';
    str2[0] = '2';

    memcpy(str1+1, chk, maxlen/2);
    memcpy(str2+1, chk + maxlen/2, maxlen/2);

    ZZ msgzz1, msgzz2;
    msgzz1 = NTL::ZZFromBytes(str1, maxlen/2+1);
    msgzz2 = NTL::ZZFromBytes(str2, maxlen/2+1);

    if(msgzz1 >= p || msgzz2 >= p) {
        std::cout << "Needs segmentation." << std::endl; 
        return 1;
    }

    ZZ_p x1, y1, x2, y2;
    curve = enc.getcurve();

    int fl = enc.encode(msgzz1, x1, y1);
    if(fl) {
        std::cout << "Could not encode!" << std::endl;
        return 1;
    }

    fl = enc.encode(msgzz2, x2, y2);

    if(fl){
        std::cout << "Could not encode!" << std::endl;
        return 1;
    }

    D = points_to_divisor(x1, y1, x2, y2, curve);
    free(str1);
    free(str2);

    return 0;
}

int text_to_divisorg3 (g3HEC::g3divisor &D, std::string txt, ZZ p, g3HEC::g3hcurve &curve, UnifiedEncoding enc) {
    int maxlen = 27;
    int len = txt.length();
    if(len > maxlen) {
        return 1;
    }
    uint8_t chk[maxlen];
    memcpy(chk, txt.c_str(), len);
    for(int i =0; i < maxlen - len; i++) {
        chk[maxlen-1-i] = '\0';
    }
    ZZ chkzz = NTL::ZZFromBytes(chk, len);
    
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
    msgzz1 = NTL::ZZFromBytes(str1, maxlen/3+1);
    msgzz2 = NTL::ZZFromBytes(str2, maxlen/3+1);
    msgzz3 = NTL::ZZFromBytes(str3, maxlen/3+1);

    if(msgzz1 >= p || msgzz2 >= p || msgzz3 >=p) {
        std::cout << "Needs segmentation." << std::endl; 
        return 1;
    }
   
    
    ZZ_p x1, y1, x2, y2, x3, y3;
    curve = enc.getcurveg3();

    int fl = enc.encode(msgzz1, x1, y1);
    if(fl) {
        std::cout << "Could not encode!" << std::endl;
        return 1;
    }

    fl = enc.encode(msgzz2, x2, y2);

    if(fl){
        std::cout << "Could not encode!" << std::endl;
        return 1;
    }

    fl = enc.encode(msgzz3, x3, y3);

    if(fl){
        std::cout << "Could not encode!" << std::endl;
        return 1;
    }

    D = points_to_divisorg3(x1, y1, x2, y2, x3, y3, curve);
    free(str1);
    free(str2);
    free(str3);

    return 0;
}

bool isAscii(const char* bytes, int len) {
    for (int i = 0; i < len; i++) {
        if (bytes[i] < 0 || bytes[i] > 127) {
            return false;
        }
    }
    return true;
}

uint8_t* find_string(ZZ_p val1, ZZ_p val2, int size, int mode=0) {
    uint8_t *str = new uint8_t[size];
    ZZ sol1, sol2, sol3, sol4;

    sol1 = rep(val1);
    sol2 = rep(-val1);
    sol3 = rep(val2);
    sol4 = rep(-val2);

    NTL::BytesFromZZ(str, sol1, size);
    bool flag = isAscii((char*)str, size); 
    if(mode)
        flag = flag && (str[0] == '1' || str[0] == '2' || str[0] == '3');
    if(flag) {
        return str;
    }

    NTL::BytesFromZZ(str, sol2, size);
    flag = isAscii((char*)str, size);
    if(mode)
        flag = flag && (str[0] == '1' || str[0] == '2' || str[0] == '3');
    if(flag) {
        return str;
    }

    NTL::BytesFromZZ(str, sol3, size);
    flag = isAscii((char*)str, size);
    if(mode)
        flag = flag && (str[0] == '1' || str[0] == '2' || str[0] == '3');
    if(flag) {
        return str;
    }

    NTL::BytesFromZZ(str, sol4, size);
    flag = isAscii((char*)str, size);
    if(mode)
        flag = flag && (str[0] == '1' || str[0] == '2' || str[0] == '3');
    if(flag) {
        return str;
    }

    memset(str, '0', size);
    return str;
}

int divisor_to_text(std::string &txt, NS_G2_NAMESPACE::divisor D, ZZ p, UnifiedEncoding enc) {
    int maxlen = 26;
    uint8_t *zer = new uint8_t[maxlen/2+1];
    memset(zer, '0', maxlen/2+1);
    uint8_t *ret = new uint8_t[maxlen+1];
    ZZ_p x1, y1, x2, y2;
    divisor_to_points(D, x1, y1, x2, y2, p);

    ZZ_p val1, val2, val3, val4;
    int fl = enc.decode(val1, val2, x1, y1);
    fl = enc.decode(val3, val4, x2, y2);

    if(fl) {
        std::cout << "Could not decode!" << std::endl;
        return 1;
    }

    uint8_t *str1 = new uint8_t[maxlen/2+1];

    str1 = find_string(val1, val2, maxlen/2+1, 1);

    if(memcmp(str1, zer, maxlen/2+1) == 0) {
        std::cout << "Could not decode!" << std::endl;
        return 1;
    }

    uint8_t *str2 = new uint8_t[maxlen/2+1];

    str2 = find_string(val3, val4, maxlen/2+1, 1);

    if(memcmp(str2, zer, maxlen/2+1) == 0) {
        std::cout << "Could not decode!" << std::endl;
        return 1;
    }

    int p1, p2;
    p1 = str1[0] - 49;
    p2 = str2[0] - 49;
    
    memcpy(ret+p1*maxlen/2, str1+1, maxlen/2);
    memcpy(ret+p2*maxlen/2, str2+1, maxlen/2);
    ret[maxlen] = '\0';
    //std::string toret((char*)ret, maxlen+1);
    txt = (char*)ret;
    return 0;
}

int divisorg3_to_text(std::string &txt, g3HEC::g3divisor D, ZZ p, UnifiedEncoding enc) {
    int maxlen = 27;
    uint8_t *zer = new uint8_t[maxlen/3+1];
    memset(zer, '0', maxlen/3+1);
    uint8_t *ret = new uint8_t[maxlen+1];

    ZZ_p x1, y1, x2, y2, x3, y3;
    divisorg3_to_points(D, x1, y1, x2, y2, x3, y3, p);
    
    ZZ_p val1, val2, val3, val4, val5, val6;
    int fl = enc.decode(val1, val2, x1, y1);
    fl = enc.decode(val3, val4, x2, y2);
    fl = enc.decode(val5, val6, x3, y3);

    if(fl) {
        std::cout << "Could not decode!" << std::endl;
        return 1;
    }
    
    uint8_t *str1;

    str1 = find_string(val1, val2, maxlen/3+1, 1);

    if(memcmp(str1, zer, maxlen/3+1) == 0) {
        std::cout << "Could not decode!" << std::endl;
        return 1;
    }

    uint8_t *str2;

    str2 = find_string(val3, val4, maxlen/3+1, 1);

    if(memcmp(str2, zer, maxlen/3+1) == 0) {
        std::cout << "Could not decode!" << std::endl;
        return 1;
    }

    uint8_t *str3;

    str3 = find_string(val5, val6, maxlen/3+1, 1);

    if(memcmp(str3, zer, maxlen/3+1) == 0) {
        std::cout << "Could not decode!" << std::endl;
        return 1;
    }

    int p1, p2, p3;
    p1 = str1[0] - 49;
    p2 = str2[0] - 49;
    p3 = str3[0] - 49;
    
    memcpy(ret+p1*maxlen/3, str1+1, maxlen/3);
    memcpy(ret+p2*maxlen/3, str2+1, maxlen/3);
    memcpy(ret+p3*maxlen/3, str3+1, maxlen/3);
    ret[maxlen] = '\0';
    //std::string toret((char*)ret, maxlen+1);
    txt = (char*)ret;
    //txt = toret;
    free(zer);
    free(str1);
    free(str2);
    free(str3);
    
    return 0;
}

Element text_to_ecpoint(std::string txt, int len, GroupParameters group, int size) {
    
    uint8_t *mess = (uint8_t *)txt.c_str();
    CryptoPP::Integer hgf1 = group.GetCurve().GetA();
    uint8_t *crv_a = new uint8_t[size];
    hgf1.Encode(crv_a, size);

    CryptoPP::Integer hgf2 = group.GetCurve().GetB();
    uint8_t *crv_b = new uint8_t[size];
    hgf2.Encode(crv_b, size);

    CryptoPP::Integer hgf3 = group.GetCurve().FieldSize();
    uint8_t *crv_p = new uint8_t[size];
    hgf3.Encode(crv_p, size);
    swap_endian(crv_a, size);
    swap_endian(crv_b, size);
    swap_endian(crv_p, size);
    ZZ crvazz = NTL::ZZFromBytes(crv_a, size);
    ZZ crvbzz = NTL::ZZFromBytes(crv_b, size);
    ZZ crvpzz = NTL::ZZFromBytes(crv_p, size);

    field_t::init(crvpzz);
    

    poly_t eccrvF;

    NTL::SetCoeff(eccrvF, 3, 1);
    NTL::SetCoeff(eccrvF, 2, 0);
    NTL::SetCoeff(eccrvF, 1, to_ZZ_p(crvazz));
    NTL::SetCoeff(eccrvF, 0, to_ZZ_p(crvbzz));

    ZZ to_enc = NTL::ZZFromBytes(mess, len);
    if(to_enc >= crvpzz) {
        std::cout << "Needs segmentation" << std::endl;
        Element point1(0,0);
        return point1;
    }
    ZZ_p xa1, ya1;
    try_koblitz(eccrvF, to_enc, xa1, ya1, to_ZZ(1000), crvpzz);
    
    uint8_t *xp = new uint8_t[size];
    uint8_t *yp = new uint8_t[size];

    NTL::BytesFromZZ(xp, rep(xa1), size);
    NTL::BytesFromZZ(yp, rep(ya1), size);

    swap_endian(xp, size);
    swap_endian(yp, size);

    CryptoPP::Integer xcpp, ycpp;
    xcpp.Decode(xp, size);
    ycpp.Decode(yp, size);

    Element point(xcpp, ycpp);
    
    return point;
}

std::string ecpoint_to_text(Element point){
    CryptoPP::Integer encmess = point.x/1000;
    uint8_t *mess = new uint8_t[encmess.ByteCount()+1];
    encmess.Encode(mess, encmess.ByteCount());
    swap_endian(mess, encmess.ByteCount());
    mess[encmess.ByteCount()] = '\0';
    std::string message = (char*)mess;
    return message;
}

int divisor_to_bytes(uint8_t *buff, NS_G2_NAMESPACE::divisor D, NS_G2_NAMESPACE::g2hcurve curve, ZZ p) {
    int size = NTL::NumBytes(p);
    poly_t u = D.get_upoly();
    poly_t v = D.get_vpoly();
    poly_t f = curve.get_f();
    ZZ_p c1, c2;
    GetCoeff(c1, u, 1);
    GetCoeff(c2, u, 0);
    uint8_t *c1z, *c2z;
    c1z = new uint8_t[size];
    NTL::BytesFromZZ(c1z, rep(c1), size);
    c2z = new uint8_t[size];
    NTL::BytesFromZZ(c2z, rep(c2), size);
    memcpy(buff, c1z, size);
    memcpy(buff+size, c2z, size);
    ZZ_p s0, v0, f0;
    GetCoeff(v0, v, 0);
    GetCoeff(f0, f, 0);
    
    ZZ_p f1, f2, f3, f4, v1;
    GetCoeff(v1, v, 1);
    GetCoeff(f1, f, 1);
    GetCoeff(f2, f, 2);
    GetCoeff(f3, f, 3);
    GetCoeff(f4, f, 4);
    if(c2 != 0)
        s0 = (v0*v0-f0)/c2;
    else {
        
        s0 = v1*v1 - f2 +f3*c1 + f4*(c2 - c1*c1) - c1*(2*c2 - c1*c1);
    }
    if((c1*c1 - 4*c2) != 0) {
        poly_t bsq, ap, gp;
        SetX(bsq);
        SetCoeff(bsq, 1, c1);
        SetCoeff(bsq, 0, (f1 - f3*c2 + f4*c2*c1 + c2*(c2 - c1*c1)));
        bsq = bsq*bsq;
        
        SetX(ap);
        SetCoeff(ap, 0, (f2 - f3*c1 - f4*(c2 - c1*c1) + c1*(2*c2 - c1*c1)));
        SetX(gp);
        SetCoeff(gp, 1, c2);
        SetCoeff(gp, 0, f0);

        poly_t ds0 = bsq - 4*ap*gp;
        MakeMonic(ds0);
        vec_ZZ_p roots = FindRoots(ds0);
        if((s0 == roots[0]) && (rep(roots[0]) < rep(roots[1])))
            buff[2*size] = 0;
        else if ((s0 == roots[0]) && (rep(roots[0]) > rep(roots[1])))
            buff[2*size] = 1;
        else if ((s0 == roots[1]) && (rep(roots[1]) > rep(roots[0])))
            buff[2*size] = 1;
        else
            buff[2*size] = 0;
    }
    else {
        buff[2*size] = 0;
    }

    if(v0!=0){
        if(rep(v0)%2 != 0) {
            buff[2*size] += 2;
        }
    }
    else {
        if(rep(v1)%2 != 0) {
            buff[2*size] += 2;
        }
    }
    return 0;
}

int divisorg3_to_bytes(uint8_t *buff, g3HEC::g3divisor D, g3HEC::g3hcurve curve, ZZ p) {
    int size = NTL::NumBytes(p);
    poly_t u = D.get_upoly();
    poly_t v = D.get_vpoly();
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
    memcpy(buff, u2z, size);
    memcpy(buff+size, u1z, size);
    memcpy(buff+2*size, u0z, size);

    uint8_t *v2z, *v1z, *v0z;
    v2z = new uint8_t[size];
    NTL::BytesFromZZ(v2z, rep(v2), size);
    v1z = new uint8_t[size];
    NTL::BytesFromZZ(v1z, rep(v1), size);
    v0z = new uint8_t[size];
    NTL::BytesFromZZ(v0z, rep(v0), size);
    memcpy(buff+3*size, v2z, size);
    memcpy(buff+4*size, v1z, size);
    memcpy(buff+5*size, v0z, size);
    
    return 0;
}

int bytes_to_divisor(NS_G2_NAMESPACE::divisor &D, uint8_t *buff, NS_G2_NAMESPACE::g2hcurve curve, ZZ p) {
    int size = NTL::NumBytes(p);
    ZZ c1, c2;
    c1 = NTL::ZZFromBytes(buff, size);
    c2 = NTL::ZZFromBytes(buff+size, size);
    poly_t u,v;
    ZZ_p u1 = to_ZZ_p(c1);
    ZZ_p u0 = to_ZZ_p(c2);
    SetCoeff(u,2,1);
    SetCoeff(u,1,u1);
    SetCoeff(u,0,u0);
    
    uint8_t bits = buff[2*size];
    poly_t f = curve.get_f();
    poly_t bsq, ap, gp;
    ZZ_p f0, f1, f2, f3, f4;
    GetCoeff(f0, f, 0);
    GetCoeff(f1, f, 1);
    GetCoeff(f2, f, 2);
    GetCoeff(f3, f, 3);
    GetCoeff(f4, f, 4);
    SetX(bsq);
    SetCoeff(bsq, 1, u1);
    SetCoeff(bsq, 0, (f1 - f3*u0 + f4*u0*u1 + u0*(u0 - u1*u1)));
    bsq = bsq*bsq;
    
    SetX(ap);
    SetCoeff(ap, 0, (f2 - f3*u1 - f4*(u0 - u1*u1) + u1*(2*u0 - u1*u1)));
    SetX(gp);
    SetCoeff(gp, 1, u0);
    SetCoeff(gp, 0, f0);

    poly_t ds0 = bsq - 4*ap*gp;
    MakeMonic(ds0);
    if(DetIrredTest(ds0)) {
        return 1;
    }
    vec_ZZ_p roots = FindRoots(ds0);
    ZZ_p s0;
    if(roots[0] == roots[1])
        s0 = roots[0];
    else{
        if((bits & 1) == 1)
            s0 = (rep(roots[0]) < rep(roots[1])) ? roots[1] : roots[0];
        else 
            s0 = (rep(roots[0]) < rep(roots[1])) ? roots[0] : roots[1];
    }

    ZZ_p v0sq, v0, v1;
    v0sq = u0*s0 + f0;
    if(v0sq != 0) {
        v0sq = squareRoot(v0sq, p);
        if((bits & 2) == 2){
            v0 = (rep(v0sq)%2 == 1) ? v0sq : -v0sq; 
        }
        else
            v0 = (rep(v0sq)%2 == 1) ? -v0sq : v0sq;
        v1 = (u1*s0 + f1 - f3*u0 + f4*u0*u1 + u0*(u0 - u1*u1))/(2*v0);
    }
    else{
        v0 = 0;
        ZZ_p v1sq;
        v1sq = s0 + f2 - f3*u1 - f4*(u0 - u1*u1) + u1*(2*u0 - u1*u1);
        v1sq = squareRoot(v1sq, p);
        if((bits & 2) == 2){
            v1 = (rep(v1sq)%2 == 1) ? v1sq : -v1sq; 
        }
        else
            v1 = (rep(v1sq)%2 == 1) ? -v1sq : v1sq;
    }

    SetCoeff(v, 1, v1);
    SetCoeff(v, 0, v0);
    D.set_curve(curve);
    D.set_upoly(u);
    D.set_vpoly(v);
    D.update();
    return 0;
}

int bytes_to_divisorg3(g3HEC::g3divisor &D, uint8_t *buff, g3HEC::g3hcurve curve, ZZ p) {
    int size = NTL::NumBytes(p);
    ZZ u2, u1, u0, v2, v1, v0;
    u2 = NTL::ZZFromBytes(buff, size);
    u1 = NTL::ZZFromBytes(buff+size, size);
    u0 = NTL::ZZFromBytes(buff+2*size, size);

    v2 = NTL::ZZFromBytes(buff+3*size, size);
    v1 = NTL::ZZFromBytes(buff+4*size, size);
    v0 = NTL::ZZFromBytes(buff+5*size, size);
    poly_t u,v;
    SetCoeff(u,3,1);
    SetCoeff(u,2,to_ZZ_p(u2));
    SetCoeff(u,1,to_ZZ_p(u1));
    SetCoeff(u,0,to_ZZ_p(u0));

    SetCoeff(v,2,to_ZZ_p(v2));
    SetCoeff(v,1,to_ZZ_p(v1));
    SetCoeff(v,0,to_ZZ_p(v0));
    D.set_curve(curve);
    D.set_upoly(u);
    D.set_vpoly(v);
    D.update();
    return 0;
}


int validate_timestamp(std::string tmstmp) {
    struct tm tm;
    strptime(tmstmp.c_str(), "%d-%m-%Y %H:%M:%S", &tm);
    time_t time = mktime(&tm);
    std::string valid = "01-01-2019 00:00:00";
    time_t t1;
    struct tm tm1;

    if(strptime(valid.c_str(), "%d-%m-%Y %H:%M:%S",&tm1) == NULL)
            printf("\nstrptime failed\n");

    t1 = mktime(&tm1);
    if(difftime(time, t1) > 0.0) {
        return 0;
    }
    else{
        return 1;
    }    
}