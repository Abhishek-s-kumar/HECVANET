#include "hec_cert.h"

ECQV::ECQV (GroupParameters group) {
    this->group = group;
}

int ECQV::encode_to_bytes(uint8_t *buff) {
    if( !this->group.GetCurve().VerifyPoint(this->pu) || this->name.empty() || this->issued_by.empty() || this->issued_on.empty() || this->expires_on.empty()) {
        return 1;
    }
    int size = this->group.GetCurve().FieldSize().ByteCount();
    memcpy(buff, this->name.c_str(), 7);
    memcpy(buff+7, this->issued_by.c_str(), 4);
    memcpy(buff+11, this->issued_on.c_str(), 10);
    memcpy(buff+21, this->expires_on.c_str(), 10);
    uint8_t *buffp = new uint8_t[2*size+1];
    group.GetCurve().EncodePoint(buffp, this->pu, false);
    memcpy(buff+31, buffp, 2*size+1);
    return 0;
}

int ECQV::cert_generate(uint8_t *encoded, std::string uname, Element ru, CryptoPP::Integer capriv) {
    this->capriv = capriv;
    this->capk = group.ExponentiateBase(capriv);
    if(uname.length() != 7) {
        std::cout << "Name must consist of 7 chars" << std::endl;
        return 1;
    }
    CryptoPP::SHA3_256 hash;
    CryptoPP::Integer k1(prng, CryptoPP::Integer::One(), group.GetMaxExponent());
    Element kG = group.ExponentiateBase(k1);

    Element pu1 = group.GetCurve().Add(ru, kG);
    this->pu = pu1;
    this->name = uname;
    this->issued_by = "DMV1";
    this->issued_on = "01-01-2023";
    this->expires_on = "31-12-2030";

    int size = this->group.GetCurve().FieldSize().ByteCount();

    encode_to_bytes(encoded);

    hash.Update(encoded, 31 + 2*size + 1);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);
    
    CryptoPP::Integer hashed, hashed_p, n = group.GetCurve().FieldSize();
    hashed.Decode((byte*)digest.c_str(), hash.DigestSize());

    hashed_p = hashed % n;

    Element chk = group.GetCurve().ScalarMultiply(this->pu, hashed_p);
    chk = group.GetCurve().Add(chk, this->capk);

    if(!group.GetCurve().VerifyPoint(chk)) {
        std::cout << "Retry with a differenet key pair." << std::endl;
        return 1;
    }

    this->r = (hashed_p*k1 + capriv);
    return 0;
}

int ECQV::cert_pk_extraction(uint8_t *cert) {
    int size = this->group.GetCurve().FieldSize().ByteCount();
    uint8_t *point = new uint8_t[2*size+1];
    memcpy(point, cert+31, 2*size+1);

    char *namec = new char[7];
    memcpy(namec, (char*)cert, 7);
    this->name = namec;

    char *issued_byc = new char[4];
    memcpy(issued_byc, (char*)cert+7, 4);
    this->issued_by = issued_byc;

    char *issued_onc = new char[10];
    memcpy(issued_onc, (char*)cert+11, 10);
    this->issued_on = issued_onc;

    char *exp_onc = new char[10];
    memcpy(exp_onc, (char*)cert+21, 10);
    this->expires_on = exp_onc;

    group.GetCurve().DecodePoint(this->pu, point, 2*size+1);
    CryptoPP::SHA3_256 hash;

    hash.Update(cert, 31 + 2*size + 1);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    CryptoPP::Integer hashed, hashed_p, n = this->group.GetCurve().FieldSize();
    hashed.Decode((byte*)digest.c_str(), hash.DigestSize());
    hashed_p = hashed % n;
    
    this->qu = this->group.GetCurve().ScalarMultiply(this->pu, hashed_p);
    this->qu = this->group.GetCurve().Add(this->qu, this->capk);

    return 0;
}

int ECQV::cert_reception(uint8_t *cert, CryptoPP::Integer ku) {
    int size = this->group.GetCurve().FieldSize().ByteCount();
    uint8_t *point = new uint8_t[2*size+1];
    memcpy(point, cert+31, 2*size+1);
    Element pdec;
    group.GetCurve().DecodePoint(pdec, point, 2*size+1);
    CryptoPP::SHA3_256 hash;

    hash.Update(cert, 31 + 2*size + 1);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    CryptoPP::Integer hashed, hashed_p, n = this->group.GetCurve().FieldSize();
    hashed.Decode((byte*)digest.c_str(), size);
    hashed_p = hashed % n;

    CryptoPP::Integer du1 = (this->r + hashed_p*ku);
    Element qut = group.ExponentiateBase(du1);
    if(group.GetCurve().Equal(this->qu, qut)) {
        std::cout << "Private key extraction successful!" << std::endl;
        this->du = du1;
        return 0;
    }
    std::cout << "Private key extraction not successful!" << std::endl;
    return 1;
}

Element ECQV::get_calculated_Qu() {
    return this->qu;
}

CryptoPP::Integer ECQV::get_extracted_du() {
    return this->du;
}

std::string ECQV::get_name() {
    return this->name;
}

std::string ECQV::get_issued_by() {
    return this->issued_by;
}

std::string ECQV::get_issued_on() {
    return this->issued_on;
}

std::string ECQV::get_expires_on() {
    return this->expires_on;
}


/* Certificate of HEC Genus 2 form */

g2HECQV::g2HECQV(NS_G2_NAMESPACE::g2hcurve curve, ZZ p, NS_G2_NAMESPACE::divisor G) {
    assert(curve.is_valid_curve());
    assert(G.is_valid_divisor());
    this->curve = curve;
    this->p = p;
    this->G = G;
}

int g2HECQV::encode_to_bytes(uint8_t *buff) {
    if( !this->pu.is_valid_divisor() || this->name.empty() || this->issued_by.empty() || this->issued_on.empty() || this->expires_on.empty()) {
        return 1;
    }
    int size = NTL::NumBytes(this->p);
    memcpy(buff, this->name.c_str(), 7);
    memcpy(buff+7, this->issued_by.c_str(), 4);
    memcpy(buff+11, this->issued_on.c_str(), 10);
    memcpy(buff+21, this->expires_on.c_str(), 10);
    uint8_t *buffp = new uint8_t[2*size+1];
    divisor_to_bytes(buffp, this->pu, this->curve, this->p);
    memcpy(buff+31, buffp, 2*size+1);
    return 0;
}

int g2HECQV::cert_generate(uint8_t *encoded, std::string uname, NS_G2_NAMESPACE::divisor ru, ZZ capriv) {
    this->capriv = capriv;
    this->capk = capriv*this->G;
    if(uname.length() != 7) {
        std::cout << "Name must consist of 7 chars" << std::endl;
        return 1;
    }
    CryptoPP::SHA3_256 hash;
    ZZ k1;
    RandomBnd(k1, p*p);
    NS_G2_NAMESPACE::divisor kG = k1*this->G;

    NS_G2_NAMESPACE::divisor pu1 = ru + kG;
    this->pu = pu1;
    this->name = uname;
    this->issued_by = "DMV1";
    this->issued_on = "01-01-2023";
    this->expires_on = "31-12-2030";

    int size = NTL::NumBytes(p);
    
    int chk1 = encode_to_bytes(encoded);
    if(chk1) {
        std::cout << "could not encode" << std::endl;
        return 1;
    }
    
    hash.Update(encoded, 31 + 2*size + 1);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);
    
    ZZ hashed, n;
    hashed = ZZFromBytes((unsigned char*)digest.data(), 32);

     
    NS_G2_NAMESPACE::divisor chk = hashed*this->pu + this->capk;
    if(!chk.is_valid_divisor()) {
        std::cout << "Retry with a different key pair!" << std::endl;
        return 1;
    } 
    this->r = hashed*k1 + this->capriv;
    
    return 0;
}

int g2HECQV::cert_pk_extraction(uint8_t *cert) {
    int size = NumBytes(this->p);
    uint8_t *div = new uint8_t[2*size+1];
    memcpy(div, cert+31, 2*size+1);

    char *namec = new char[7];
    memcpy(namec, (char*)cert, 7);
    this->name = namec;

    char *issued_byc = new char[4];
    memcpy(issued_byc, (char*)cert+7, 4);
    this->issued_by = issued_byc;

    char *issued_onc = new char[10];
    memcpy(issued_onc, (char*)cert+11, 10);
    this->issued_on = issued_onc;

    char *exp_onc = new char[10];
    memcpy(exp_onc, (char*)cert+21, 10);
    this->expires_on = exp_onc;

    int chk2 = bytes_to_divisor(this->pu, div, this->curve, this->p);
    if(chk2){
        std::cout << "Could not decode" << std::endl;
        return 1;
    }
    CryptoPP::SHA3_256 hash;

    hash.Update(cert, 31 + 2*size + 1);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    ZZ hashed, n;
    hashed = ZZFromBytes((unsigned char*)digest.data(), 32);
    
    this->qu = hashed*this->pu + this->capk;

    return 0;
}

int g2HECQV::cert_reception(uint8_t *cert, ZZ ku) {
    int size = NumBytes(this->p);
    uint8_t *div = new uint8_t[2*size+1];
    memcpy(div, cert+31, 2*size+1);
    NS_G2_NAMESPACE::divisor pdec;
    bytes_to_divisor(pdec, div, this->curve, this->p);
    CryptoPP::SHA3_256 hash;

    hash.Update(cert, 31 + 2*size + 1);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    ZZ hashed, n;
    hashed = ZZFromBytes((unsigned char*)digest.data(), 32);
    ZZ du1 = (this->r + hashed*ku);
    NS_G2_NAMESPACE::divisor qut = du1*this->G;
    if(this->qu == qut) {
        std::cout << "Private key extraction successful!" << std::endl;
        this->du = du1;
        return 0;
    }

    std::cout << "Private key extraction not successful!" << std::endl;
    return 1;
}


NS_G2_NAMESPACE::divisor g2HECQV::get_calculated_Qu() {
    return this->qu;
}

ZZ g2HECQV::get_extracted_du() {
    return this->du;
}

std::string g2HECQV::get_name() {
    return this->name;
}

std::string g2HECQV::get_issued_by() {
    return this->issued_by;
}

std::string g2HECQV::get_issued_on() {
    return this->issued_on;
}

std::string g2HECQV::get_expires_on() {
    return this->expires_on;
}


/* Certificate of HEC Genus 3 form */

