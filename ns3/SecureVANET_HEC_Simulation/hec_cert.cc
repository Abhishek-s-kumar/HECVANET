#include "hec_cert.h"


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

int g2HECQV::cert_pk_extraction(uint8_t *cert, NS_G2_NAMESPACE::divisor capk1) {
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
    
    this->capk = capk1;
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
        //std::cout << "Private key extraction successful!" << std::endl;
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

g3HECQV::g3HECQV(g3HEC::g3hcurve curve, ZZ p, g3HEC::g3divisor G) {
    assert(curve.is_valid_curve());
    assert(G.is_valid_divisor());
    this->curve = curve;
    this->p = p;
    this->G = G;
}

int g3HECQV::encode_to_bytes(uint8_t *buff) {
    if( !this->pu.is_valid_divisor() || this->name.empty() || this->issued_by.empty() || this->issued_on.empty() || this->expires_on.empty()) {
        return 1;
    }
    int size = NTL::NumBytes(this->p);
    memcpy(buff, this->name.c_str(), 7);
    memcpy(buff+7, this->issued_by.c_str(), 4);
    memcpy(buff+11, this->issued_on.c_str(), 10);
    memcpy(buff+21, this->expires_on.c_str(), 10);
    uint8_t *buffp = new uint8_t[6*size];
    divisorg3_to_bytes(buffp, this->pu, this->curve, this->p);
    memcpy(buff+31, buffp, 6*size);
    free(buffp);
    return 0;
}

int g3HECQV::cert_generate(uint8_t *encoded, std::string uname, g3HEC::g3divisor ru, ZZ capriv1) {
    this->capriv = capriv1;
    this->capk = capriv1*this->G;
    if(uname.length() != 7) {
        std::cout << "Name must consist of 7 chars" << std::endl;
        return 1;
    }
    CryptoPP::SHA3_256 hash;
    ZZ k1;
    RandomBnd(k1, p*p*p);
    g3HEC::g3divisor kG = k1*this->G;

    g3HEC::g3divisor pu1 = ru + kG;
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
    
    hash.Update(encoded, 31 + 6*size);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);
    
    ZZ hashed, n;
    hashed = ZZFromBytes((unsigned char*)digest.data(), 32);

     
    g3HEC::g3divisor chk = hashed*this->pu + this->capk;
    if(!chk.is_valid_divisor()) {
        std::cout << "Retry with a different key pair!" << std::endl;
        return 1;
    } 
    this->r = hashed*k1 + this->capriv;
    
    return 0;
}

int g3HECQV::cert_pk_extraction(uint8_t *cert, g3HEC::g3divisor capk1) {
    int size = NumBytes(this->p);
    uint8_t *div = new uint8_t[6*size];
    memcpy(div, cert+31, 6*size);

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

    int chk2 = bytes_to_divisorg3(this->pu, div, this->curve, this->p);
    if(chk2){
        std::cout << "Could not decode" << std::endl;
        return 1;
    }
    CryptoPP::SHA3_256 hash;

    hash.Update(cert, 31 + 6*size);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    ZZ hashed, n;
    hashed = ZZFromBytes((unsigned char*)digest.data(), 32);
    
    this->capk = capk1;
    this->qu = hashed*this->pu + this->capk;

    return 0;
}

int g3HECQV::cert_reception(uint8_t *cert, ZZ ku) {
    int size = NumBytes(this->p);
    uint8_t *div = new uint8_t[6*size];
    memcpy(div, cert+31, 6*size);
    g3HEC::g3divisor pdec;
    bytes_to_divisorg3(pdec, div, this->curve, this->p);
    CryptoPP::SHA3_256 hash;

    hash.Update(cert, 31 + 6*size);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    ZZ hashed, n;
    hashed = ZZFromBytes((unsigned char*)digest.data(), 32);
    ZZ du1 = (this->r + hashed*ku);
    g3HEC::g3divisor qut = du1*this->G;
    if(this->qu == qut) {
        //std::cout << "Private key extraction successful!" << std::endl;
        this->du = du1;
        return 0;
    }

    std::cout << "Private key extraction not successful!" << std::endl;
    return 1;
}


g3HEC::g3divisor g3HECQV::get_calculated_Qu() {
    return this->qu;
}

ZZ g3HECQV::get_extracted_du() {
    return this->du;
}

std::string g3HECQV::get_name() {
    return this->name;
}

std::string g3HECQV::get_issued_by() {
    return this->issued_by;
}

std::string g3HECQV::get_issued_on() {
    return this->issued_on;
}

std::string g3HECQV::get_expires_on() {
    return this->expires_on;
}