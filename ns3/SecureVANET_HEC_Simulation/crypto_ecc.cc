#include "crypto_ecc.h"
#include "helpers.h"

/* --------------------------- ECQV cert methods --------------------------- */

ECQV::ECQV (GroupParameters group) {
    this->group = group;
    Integer ca_priv("99904945320188894543539641655649253921899278606834393872940151579788317849983");
    this->capriv = ca_priv;
    this->capk = group.ExponentiateBase(ca_priv);
}

void ECQV::encode_to_bytes(uint8_t *buff) {
    if( !this->group.GetCurve().VerifyPoint(this->pu) || this->name.empty() || this->issued_by.empty() || this->issued_on.empty() || this->expires_on.empty()) {
        throw std::runtime_error("Cannot serialize certificate, some field(s) might be missing");
    }
    
    memcpy(buff, this->name.c_str(), 7);
    memcpy(buff+7, this->issued_by.c_str(), 4);
    memcpy(buff+11, this->issued_on.c_str(), 10);
    memcpy(buff+21, this->expires_on.c_str(), 10);
    group.GetCurve().EncodePoint(buff+31, this->pu, true);
}

vector<unsigned char> ECQV::cert_generate(std::string uname, Element ru) {
    if(uname.length() != 7) {
        throw std::runtime_error("Name must consist of 7 chars");
    }

    Integer k1(prng, Integer::One(), group.GetMaxExponent());
    Element kG = group.ExponentiateBase(k1);

    Element pu1 = group.GetCurve().Add(ru, kG);
    this->pu = pu1;
    this->name = uname;
    this->issued_by = "DMV1";
    this->issued_on = "01-01-2023";
    this->expires_on = "31-12-2030";

    int element_size = this->group.GetCurve().FieldSize().ByteCount();

    byte encoded[31+element_size+1];
    encode_to_bytes(encoded);

    hash.Update(encoded, 31 + element_size + 1);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    Integer hashed, hashed_p, n = group.GetGroupOrder();
    hashed.Decode((byte*)digest.c_str(), hash.DigestSize());
    hashed_p = hashed%n;

    Element chk = group.GetCurve().ScalarMultiply(this->pu, hashed_p);
    chk = group.GetCurve().Add(chk, this->capk);

    if(!group.GetCurve().VerifyPoint(chk)) {
        throw std::runtime_error("Collision on certificate generation. Retry with a differenet key pair.");
    }

    ModularArithmetic mod(n);
    
    this->r = mod.Multiply(hashed_p, k1);
    this->r = mod.Add(this->r, capriv);
    vector<unsigned char> buff;
    buff.insert(buff.end(), encoded, encoded + 31 + element_size + 1);
    return buff;
}

Element ECQV::cert_pk_extraction(vector<unsigned char> cert) {
    int element_size = this->group.GetCurve().FieldSize().ByteCount();

    size_t check_size = element_size + 31 + 1;
    if(cert.size() != check_size) {
        throw std::runtime_error("Trying to extract public key from invalid certificate.");
    }

    uint8_t *point = new uint8_t[element_size+1];
    memcpy(point, cert.data()+31, element_size+1);

    string name((char*)cert.data(), 7);
    this->name = name;

    string issued_by((char*)cert.data()+7, 4);
    this->issued_by = issued_by;

    string issued_on((char*)cert.data()+11, 10);
    this->issued_on = issued_on;

    string exp_on((char*)cert.data()+21, 10);
    this->expires_on = exp_on;

    group.GetCurve().DecodePoint(this->pu, point, element_size+1);

    hash.Update(cert.data(), 31 + element_size + 1);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    Integer hashed, hashed_p, n = this->group.GetGroupOrder();
    hashed.Decode((byte*)digest.c_str(), hash.DigestSize());
    hashed_p = hashed%n;

    this->qu = this->group.GetCurve().ScalarMultiply(this->pu, hashed_p);
    this->qu = this->group.GetCurve().Add(this->qu, this->capk);

    return this->qu;
}

Integer ECQV::cert_reception(vector<unsigned char> cert, Integer ku) {
    int element_size = this->group.GetCurve().FieldSize().ByteCount();

    size_t check_size = element_size + 31 + 1;
    if(cert.size() != check_size) {
        throw std::runtime_error("Trying to extract public key from invalid certificate.");
    }

    uint8_t *point = new uint8_t[element_size+1];
    memcpy(point, cert.data()+31, element_size+1);
    Element pdec;
    group.GetCurve().DecodePoint(pdec, point, element_size+1);

    hash.Update(cert.data(), 31 + element_size + 1);
    std::string digest;
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);

    Integer hashed, hashed_p, n = this->group.GetGroupOrder();
    hashed.Decode((byte*)digest.c_str(), element_size);
    hashed_p = hashed%n;

    ModularArithmetic mod(n);
    Integer du1 = mod.Multiply(hashed_p, ku);
    du1 = mod.Add(du1, this->r);
    Element qut = group.ExponentiateBase(du1);
    if(group.GetCurve().Equal(this->qu, qut)) {
        this->du = du1;
        return this->du;
    }
    throw std::runtime_error("Could not extract private key.");
    return 1;
}

Element ECQV::get_calculated_Qu() {
    return this->qu;
}

Integer ECQV::get_extracted_du() {
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





/* --------------------------- Crypto ECC methods --------------------------- */

tuple<Element, Element> CryptoECC::encrypt_ElGamal(Element pub, Element mess)
{
    Integer k(prng, Integer::One(), _group.GetMaxExponent());
    Element a = _group.ExponentiateBase(k);
    Element btemp = _group.GetCurve().ScalarMultiply(pub, k);
    Element b = _group.GetCurve().Add(btemp, mess);
    tuple<Element, Element> encrypted(a, b);
    return encrypted;
}


Element CryptoECC::decrypt_ElGamal(Integer priv, Element a, Element b)
{
    Element mtemp = _group.GetCurve().ScalarMultiply(a, priv);
    Element m = _group.GetCurve().Subtract(b, mtemp);
    return m;
}


tuple<ZZ_p, ZZ_p> CryptoECC::encode_koblitz(poly_t f, ZZ x, ZZ k, ZZ p)
{
    ZZ_p x1, y1, cand_y;
    for (int i=0; i < k; i++) {
        x1 = to_ZZ_p(x*k + i);
        cand_y = eval(f, x1);
        cand_y = squareRoot(cand_y, p);
        if(cand_y != 0) {
            y1 = cand_y;
            tuple<ZZ_p, ZZ_p> coords(x1, y1);
            return coords;
        }
    }
    throw std::runtime_error("Cannot encode message to EC Point");
}

Element CryptoECC::encode(std::string txt)
{
    int size = _group.GetCurve().FieldSize().ByteCount();
    //vector<unsigned char> mess(txt.begin(), txt.end());

    // Get A parameter of the curve and encode it to bytes
    Integer crv_A = _group.GetCurve().GetA();
    byte crv_A_bytes[size];
    crv_A.Encode(crv_A_bytes, size);

    // Get B parameter of the curve and encode it to bytes
    Integer crv_B = _group.GetCurve().GetB();
    byte crv_B_bytes[size];
    crv_B.Encode(crv_B_bytes, size);

    // Get field characteristic p
    Integer crv_p = _group.GetCurve().FieldSize();
    byte crv_p_bytes[size];
    crv_p.Encode(crv_p_bytes, size);

    // Swap endians because CryptoPP uses big endian as default
    swap_endian(crv_A_bytes, size);
    swap_endian(crv_B_bytes, size);
    swap_endian(crv_p_bytes, size);

    // Convert to ZZ type for NTL
    ZZ crv_a_zz = NTL::ZZFromBytes(crv_A_bytes, size);
    ZZ crv_b_zz = NTL::ZZFromBytes(crv_B_bytes, size);
    ZZ crv_p_zz = NTL::ZZFromBytes(crv_p_bytes, size);

    // Construct f polyonym
    field_t::init(crv_p_zz);
    poly_t crv_F;
    NTL::SetCoeff(crv_F, 3, 1);
    NTL::SetCoeff(crv_F, 2, 0);
    NTL::SetCoeff(crv_F, 1, to_ZZ_p(crv_a_zz));
    NTL::SetCoeff(crv_F, 0, to_ZZ_p(crv_b_zz));

    // Message to encrypt to ZZ big integer for NTL
    ZZ to_enc = NTL::ZZFromBytes((unsigned char*)txt.c_str(), txt.length());

    if(to_enc >= crv_p_zz) {
        throw std::runtime_error("Message needs segmenation to encode");
    }

    // Encode using Koblitz
    tuple<ZZ_p, ZZ_p> encoded_point;
    encoded_point = encode_koblitz(crv_F, to_enc, to_ZZ(1000), crv_p_zz);

    byte xp[size], yp[size];
    NTL::BytesFromZZ(xp, rep(std::get<0>(encoded_point)), size);
    NTL::BytesFromZZ(yp, rep(std::get<1>(encoded_point)), size);

    swap_endian(xp, size);
    swap_endian(yp, size);

    // Build EC point
    Integer ret_x, ret_y;
    ret_x.Decode(xp, size);
    ret_y.Decode(yp, size);
    Element point(ret_x, ret_y);

    if(!_group.GetCurve().VerifyPoint(point))
        throw std::runtime_error("Could not encode point.");

    return point;
}


string CryptoECC::decode(Element point, Integer k)
{
    Integer decoded = point.x/k;
    byte mess[decoded.ByteCount() + 1];
    decoded.Encode(mess, decoded.ByteCount());
    swap_endian(mess, decoded.ByteCount());
    mess[decoded.ByteCount()] = '\0';
    std::string message((char*)mess, decoded.ByteCount()+1);
    return message;
}

string CryptoECC::sign(Integer priv, vector<unsigned char> mess) 
{
    ECDSA<ECP, SHA256>::PrivateKey priv_key;
    priv_key.Initialize(_group, priv);
    ECDSA<ECP, SHA256>::Signer signer(priv_key);

    size_t siglen = signer.MaxSignatureLength();
    std::string signature(siglen, 0x00);
    siglen = signer.SignMessage( prng, mess.data(), mess.size(), (byte*)&signature[0] );
    signature.resize(siglen);

    return signature;
}

bool CryptoECC::verify(string sig, Element Pk, vector<unsigned char> mess)
{
    ECDSA<ECP, SHA256>::PublicKey publicKey;
    publicKey.Initialize(_group, Pk);
    ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

    return verifier.VerifyMessage( mess.data(), mess.size(), (const byte*)&sig[0], sig.length());
}

tuple<Integer, Element> CryptoECC::generate_cert_get_keypair(vector<unsigned char> &gen_cert, string uname)
{
    Integer x(prng, CryptoPP::Integer::One(), _group.GetMaxExponent());
    
    Element h = _group.ExponentiateBase(x);
    gen_cert = cert.cert_generate(uname, h);

    Element pub = cert.cert_pk_extraction(gen_cert);
    Integer priv = cert.cert_reception(gen_cert, x);
    return tuple<Integer, Element>(priv, pub);
}

Element CryptoECC::extract_public(vector<unsigned char> rec_cert)
{
    return cert.cert_pk_extraction(rec_cert);
}

void CryptoECC::serialize(Element point, vector<unsigned char> &buff)
{
    int size = _group.GetCurve().FieldSize().ByteCount();
    byte temp[size+1];
    _group.GetCurve().EncodePoint(temp, point, true);
    buff.insert(buff.end(), temp, temp + size+1);
}

Element CryptoECC::deserialize(vector<unsigned char> buff)
{
    int size = _group.GetCurve().FieldSize().ByteCount();
    Element point;
    _group.GetCurve().DecodePoint(point, buff.data(), size+1);
    return point;
}