#include "crypto_ecc.h"


tuple<Element, Element> CryptoECC::encrypt_ElGamal(Element pub, Element mess)
{
    CryptoPP::Integer k(prng, CryptoPP::Integer::One(), _group.GetMaxExponent());
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