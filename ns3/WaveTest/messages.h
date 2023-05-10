#ifndef HEADERS_H 
#define HEADERS_H

#include "encoding.h"
#include "hec_cert.h"
#include "sign.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"
#include "ns3/wave-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "custom-mobility-model.h"
#include "ns3/node.h"

#endif

#include "cryptopp/aes.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"


enum ProtocolVEH {
    RECEIVE_CERT,
    RECEIVE_ACCEPT_KEY
};

struct RSU_data_ec{
    ProtocolVEH states[100];
    CryptoPP::Integer priv;
    Element rsupub, capub;
    int numveh;
    std::string symm_perveh[100], iv_perveh[100];
    GroupParameters group;
};

struct Vehicle_data_ec{
    GroupParameters group;
    Element capub, rsupub, pub;
    CryptoPP::Integer priv;
    uint8_t cert[96];
    ProtocolVEH state;
    std::string symm, iv;
};

struct RSU_data_g2{
    ProtocolVEH states[100];
    ZZ priv;
    uint8_t rsupub[33], g[33], capub[33];
    int numveh, u, w;
    std::string symm_perveh[100], iv_perveh[100];
    NS_G2_NAMESPACE::g2hcurve curve;
};

struct Vehicle_data_g2{
    NS_G2_NAMESPACE::g2hcurve curve;
    uint8_t capub[33], rsupub[33], g[33], pub[33];
    ZZ priv;
    uint8_t cert[64];
    ProtocolVEH state;
    std::string symm, iv;
    int u, w;
};

struct RSU_data_g3{
    ProtocolVEH states[100];
    ZZ priv;
    uint8_t rsupub[66], g[66], capub[66];
    int numveh, u, w;
    std::string symm_perveh[100], iv_perveh[100];
    g3HEC::g3hcurve curve;
};

struct Vehicle_data_g3{
    g3HEC::g3hcurve curve;
    uint8_t capub[66], rsupub[66], g[66], pub[66];
    ZZ priv;
    uint8_t cert[97];
    ProtocolVEH state;
    std::string symm, iv;
    int u, w;
};

extern Vehicle_data_ec veh1ec;
extern RSU_data_ec rsu1ec;

extern Vehicle_data_g2 veh1g2;
extern RSU_data_g2 rsu1g2;

extern Vehicle_data_g3 veh1g3;
extern RSU_data_g3 rsu1g3;

void receive_Cert_Send_Join(uint8_t *buffrc, int ec_algo);

void extract_RSU_SendAccept_g2(uint8_t *buffrc, int vid);
void extract_RSU_SendAccept_g3(uint8_t *buffrc, int vid);
void extract_RSU_SendAccept_ec(uint8_t *buffrc, int vid);

void extract_Symmetric(uint8_t *buffrc, int ec_algo);