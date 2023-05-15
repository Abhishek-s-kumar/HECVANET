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
#include "cryptopp/modarith.h"

#include <thread>
#include <random>
#include <chrono>

//For colorful console printing
/*
 * Usage example :
 *    std::cout << BOLD_CODE << "some bold text << END_CODE << std::endl;
 *
 *    std::cout << YELLOW_CODE << BOLD_CODE << "some bold yellow text << END_CODE << std::endl;
 *
 */

#define YELLOW_CODE "\033[33m"
#define GREEN_CODE "\033[32m"
#define RED_CODE "\033[31m"
#define TEAL_CODE "\033[36m"
#define BOLD_CODE "\033[1m"
#define END_CODE "\033[0m"
#undef MAX_STRING_LEN 
#define MAX_STRING_LEN 300


enum ProtocolVEH {
    RECEIVE_CERT,
    RECEIVE_ACCEPT_KEY,
    ON_SYMMETRIC_ENC
};

struct RSU_data_ec{
    ProtocolVEH states[100];
    CryptoPP::Integer priv;
    Element rsupub, capub, vehpk[100];
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
    uint8_t rsupub[33], g[33], capub[33], vehpk[100][33];
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
    uint8_t rsupub[66], g[66], capub[66], vehpk[100][66];
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

extern Vehicle_data_ec vehec[100];
extern RSU_data_ec rsuec[5];

extern Vehicle_data_g2 vehg2[100];
extern RSU_data_g2 rsug2[5];

extern Vehicle_data_g3 vehg3[100];
extern RSU_data_g3 rsug3[5];

extern int rsuid;

void receive_Cert_Send_Join(uint8_t *buffrc, int ec_algo, int vid);

void extract_RSU_SendAccept_g2(uint8_t *buffrc, int vid, int rid);
void extract_RSU_SendAccept_g3(uint8_t *buffrc, int vid, int rid);
void extract_RSU_SendAccept_ec(uint8_t *buffrc, int vid, int rid);

void extract_Symmetric(uint8_t *buffrc, int ec_algo, int vid, int rid);