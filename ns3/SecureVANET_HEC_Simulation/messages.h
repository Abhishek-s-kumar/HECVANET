#ifndef MESSAGES_H 
#define MESSAGES_H

#include "cryptopp/cryptlib.h"
#include "cryptopp/sha3.h"
#include "ns3/wave-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "custom-mobility-model.h"
#include "ns3/node.h"

#include "hec_cert.h"
#include "sign.h"
#include "encoding.h"
#include "cryptopp/aes.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/modarith.h"
#include "cryptopp/pkcspad.h"
#include "ns3/basic-energy-source-helper.h"

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
    ON_SYMMETRIC_ENC,
    GROUP_LEADER_INFORM,
    IS_GROUP_LEADER,
    RECEIVE_ACCEPT_GL,
    ON_SYMM_GL,
    INFORM_MSG
};

struct RSU_data_ec{
    ProtocolVEH states[100];
    CryptoPP::Integer priv;
    Element rsupub, capub, vehpk[100];
    int numveh, glid;
    std::string symm_perveh[100], iv_perveh[100];
    GroupParameters group;
    uint8_t certs[100][64];
};

struct Vehicle_data_ec{
    GroupParameters group;
    Element capub, rsupub, pub, glpub;
    CryptoPP::Integer priv;
    uint8_t cert[64];
    ProtocolVEH state;
    std::string symm, iv;
    int glid;
};

struct GroupLeader_data_ec {
    Vehicle_data_ec *mydata;
    ProtocolVEH states[100];
    std::string symm_perveh[100], iv_perveh[100];
    int numveh, myid;
    Element vehpk[100];
    std::string agg_messages;
};

struct RSU_data_g2{
    ProtocolVEH states[100];
    ZZ priv;
    uint8_t rsupub[33], g[33], capub[33], vehpk[100][33], certs[100][64];
    int numveh, u, w, glid;
    std::string symm_perveh[100], iv_perveh[100];
    NS_G2_NAMESPACE::g2hcurve curve;
};

struct Vehicle_data_g2{
    NS_G2_NAMESPACE::g2hcurve curve;
    uint8_t capub[33], rsupub[33], g[33], pub[33], glpub[33];
    ZZ priv;
    uint8_t cert[64];
    ProtocolVEH state;
    std::string symm, iv;
    int u, w, glid;
};

struct GroupLeader_data_g2 {
    Vehicle_data_g2 *mydata;
    ProtocolVEH states[100];
    std::string symm_perveh[100], iv_perveh[100];
    int numveh, myid;
    uint8_t vehpk[100][33];
    std::string agg_messages;
};

struct RSU_data_g3{
    ProtocolVEH states[100];
    ZZ priv;
    uint8_t rsupub[66], g[66], capub[66], vehpk[100][66], certs[100][97];
    int numveh, u, w, glid;
    std::string symm_perveh[100], iv_perveh[100];
    g3HEC::g3hcurve curve;
};

struct Vehicle_data_g3{
    g3HEC::g3hcurve curve;
    uint8_t capub[66], rsupub[66], g[66], pub[66], glpub[66];
    ZZ priv;
    uint8_t cert[97];
    ProtocolVEH state;
    std::string symm, iv;
    int u, w, glid;
};

struct GroupLeader_data_g3 {
    Vehicle_data_g3 *mydata;
    ProtocolVEH states[100];
    std::string symm_perveh[100], iv_perveh[100];
    int numveh, myid;
    uint8_t vehpk[100][66];
    std::string agg_messages;
};

extern Vehicle_data_ec vehec[100];
extern RSU_data_ec rsuec[5];
extern GroupLeader_data_ec glec;

extern Vehicle_data_g2 vehg2[100];
extern RSU_data_g2 rsug2[5];
extern GroupLeader_data_g2 gl2;

extern Vehicle_data_g3 vehg3[100];
extern RSU_data_g3 rsug3[5];
extern GroupLeader_data_g3 gl3;

extern int rsuid;
extern uint8_t hpk[23];
extern uint8_t hpk3[48];

extern uint32_t get_metrics;
extern float prev_energy[64];
extern double prev_times[64];
extern ns3::Ptr<ns3::EnergySourceContainer> Vehicle_sources;


void receive_Cert_Send_Join(uint8_t *buffrc, int ec_algo, int vid);

void extract_RSU_SendAccept_g2(uint8_t *buffrc, int vid, int rid);
void extract_RSU_SendAccept_g3(uint8_t *buffrc, int vid, int rid);
void extract_RSU_SendAccept_ec(uint8_t *buffrc, int vid, int rid);

void extract_Symmetric(uint8_t *buffrc, int ec_algo, int vid, int rid, int mode=0);


void RSU_inform_GL(int ec_algo, int vid);
void extract_GLProof_Broadcast(uint8_t *buffrc, int ec_algo, int vid);

void receive_GLCert_Send_Join(uint8_t *buffrc, int ec_algo, int vid, int glid);

void extract_GLJoin_SendAccept(uint8_t *buffrc, int ec_algo, int vid, int glid);

void schedule_inform_message(int ec_algo, int vid, int glid);
void extract_Inform_Aggregate(uint8_t *buffrc, int ec_algo, int vid, int glid);

void extract_Info_RSU(uint8_t *buffrc, int infnum, int ec_algo, int glid);

#endif