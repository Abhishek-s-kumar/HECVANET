#include "messages.h"


using namespace ns3;

void send_GLJoin_g2(Vehicle_data_g2 *veh1g2, int vid, int destnode) {
    ZZ ptest = to_ZZ(pt);
    UnifiedEncoding enc(ptest, veh1g2->u, veh1g2->w, 2, ZZ_p::zero());
    int size = NumBytes(ptest);
    
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
    auto str = oss.str();
    std::string str11 = "Join ";
    std::string finalstr = str11 + str;

    NS_G2_NAMESPACE::divisor m, a, b, glpub, g;

    int rt = text_to_divisor(m, finalstr, ptest, veh1g2->curve, enc);
    if(rt) {
      exit(1);
    }

    bytes_to_divisor(glpub, veh1g2->glpub, veh1g2->curve, ptest);
    bytes_to_divisor(g, veh1g2->g, veh1g2->curve, ptest);

    ZZ k;
    RandomBnd(k, ptest*ptest);
    a = k*g;
    b = k*glpub + m;

    int sizenosign = 2*(2*size + 1) + 31 + 2*size+1;
    uint8_t *temp = new uint8_t[sizenosign];
    divisor_to_bytes(temp, a, veh1g2->curve, ptest);
    divisor_to_bytes(temp+2*size+1, b, veh1g2->curve, ptest);
    memcpy(temp+2*(2*size+1), veh1g2->cert, 31 + 2*size+1);

    int signsize = NumBytes(to_ZZ(pg2));
    ZZ sigb;
    uint8_t *siga = new uint8_t[2*signsize+1];

    sign_genus2(siga, sigb, (uint8_t*)finalstr.c_str(), finalstr.length(), ptest);
    verify_sig2(siga, sigb, (uint8_t*)finalstr.c_str(), finalstr.length(), hpk);

    int fullsize = sizenosign + 2*signsize + 1 + 61;
    uint8_t *cypherbuff = new uint8_t[fullsize+2];
    cypherbuff[0] = RECEIVE_ACCEPT_GL;
    cypherbuff[1] = vid;
    memcpy(cypherbuff+2, temp, sizenosign);
    memcpy(cypherbuff+sizenosign+2, siga, 2*signsize+1);
    BytesFromZZ(cypherbuff+sizenosign+2+2*signsize+1, sigb, 61);

    Ptr<Node> n1 =  ns3::NodeList::GetNode(vid);
    Ptr <NetDevice> d0 = n1->GetDevice(0);
    Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

    Ptr<Node> n0 = ns3::NodeList::GetNode(destnode);
    Ptr <NetDevice> nd0 = n0->GetDevice(0);

    Ptr <Packet> packet_i = Create<Packet>(cypherbuff, fullsize+2);
    Mac48Address dest	= Mac48Address::ConvertFrom (nd0->GetAddress());

    uint16_t protocol = 0x88dc;
    TxInfo tx;
    tx.preamble = WIFI_PREAMBLE_LONG;
    tx.channelNumber = CCH;
    tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
    tx.priority = 7;	//We set the AC to highest prior
    tx.txPowerLevel = 7; //When we define TxPowerStar

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0, 5);
    
    float timerand = dis(gen);

    //wd0->SendX(packet_i, dest, protocol, tx);
    Simulator::Schedule(Seconds(timerand), &WaveNetDevice::SendX, wd0, packet_i, dest, protocol, tx);
    veh1g2->state = RECEIVE_ACCEPT_GL;
    free(temp);
    free(cypherbuff);
}

void send_GLJoin_ec(Vehicle_data_ec *veh1ec, int vid, int destnode) {
    CryptoPP::AutoSeededRandomPool prng;  
    int size = veh1ec->group.GetCurve().FieldSize().ByteCount();

    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
    auto str = oss.str();
    std::string str11 = "Join ";
    std::string finalstr = str11 + str;

    Element m = text_to_ecpoint(finalstr, finalstr.length(), veh1ec->group, size);
    
    CryptoPP::Integer k(prng, CryptoPP::Integer::One(), veh1ec->group.GetMaxExponent());

    Element a,b,btemp;
    a = veh1ec->group.ExponentiateBase(k);
    btemp = veh1ec->group.GetCurve().ScalarMultiply(veh1ec->glpub, k);
    b = veh1ec->group.GetCurve().Add(btemp, m);

    int sizenosign = 2*(2*size+1) + 31 + 2*size + 1;
    uint8_t *temp = new uint8_t[sizenosign];

    veh1ec->group.GetCurve().EncodePoint(temp, a, false);
    veh1ec->group.GetCurve().EncodePoint(temp+2*size+1, b, false);

    memcpy(temp+2*(2*size+1), veh1ec->cert, 31 + 2*size+1);

    std::string sigecc;
    sign_ec(sigecc, veh1ec->priv, (uint8_t*)finalstr.c_str(), finalstr.length());
    int nok = verify_ec(sigecc, veh1ec->pub, (uint8_t*)finalstr.c_str(), finalstr.length());
    if(nok)
        return;

    int fullsize = sizenosign + sigecc.length() + 1;
    uint8_t *cypherbuff = new uint8_t[fullsize+2];
    cypherbuff[0] = RECEIVE_ACCEPT_GL;
    cypherbuff[1] = vid;
    memcpy(cypherbuff+2, temp, sizenosign);
    memcpy(cypherbuff+sizenosign+2, sigecc.c_str(), sigecc.length());
    cypherbuff[fullsize+1] = 0;

    Ptr<Node> n1 =  ns3::NodeList::GetNode(vid);
    Ptr <NetDevice> d0 = n1->GetDevice(0);
    Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

    Ptr<Node> n0 = ns3::NodeList::GetNode(destnode);
    Ptr <NetDevice> nd0 = n0->GetDevice(0);

    Ptr <Packet> packet_i = Create<Packet>(cypherbuff, fullsize+2);
    Mac48Address dest	= Mac48Address::ConvertFrom (nd0->GetAddress());
    uint16_t protocol = 0x88dc;
    TxInfo tx;
    tx.preamble = WIFI_PREAMBLE_LONG;
    tx.channelNumber = CCH;
    tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
    tx.priority = 7;	//We set the AC to highest prior
    tx.txPowerLevel = 7; //When we define TxPowerStar

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0, 5);
    
    float timerand = dis(gen);

    //wd0->SendX(packet_i, dest, protocol, tx);
    Simulator::Schedule(Seconds(timerand), &WaveNetDevice::SendX, wd0, packet_i, dest, protocol, tx);

    veh1ec->state = RECEIVE_ACCEPT_GL;
    free(temp);
    free(cypherbuff);
}

void send_GLJoing_g3(Vehicle_data_g3 *veh1g3, int vid, int destnode) {
    ZZ ptest = to_ZZ(pg3);
    UnifiedEncoding enc(ptest, veh1g3->u, veh1g3->w, 3, ZZ_p::zero());
    int size = NumBytes(ptest);
    
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
    auto str = oss.str();
    std::string str11 = "Join ";
    std::string finalstr = str11 + str;

    g3HEC::g3divisor m, a, b, glpub, g;

    int rt = text_to_divisorg3(m, finalstr, ptest, veh1g3->curve, enc);
    if(rt) {
      exit(1);
    }

    bytes_to_divisorg3(glpub, veh1g3->glpub, veh1g3->curve, ptest);
    bytes_to_divisorg3(g, veh1g3->g, veh1g3->curve, ptest);

    ZZ k;
    RandomBnd(k, ptest*ptest*ptest);
    a = k*g;
    b = k*glpub + m;

    int sizenosign = 2*(6*size) + 31 + 6*size;
    uint8_t *temp = new uint8_t[sizenosign];
    divisorg3_to_bytes(temp, a, veh1g3->curve, ptest);
    divisorg3_to_bytes(temp+6*size, b, veh1g3->curve, ptest);
    memcpy(temp+2*(6*size), veh1g3->cert, 31 + 6*size);

    int signsize = NumBytes(to_ZZ(pg2));
    ZZ sigb;
    uint8_t *siga = new uint8_t[2*signsize+1];

    sign_genus2(siga, sigb, (uint8_t*)finalstr.c_str(), finalstr.length(), ptest);
    verify_sig2(siga, sigb, (uint8_t*)finalstr.c_str(), finalstr.length(), hpk);

    int fullsize = sizenosign + 2*signsize + 1 + 61;
    uint8_t *cypherbuff = new uint8_t[fullsize+2];
    cypherbuff[0] = RECEIVE_ACCEPT_GL;
    cypherbuff[1] = vid;
    memcpy(cypherbuff+2, temp, sizenosign);
    memcpy(cypherbuff+sizenosign+2, siga, 2*signsize+1);
    BytesFromZZ(cypherbuff+sizenosign+2+2*signsize+1, sigb, 61);

    Ptr<Node> n1 =  ns3::NodeList::GetNode(vid);
    Ptr <NetDevice> d0 = n1->GetDevice(0);
    Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

    Ptr<Node> n0 = ns3::NodeList::GetNode(destnode);
    Ptr <NetDevice> nd0 = n0->GetDevice(0);

    Ptr <Packet> packet_i = Create<Packet>(cypherbuff, fullsize+2);
    Mac48Address dest	= Mac48Address::ConvertFrom (nd0->GetAddress());

    uint16_t protocol = 0x88dc;
    TxInfo tx;
    tx.preamble = WIFI_PREAMBLE_LONG;
    tx.channelNumber = CCH;
    tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
    tx.priority = 7;	//We set the AC to highest prior
    tx.txPowerLevel = 7; //When we define TxPowerStar

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0, 5);
    
    float timerand = dis(gen);

    //wd0->SendX(packet_i, dest, protocol, tx);
    Simulator::Schedule(Seconds(timerand), &WaveNetDevice::SendX, wd0, packet_i, dest, protocol, tx);
    veh1g3->state = RECEIVE_ACCEPT_GL;
    free(temp);
    free(cypherbuff);
}

void receive_GLCert_Send_Join(uint8_t *buffrc, int ec_algo, int vid, int glid) {
    switch (ec_algo)
    {
    case 0: {
        Vehicle_data_g2 *veh1g2 = &vehg2[vid];
        ZZ ptest = to_ZZ(pt);
        field_t::init(ptest);
        int size = NumBytes(ptest);

        int sizenosign = 27 + 31 + 2*size+1;

        std::string lead((char*)buffrc, 27);
        std::string tocmp = "Leader";
        if(memcmp(lead.c_str(), tocmp.c_str(), 6) != 0) {
            return;
        }
        else
            std::cout << BOLD_CODE << GREEN_CODE << "Received Proof of Leadership on node: " << vid << END_CODE << std::endl;

        int nok = validate_timestamp(lead.substr(7, 27));
        if(nok)
            return;
        else 
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;


        int signsize = NumBytes(to_ZZ(pg2));
        uint8_t *siga = new uint8_t[2*signsize+1];
        ZZ sigb;

        memcpy(siga, buffrc+sizenosign, 2*signsize+1);
        sigb = -ZZFromBytes(buffrc+sizenosign+2*signsize+1, 61);

        nok = verify_sig2(siga, sigb, buffrc, sizenosign, hpk);

        if(nok) {
            sigb = -sigb;
            nok = verify_sig2(siga, sigb, buffrc, sizenosign, hpk);
            if(nok)
                return;
        }

        NS_G2_NAMESPACE::divisor g, capub, glpub;
        bytes_to_divisor(g, veh1g2->g, veh1g2->curve, ptest);
        bytes_to_divisor(capub, veh1g2->capub, veh1g2->curve, ptest);

        g2HECQV cert2(veh1g2->curve, ptest, g);
        cert2.cert_pk_extraction(buffrc+27, capub);

        std::string issued_by, expires_on;
        issued_by = cert2.get_issued_by();
        expires_on = cert2.get_expires_on();

        if(issued_by.substr(0,4) != "DMV1" || expires_on.substr(6) <= "2023") {
            return;
        }

        glpub = cert2.get_calculated_Qu();
        std::cout << BOLD_CODE << GREEN_CODE << "Received GL public key, node: " << vid << END_CODE << std::endl;
        divisor_to_bytes(veh1g2->glpub, glpub, veh1g2->curve, ptest);
        send_GLJoin_g2(veh1g2, vid, glid);

        break;
    }
    case 1: {
        Vehicle_data_ec *veh1ec = &vehec[vid];
        CryptoPP::AutoSeededRandomPool prng; 
        int size = veh1ec->group.GetCurve().FieldSize().ByteCount();

        int sizenosign = 27 + 31 + 2*size+1;

        std::string lead((char*)buffrc, 27);
        std::string tocmp = "Leader";
        if(memcmp(lead.c_str(), tocmp.c_str(), 6) != 0) {
            return;
        }
        else
            std::cout << BOLD_CODE << GREEN_CODE << "Received Proof of Leadership on node: " << vid << END_CODE << std::endl;

        int nok = validate_timestamp(lead.substr(7, 27));
        if(nok)
            return;
        else 
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;

        char sig[2*size+1];
        memcpy(sig, buffrc+sizenosign, 2*size+1);
        std::string sigecc(sig, 2*size+1);

        nok = verify_ec(sigecc, veh1ec->rsupub, buffrc, sizenosign);

        if(nok) {
            return;
        }

        ECQV cert(veh1ec->group);
        cert.cert_pk_extraction(buffrc+27, veh1ec->capub);
        std::string issued_by, expires_on;
        issued_by = cert.get_issued_by();
        expires_on = cert.get_expires_on();

        if(issued_by.substr(0,4) != "DMV1" || expires_on.substr(6) <= "2023") {
            return;
        }

        veh1ec->glpub = cert.get_calculated_Qu();
        std::cout << BOLD_CODE << GREEN_CODE << "Received GL public key, node: " << vid << END_CODE << std::endl;
        send_GLJoin_ec(veh1ec, vid, glid);
        break;
    }
    case 2: {
        Vehicle_data_g3 *veh1g3 = &vehg3[vid];
        ZZ ptest = to_ZZ(pg3);
        field_t::init(ptest);
        int size = NumBytes(ptest);

        int sizenosign = 27 + 31 + 6*size;

        std::string lead((char*)buffrc, 27);
        std::string tocmp = "Leader";
        if(memcmp(lead.c_str(), tocmp.c_str(), 6) != 0) {
            return;
        }
        else
            std::cout << BOLD_CODE << GREEN_CODE << "Received Proof of Leadership on node: " << vid << END_CODE << std::endl;

        int nok = validate_timestamp(lead.substr(7, 27));
        if(nok)
            return;
        else 
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;


        int signsize = NumBytes(to_ZZ(pg2));
        uint8_t *siga = new uint8_t[2*signsize+1];
        ZZ sigb;

        memcpy(siga, buffrc+sizenosign, 2*signsize+1);
        sigb = -ZZFromBytes(buffrc+sizenosign+2*signsize+1, 61);

        nok = verify_sig2(siga, sigb, buffrc, sizenosign, hpk);

        if(nok) {
            sigb = -sigb;
            nok = verify_sig2(siga, sigb, buffrc, sizenosign, hpk);
            if(nok)
                return;
        }

        g3HEC::g3divisor g, capub, glpub;
        bytes_to_divisorg3(g, veh1g3->g, veh1g3->curve, ptest);
        bytes_to_divisorg3(capub, veh1g3->capub, veh1g3->curve, ptest);

        g3HECQV cert2(veh1g3->curve, ptest, g);
        cert2.cert_pk_extraction(buffrc+27, capub);

        std::string issued_by, expires_on;
        issued_by = cert2.get_issued_by();
        expires_on = cert2.get_expires_on();

        if(issued_by.substr(0,4) != "DMV1" || expires_on.substr(6) <= "2023") {
            return;
        }

        glpub = cert2.get_calculated_Qu();
        std::cout << BOLD_CODE << GREEN_CODE << "Received GL public key, node: " << vid << END_CODE << std::endl;
        divisorg3_to_bytes(veh1g3->glpub, glpub, veh1g3->curve, ptest);
        send_GLJoing_g3(veh1g3, vid, glid);

        break;
    }
    default:
        break;
    }
}