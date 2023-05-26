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

    int fullsize = sizenosign + 2*signsize + 1 + 21;
    uint8_t *cypherbuff = new uint8_t[fullsize+2];
    cypherbuff[0] = RECEIVE_ACCEPT_GL;
    cypherbuff[1] = vid;
    memcpy(cypherbuff+2, temp, sizenosign);
    memcpy(cypherbuff+sizenosign+2, siga, 2*signsize+1);
    BytesFromZZ(cypherbuff+sizenosign+2+2*signsize+1, sigb, 21);

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

    int sizenosign = 2*(size+1) + 31 + size + 1;
    uint8_t *temp = new uint8_t[sizenosign];

    veh1ec->group.GetCurve().EncodePoint(temp, a, true);
    veh1ec->group.GetCurve().EncodePoint(temp+size+1, b, true);

    memcpy(temp+2*(size+1), veh1ec->cert, 31 + size+1);

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
    cypherbuff[fullsize+1] = '\0';

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

    int signsize = NumBytes(to_ZZ(psign3));
    ZZ sigb;
    uint8_t *siga = new uint8_t[6*signsize];

    sign_genus3(siga, sigb, (uint8_t*)finalstr.c_str(), finalstr.length(), ptest);
    int nok = verify_sig3(siga, sigb, (uint8_t*)finalstr.c_str(), finalstr.length(), hpk3);

    if(nok)
        return;

    int fullsize = sizenosign + 6*signsize + 21;
    uint8_t *cypherbuff = new uint8_t[fullsize+2];
    cypherbuff[0] = RECEIVE_ACCEPT_GL;
    cypherbuff[1] = vid;
    memcpy(cypherbuff+2, temp, sizenosign);
    memcpy(cypherbuff+sizenosign+2, siga, 6*signsize);
    BytesFromZZ(cypherbuff+sizenosign+2+6*signsize, sigb, 21);

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
        sigb = ZZFromBytes(buffrc+sizenosign+2*signsize+1, 21);

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
        veh1g2->glid = glid;
        send_GLJoin_g2(veh1g2, vid, glid);

        break;
    }
    case 1: {
        Vehicle_data_ec *veh1ec = &vehec[vid];
        CryptoPP::AutoSeededRandomPool prng; 
        int size = veh1ec->group.GetCurve().FieldSize().ByteCount();

        int sizenosign = 27 + 31 + size+1;

        std::string lead((char*)buffrc, 27);
        std::string tocmp = "Leader";
        if(memcmp(lead.c_str(), tocmp.c_str(), 6) != 0) {
            return;
        }
        else
            std::cout << BOLD_CODE << GREEN_CODE << "Received Proof of Leadership on node: " << vid << END_CODE << std::endl;

        int nok = validate_timestamp(lead.substr(7, 27));
        if(nok) {
            std::cout << RED_CODE << "Invalid Timestamp." << END_CODE << std::endl;
            return;
        }
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
            std::cout << RED_CODE << "Invalid Cert." << END_CODE << std::endl;
            return;
        }

        veh1ec->glpub = cert.get_calculated_Qu();
        std::cout << BOLD_CODE << GREEN_CODE << "Received GL public key, node: " << vid << END_CODE << std::endl;
        veh1ec->glid = glid;
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
        if(nok) {
            std::cout << RED_CODE << "Invalid Timestamp." << END_CODE << std::endl;
            return;
        }
        else 
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;


        int signsize = NumBytes(to_ZZ(psign3));
        uint8_t *siga = new uint8_t[6*signsize];
        ZZ sigb;

        memcpy(siga, buffrc+sizenosign, 6*signsize);
        sigb = ZZFromBytes(buffrc+sizenosign+6*signsize, 21);

        nok = verify_sig3(siga, sigb, buffrc, sizenosign, hpk3);

        if(nok) {
            sigb = -sigb;
            nok = verify_sig3(siga, sigb, buffrc, sizenosign, hpk3);
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
            std::cout << RED_CODE << "Invalid Cert." << END_CODE << std::endl;
            return;
        }

        glpub = cert2.get_calculated_Qu();
        std::cout << BOLD_CODE << GREEN_CODE << "Received GL public key, node: " << vid << END_CODE << std::endl;
        divisorg3_to_bytes(veh1g3->glpub, glpub, veh1g3->curve, ptest);
        veh1g3->glid = glid;
        send_GLJoing_g3(veh1g3, vid, glid);

        break;
    }
    default:
        break;
    }
}


void extract_GLJoin_SendAccept(uint8_t *buffrc, int ec_algo, int vid, int glid) {
    switch (ec_algo)
    {
    case 0: {
        ZZ ptest = to_ZZ(pt);
        int size = NumBytes(ptest);
        UnifiedEncoding enc(ptest, gl2.mydata->u, gl2.mydata->w, 2, ZZ_p::zero());
        int signsize = NumBytes(to_ZZ(pg2));
        int sizenosign = 2*(2*size + 1) + 31 + 2*size+1;

        uint8_t *siga = new uint8_t[2*signsize+1];
        ZZ sigb;

        memcpy(siga, buffrc+sizenosign, 2*signsize+1);
        sigb = ZZFromBytes(buffrc+sizenosign+2*signsize+1, 21);

        NS_G2_NAMESPACE::divisor a, b, m, x;
        
        int nok = bytes_to_divisor(a, buffrc, gl2.mydata->curve, ptest);        
        nok = bytes_to_divisor(b, buffrc+2*size+1, gl2.mydata->curve, ptest);
        
        if(nok) {
            std::cout << RED_CODE << "Bytes to divisor did not succeed." << END_CODE << std::endl;
            return;
        }
        m = b - gl2.mydata->priv*a;
        std::string rec;
        divisor_to_text(rec, m, ptest, enc);
        std::string tocmp = "Join";

        if(memcmp(rec.c_str(), tocmp.c_str(), 4) != 0) {
            return;
        }
        std::cout << BOLD_CODE << GREEN_CODE << "Received Join on GL from vehicle: " << vid << END_CODE << std::endl;
        gl2.numveh++;

        std::string tmstmp = rec.substr(5);
        nok = validate_timestamp(tmstmp);
        if(nok) {
            std::cout << BOLD_CODE << RED_CODE << "Message not fresh" << END_CODE << std::endl;
            return;
        }
        else {
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;
        }


        nok = verify_sig2(siga, sigb, (uint8_t*)rec.c_str(), rec.length(), hpk);

        if(nok) {
            sigb = -sigb;
            nok = verify_sig2(siga, sigb, (uint8_t*)rec.c_str(), rec.length(), hpk);
            if(nok)
                return;
        }

        NS_G2_NAMESPACE::divisor g, capub, vehpk;
        bytes_to_divisor(g, gl2.mydata->g, gl2.mydata->curve, ptest);
        bytes_to_divisor(capub, gl2.mydata->capub, gl2.mydata->curve, ptest);

        g2HECQV recert(gl2.mydata->curve, ptest, g);
        uint8_t *received_cert = new uint8_t[31 + 2*size+1];
        memcpy(received_cert, buffrc+4*size+2, 31 + 2*size+1);

        recert.cert_pk_extraction(received_cert, capub);
        vehpk = recert.get_calculated_Qu();
        if(!vehpk.is_valid_divisor()) {
            return;
        }
        divisor_to_bytes(gl2.vehpk[vid], vehpk, gl2.mydata->curve, ptest);

        std::string issued_by, expires_on;
        issued_by = recert.get_issued_by();
        expires_on = recert.get_expires_on();

        if(issued_by.substr(0,4) != "DMV1" || expires_on.substr(6) <= "2023") {
            std::cout << RED_CODE << "Invalid Cert." << END_CODE << std::endl;
        return;
        }

        using namespace CryptoPP;


        AutoSeededRandomPool prng;

        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);

        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(iv, iv.size());

        std::string keystr, ivstr;
        HexEncoder encoder(new StringSink(keystr));
        encoder.Put(key, key.size());
        encoder.MessageEnd();

        HexEncoder encoder2(new StringSink(ivstr));
        encoder2.Put(iv, iv.size());
        encoder2.MessageEnd();
    
        std::string str1 = "Accept ";
        str1 += keystr.substr(0, 16);

        NS_G2_NAMESPACE::divisor mess1, a1, b1;
        
        text_to_divisor(mess1, str1, ptest, gl2.mydata->curve, enc);
        
        ZZ k;
        RandomBnd(k, ptest*ptest);
        a1 = k*g;
        b1 = k*vehpk + mess1;


        
        std::string str2 = keystr.substr(16);
        str2 += ivstr.substr(0, 10);


        NS_G2_NAMESPACE::divisor mess2, a2, b2;
        
        text_to_divisor(mess2, str2, ptest, gl2.mydata->curve, enc);
        
        a2 = k*g;
        b2 = k*vehpk + mess2;



        std::string str3 = ivstr.substr(10);


        NS_G2_NAMESPACE::divisor mess3, a3, b3;
        
        text_to_divisor(mess3, str3, ptest, gl2.mydata->curve, enc);
        
        a3 = k*g;
        b3 = k*vehpk + mess3;


        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        
        std::ostringstream oss;
        oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
        auto str = oss.str();

        std::string str4 = str;

        NS_G2_NAMESPACE::divisor mess4, a4, b4;
        
        text_to_divisor(mess4, str4, ptest, gl2.mydata->curve, enc);
        
        a4 = k*g;
        b4 = k*vehpk + mess4;


        int onedivsize = 2*size+1;
        int size1no = 8*onedivsize;
        int fullsize1 = size1no + 2*signsize + 22;

        uint8_t cypherbuff[fullsize1+2];
        uint8_t temp[size1no];

        divisor_to_bytes(temp, a1, gl2.mydata->curve, ptest);
        divisor_to_bytes(temp+onedivsize, b1, gl2.mydata->curve, ptest);
        divisor_to_bytes(temp+2*onedivsize, a2, gl2.mydata->curve, ptest);
        divisor_to_bytes(temp+3*onedivsize, b2, gl2.mydata->curve, ptest);
        divisor_to_bytes(temp+4*onedivsize, a3, gl2.mydata->curve, ptest);
        divisor_to_bytes(temp+5*onedivsize, b3, gl2.mydata->curve, ptest);
        divisor_to_bytes(temp+6*onedivsize, a4, gl2.mydata->curve, ptest);
        divisor_to_bytes(temp+7*onedivsize, b4, gl2.mydata->curve, ptest);

        uint8_t mysiga[2*signsize+1];
        ZZ mysigb;
        std::string signstr = str1+str2+str3+str4;
        sign_genus2(mysiga, mysigb, (uint8_t*)signstr.c_str(), signstr.length(), ptest);
        verify_sig2(mysiga, mysigb, (uint8_t*)signstr.c_str(), signstr.length(), hpk);

        cypherbuff[0] = RECEIVE_ACCEPT_GL;
        cypherbuff[1] = glid;
        memcpy(cypherbuff+2, temp, size1no);
        memcpy(cypherbuff+size1no+2, mysiga, 2*signsize+1);
        BytesFromZZ(cypherbuff+size1no+2*signsize+3, mysigb, 21);

        Ptr<Node> n0 =  ns3::NodeList::GetNode(glid);
        Ptr <NetDevice> d0 = n0->GetDevice(0);
        Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

        Ptr<Node> n1 = ns3::NodeList::GetNode(vid);
        Ptr <NetDevice> nd0 = n1->GetDevice(0);

        Ptr <Packet> packet_i = Create<Packet>(cypherbuff, fullsize1+2);
        Mac48Address dest	= Mac48Address::ConvertFrom (nd0->GetAddress());
        uint16_t protocol = 0x88dc;
        TxInfo tx;
        tx.preamble = WIFI_PREAMBLE_LONG;
        tx.channelNumber = CCH;
        tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
        tx.priority = 7;	//We set the AC to highest prior
        tx.txPowerLevel = 7; //When we define TxPowerStar
        wd0->SendX(packet_i, dest, protocol, tx);
        gl2.symm_perveh[vid] = keystr;
        gl2.iv_perveh[vid] = ivstr;
        gl2.states[vid] = RECEIVE_ACCEPT_GL;
        free(siga);
        free(received_cert);

        break;
    }

    case 1: {
        GroupParameters group = glec.mydata->group;
        int size = group.GetCurve().FieldSize().ByteCount();

        ECQV cert(group);
        cert.cert_pk_extraction(buffrc+2*size+2, glec.mydata->capub);
        Element vehpub = cert.get_calculated_Qu();
        glec.vehpk[vid] = vehpub;

        int sizenosign = 2*(size+1) + 31 + size + 1;
        char sig[2*size];
        memcpy(sig, buffrc+sizenosign, 2*size);
        std::string sigecc(sig, 2*size);
        

        Element a, b, m, mtemp;
        group.GetCurve().DecodePoint(a, buffrc, size+1);
        group.GetCurve().DecodePoint(b, buffrc+size+1, size+1);
        mtemp = group.GetCurve().ScalarMultiply(a, glec.mydata->priv);
        m = group.GetCurve().Subtract(b, mtemp);
        std::string rec;
        rec = ecpoint_to_text(m);

        std::string tocmp = "Join";

        if(memcmp(rec.c_str(), tocmp.c_str(), 4) != 0) {
            return;
        }
        std::cout << BOLD_CODE << GREEN_CODE << "Received Join on GL from vehicle: " << vid << END_CODE << std::endl;
        glec.numveh++;

        std::string tmstmp = rec.substr(5);
        int nok = validate_timestamp(tmstmp);
        if(nok) {
            std::cout << BOLD_CODE << RED_CODE << "Message not fresh" << END_CODE << std::endl;
            return;
        }
        else {
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;
        }

        nok = verify_ec(sigecc, vehpub, (uint8_t*)rec.c_str(), rec.length());

        if(nok) {
            return;
        }

        std::string issued_by, expires_on;
        issued_by = cert.get_issued_by();
        expires_on = cert.get_expires_on();

        if(issued_by.substr(0,4) != "DMV1" || expires_on.substr(6) <= "2023") {
            std::cout << RED_CODE << "Invalid Cert." << END_CODE << std::endl;
            return;
        }

        using namespace CryptoPP;


        AutoSeededRandomPool prng;

        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);

        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(iv, iv.size());

        std::string keystr, ivstr;
        HexEncoder encoder(new StringSink(keystr));
        encoder.Put(key, key.size());
        encoder.MessageEnd();

        HexEncoder encoder2(new StringSink(ivstr));
        encoder2.Put(iv, iv.size());
        encoder2.MessageEnd();

        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        
        std::ostringstream oss;
        oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
        auto str = oss.str();

        std::string finalstr1 = "Accept " + keystr.substr(0, 16);
        std::string finalstr2 = keystr.substr(16) + ivstr.substr(0, 12);
        std::string finalstr3 = ivstr.substr(12);
        std::string finalstr4 = str;
        Element m1, m2, m3, m4;
        m1 = text_to_ecpoint(finalstr1, finalstr1.length(), group, size);
        m2 = text_to_ecpoint(finalstr2, finalstr2.length(), group, size);
        m3 = text_to_ecpoint(finalstr3, finalstr3.length(), group, size);
        m4 = text_to_ecpoint(finalstr4, finalstr4.length(), group, size);

        Element a1,b1,a2,b2,a3,b3,a4,b4;
        CryptoPP::Integer k(prng, CryptoPP::Integer::One(), group.GetMaxExponent());
        a1 = group.ExponentiateBase(k);
        b1 = group.GetCurve().ScalarMultiply(vehpub, k);
        b1 = group.GetCurve().Add(b1, m1);

        a2 = group.ExponentiateBase(k);
        b2 = group.GetCurve().ScalarMultiply(vehpub, k);
        b2 = group.GetCurve().Add(b2, m2);

        a3 = group.ExponentiateBase(k);
        b3 = group.GetCurve().ScalarMultiply(vehpub, k);
        b3 = group.GetCurve().Add(b3, m3);

        a4 = group.ExponentiateBase(k);
        b4 = group.GetCurve().ScalarMultiply(vehpub, k);
        b4 = group.GetCurve().Add(b4, m4);

        int onedivsize = size+1;
        int size1no = 8*onedivsize;
        int fullsize1 = size1no + 2*size + 1;

        uint8_t cypherbuff[fullsize1+2];
        uint8_t temp[size1no];
        group.GetCurve().EncodePoint(temp, a1, true);
        group.GetCurve().EncodePoint(temp+onedivsize, b1, true);
        group.GetCurve().EncodePoint(temp+2*onedivsize, a2, true);
        group.GetCurve().EncodePoint(temp+3*onedivsize, b2, true);
        group.GetCurve().EncodePoint(temp+4*onedivsize, a3, true);
        group.GetCurve().EncodePoint(temp+5*onedivsize, b3, true);
        group.GetCurve().EncodePoint(temp+6*onedivsize, a4, true);
        group.GetCurve().EncodePoint(temp+7*onedivsize, b4, true);

        std::string mysig;
        std::string signstr = finalstr1 + finalstr2 + finalstr3 + finalstr4;
        sign_ec(mysig, glec.mydata->priv, (uint8_t*)signstr.c_str(), signstr.length());
        nok = verify_ec(mysig, glec.mydata->pub, (uint8_t*)signstr.c_str(), signstr.length());
        
        if(nok)
            return;

        cypherbuff[0] = RECEIVE_ACCEPT_GL;
        cypherbuff[1] = glid;
        memcpy(cypherbuff+2, temp, size1no);
        memcpy(cypherbuff+2+size1no, mysig.c_str(), mysig.length());
        cypherbuff[fullsize1+1] = '\0';

        Ptr<Node> n0 =  ns3::NodeList::GetNode(glid);
        Ptr <NetDevice> d0 = n0->GetDevice(0);
        Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

        Ptr<Node> n1 = ns3::NodeList::GetNode(vid);
        Ptr <NetDevice> nd0 = n1->GetDevice(0);

        Ptr <Packet> packet_i = Create<Packet>(cypherbuff, fullsize1+2);
        Mac48Address dest	= Mac48Address::ConvertFrom (nd0->GetAddress());
        uint16_t protocol = 0x88dc;
        TxInfo tx;
        tx.preamble = WIFI_PREAMBLE_LONG;
        tx.channelNumber = CCH;
        tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
        tx.priority = 7;	//We set the AC to highest prior
        tx.txPowerLevel = 7; //When we define TxPowerStar
        wd0->SendX(packet_i, dest, protocol, tx);
        glec.symm_perveh[vid] = keystr;
        glec.iv_perveh[vid] = ivstr;
        glec.states[vid] = RECEIVE_ACCEPT_GL;
        break;
    }

    case 2: {
        ZZ ptest = to_ZZ(pg3);
        int size = NumBytes(ptest);
        UnifiedEncoding enc(ptest, 10, 4, 3, ZZ_p::zero());

        int signsize = NumBytes(to_ZZ(psign3));
        int sizenosign = 12*size + 31 + 6*size;

        // int fullsize = sizenosign + 2*signsize + 1 + signsize;

        uint8_t *siga = new uint8_t[6*signsize];
        ZZ sigb;

        memcpy(siga, buffrc+sizenosign, 6*signsize);
        sigb = ZZFromBytes(buffrc+sizenosign+6*signsize, 21);
        

        g3HEC::g3divisor a, b, m, x;
        
        int nok = bytes_to_divisorg3(a, buffrc, gl3.mydata->curve, ptest);
        nok = bytes_to_divisorg3(b, buffrc+6*size, gl3.mydata->curve, ptest);
        
        if(nok) {
            std::cout << RED_CODE << "Bytes to divisor did not succeed." << END_CODE << std::endl;
            return;
        }

        m = b - gl3.mydata->priv*a;
        std::string rec;
        divisorg3_to_text(rec, m, ptest, enc);
        std::string tocmp = "Join";

        if(memcmp(rec.c_str(), tocmp.c_str(), 4) != 0) {
            return;
        }
        std::cout << BOLD_CODE << GREEN_CODE << "Received Join GL from vehicle: " << vid << END_CODE << std::endl;
        gl3.numveh++;

        std::string tmstmp = rec.substr(5);
        nok = validate_timestamp(tmstmp);
        if(nok) {
            std::cout << BOLD_CODE << RED_CODE << "Message not fresh" << END_CODE << std::endl;
            return;
        }
        else {
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;
        }

        nok = verify_sig3(siga, sigb, (uint8_t*)rec.c_str(), rec.length(), hpk3);

        if(nok) {
            sigb = -sigb;
            nok = verify_sig3(siga, sigb, (uint8_t*)rec.c_str(), rec.length(), hpk3);
            if(nok)
                return;
        }

        g3HEC::g3divisor g, capub, vehpk;
        bytes_to_divisorg3(g, gl3.mydata->g, gl3.mydata->curve, ptest);
        bytes_to_divisorg3(capub, gl3.mydata->capub, gl3.mydata->curve, ptest);

        g3HECQV recert(gl3.mydata->curve, ptest, g);
        uint8_t *received_cert = new uint8_t[31 + 6*size];
        memcpy(received_cert, buffrc+12*size, 31 + 6*size);

        recert.cert_pk_extraction(received_cert, capub);
        vehpk = recert.get_calculated_Qu();
        if(!vehpk.is_valid_divisor()) {
            return;
        }

        std::string issued_by, expires_on;
        issued_by = recert.get_issued_by();
        expires_on = recert.get_expires_on();

        divisorg3_to_bytes(gl3.vehpk[vid], vehpk, gl3.mydata->curve, ptest);

        if(issued_by.substr(0,4) != "DMV1" || expires_on.substr(6) <= "2023") {
            std::cout << RED_CODE << "Invalid Cert." << END_CODE << std::endl;
            return;
        }

        using namespace CryptoPP;


        AutoSeededRandomPool prng;

        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);

        prng.GenerateBlock(key, key.size());
        prng.GenerateBlock(iv, iv.size());

        std::string keystr, ivstr;
        HexEncoder encoder(new StringSink(keystr));
        encoder.Put(key, key.size());
        encoder.MessageEnd();

        HexEncoder encoder2(new StringSink(ivstr));
        encoder2.Put(iv, iv.size());
        encoder2.MessageEnd();
    
        std::string str1 = "Accept ";
        str1 += keystr.substr(0, 16);

        g3HEC::g3divisor mess1, a1, b1;
        
        int rt = text_to_divisorg3(mess1, str1, ptest, gl3.mydata->curve, enc);
        if(rt) {
            exit(1);
        }
        
        ZZ k;
        RandomBnd(k, ptest*ptest*ptest);
        a1 = k*g;
        b1 = k*vehpk + mess1;


        std::string str2 = keystr.substr(16);
        str2 += ivstr.substr(0, 10);


        g3HEC::g3divisor mess2, a2, b2;
        
        rt = text_to_divisorg3(mess2, str2, ptest, gl3.mydata->curve, enc);
        if(rt) {
            exit(1);
        }
        
        a2 = k*g;
        b2 = k*vehpk + mess2;



        std::string str3 = ivstr.substr(10);


        g3HEC::g3divisor mess3, a3, b3;
        
        rt = text_to_divisorg3(mess3, str3, ptest, gl3.mydata->curve, enc);
        if(rt) {
            exit(1);
        }
        
        a3 = k*g;
        b3 = k*vehpk + mess3;


        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        
        std::ostringstream oss;
        oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
        auto str = oss.str();
        std::string str4 = str;

        g3HEC::g3divisor mess4, a4, b4;
        
        rt = text_to_divisorg3(mess4, str4, ptest, gl3.mydata->curve, enc);
        if(rt) {
            exit(1);
        }
        
        a4 = k*g;
        b4 = k*vehpk + mess4;


        int onedivsize = 6*size;
        int size1no = 8*onedivsize;
        int fullsize1 = size1no + 6*signsize + 21;

        uint8_t cypherbuff[fullsize1+2];
        uint8_t temp[size1no];

        divisorg3_to_bytes(temp, a1, gl3.mydata->curve, ptest);
        divisorg3_to_bytes(temp+onedivsize, b1, gl3.mydata->curve, ptest);
        divisorg3_to_bytes(temp+2*onedivsize, a2, gl3.mydata->curve, ptest);
        divisorg3_to_bytes(temp+3*onedivsize, b2, gl3.mydata->curve, ptest);
        divisorg3_to_bytes(temp+4*onedivsize, a3, gl3.mydata->curve, ptest);
        divisorg3_to_bytes(temp+5*onedivsize, b3, gl3.mydata->curve, ptest);
        divisorg3_to_bytes(temp+6*onedivsize, a4, gl3.mydata->curve, ptest);
        divisorg3_to_bytes(temp+7*onedivsize, b4, gl3.mydata->curve, ptest);

        uint8_t mysiga[6*signsize];
        ZZ mysigb;
        std::string signstr = str1 + str2 + str3 + str4;
        sign_genus3(mysiga, mysigb, (uint8_t *)signstr.c_str(), signstr.length(), ptest);
        
        nok = verify_sig3(mysiga, mysigb, (uint8_t *)signstr.c_str(), signstr.length(), hpk3);
        if(nok)
            return;

        cypherbuff[0] = RECEIVE_ACCEPT_GL;
        cypherbuff[1] = glid;
        memcpy(cypherbuff+2, temp, size1no);
        memcpy(cypherbuff+size1no+2, mysiga, 6*signsize);
        BytesFromZZ(cypherbuff+size1no+6*signsize+2, mysigb, 21);

        Ptr<Node> n0 =  ns3::NodeList::GetNode(glid);
        Ptr <NetDevice> d0 = n0->GetDevice(0);
        Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

        Ptr<Node> n1 = ns3::NodeList::GetNode(vid);
        Ptr <NetDevice> nd0 = n1->GetDevice(0);

        Ptr <Packet> packet_i = Create<Packet>(cypherbuff, fullsize1+2);
        Mac48Address dest	= Mac48Address::ConvertFrom (nd0->GetAddress());
        uint16_t protocol = 0x88dc;
        TxInfo tx;
        tx.preamble = WIFI_PREAMBLE_LONG;
        tx.channelNumber = CCH;
        tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
        tx.priority = 7;	//We set the AC to highest prior
        tx.txPowerLevel = 7; //When we define TxPowerStar
        wd0->SendX(packet_i, dest, protocol, tx);
        gl3.symm_perveh[vid] = keystr;
        gl3.iv_perveh[vid] = ivstr;
        gl3.states[vid] = RECEIVE_ACCEPT_GL;
        free(siga);
        free(received_cert);
        break;
    }
    default:
        break;
    }
}



