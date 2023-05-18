#include "messages.h"


using namespace ns3;

void encrypt_message_AES (uint8_t *out, uint8_t *in, int size, std::string keystr, std::string ivstr) {
    using namespace CryptoPP;
    byte key[16], iv[16]; 
    CryptoPP::StringSource(keystr, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(key, CryptoPP::AES::DEFAULT_KEYLENGTH)
        )
    );

    CryptoPP::StringSource(ivstr, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(iv, CryptoPP::AES::DEFAULT_KEYLENGTH)
        )
    );

    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, 16, iv);

    StreamTransformationFilter encfilter(e, nullptr, BlockPaddingSchemeDef::PKCS_PADDING);
    encfilter.Put(in, size);
    encfilter.MessageEnd();
    encfilter.Get(out, size+16-size%16);
}

void decrypt_message_AES (uint8_t *out, uint8_t *in, int size, std::string keystr, std::string ivstr) {
    using namespace CryptoPP;
    byte key[16], iv[16]; 
    CryptoPP::StringSource(keystr, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(key, CryptoPP::AES::DEFAULT_KEYLENGTH)
        )
    );

    CryptoPP::StringSource(ivstr, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(iv, CryptoPP::AES::DEFAULT_KEYLENGTH)
        )
    );

    try {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, 16, iv);
        
        StreamTransformationFilter decfilter(d, nullptr, BlockPaddingSchemeDef::PKCS_PADDING);
        decfilter.Put(in, size);
        decfilter.MessageEnd();
        decfilter.Get(out, size);
    }
    catch(const Exception& ex) {
        std::cerr << "Decryption error: " << ex.what() << std::endl;
    }
}

void RSU_inform_GL(int ec_algo, int vid) {
    switch (ec_algo) {
        case 0:
        {
            ZZ ptest = to_ZZ(pt);
            field_t::init(ptest);
            int size = NumBytes(ptest);
            
            auto t = std::time(nullptr);
            auto tm = *std::localtime(&t);
            
            std::ostringstream oss;
            oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
            auto str = oss.str();
            std::string str11 = "Leader ";
            std::string finalstr = str11 + str;


            int signsize = NumBytes(to_ZZ(pg2));
            int sizenosign = finalstr.length()+1 + 31 + 2*size+1;

            int sizemod16 = sizenosign + 16 - sizenosign%16;
            int fullsize = sizemod16 + 2*signsize + 62;

            uint8_t sendbuff[fullsize+2];

            uint8_t temp[sizenosign];
            memcpy(temp, finalstr.c_str(), finalstr.length());
            temp[finalstr.length()] = '\0';
            memcpy(temp + finalstr.length()+1, rsug2[0].certs[vid], 31+2*size+1);


            /* Encrypt using symmetric key: */
            uint8_t cypher[sizemod16];

            encrypt_message_AES(cypher, temp, sizenosign, rsug2[0].symm_perveh[vid], rsug2[0].iv_perveh[vid]);
            

            ZZ sigb;
            uint8_t *siga = new uint8_t[2*signsize+1];

            sign_genus2(siga, sigb, temp, sizenosign, ptest);
            int nok = verify_sig2(siga, sigb, temp, sizenosign, hpk);
            
            if(nok)
                return;

            sendbuff[0] = GROUP_LEADER_INFORM;
            sendbuff[1] = vid;
            memcpy(sendbuff+2, cypher, sizemod16);
            memcpy(sendbuff+sizemod16+2, siga, 2*signsize+1);
            BytesFromZZ(sendbuff+sizemod16+2+2*signsize+1, sigb, 61);

            Ptr<Node> n1 =  ns3::NodeList::GetNode(rsuid);
            Ptr <NetDevice> d0 = n1->GetDevice(0);
            Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

            Ptr<Node> n0 = ns3::NodeList::GetNode(vid);
            Ptr <NetDevice> nd0 = n0->GetDevice(0);

            Ptr <Packet> packet_i = Create<Packet>(sendbuff, fullsize+2);
            Mac48Address dest = Mac48Address::ConvertFrom (nd0->GetAddress());

            uint16_t protocol = 0x88dc;
            TxInfo tx;
            tx.preamble = WIFI_PREAMBLE_LONG;
            tx.channelNumber = CCH;
            tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
            tx.priority = 7;	//We set the AC to highest prior
            tx.txPowerLevel = 7; //When we define TxPowerStar
            wd0->SendX(packet_i, dest, protocol, tx);
            rsug2[0].glid = vid;
            break;
        }
        case 1: {
            CryptoPP::AutoSeededRandomPool prng;  
            int size = rsuec[0].group.GetCurve().FieldSize().ByteCount();
            auto t = std::time(nullptr);
            auto tm = *std::localtime(&t);
            
            std::ostringstream oss;
            oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
            auto str = oss.str();
            std::string str11 = "Leader ";
            std::string finalstr = str11 + str;

            int sizenosign = finalstr.length()+1 + 31 + 2*size+1;
            int sizemod16 = sizenosign + 16 - sizenosign%16;

            uint8_t temp[sizenosign];
            memcpy(temp, finalstr.c_str(), finalstr.length());
            temp[finalstr.length()] = '\0';
            memcpy(temp + finalstr.length()+1, rsuec[0].certs[vid], 31+2*size+1);

            uint8_t cypher[sizemod16];
            encrypt_message_AES(cypher, temp, sizenosign, rsuec[0].symm_perveh[vid], rsuec[0].iv_perveh[vid]);
            
            std::string sigecc;
            sign_ec(sigecc, rsuec[0].priv, temp, sizenosign);
            int nok = verify_ec(sigecc, rsuec[0].rsupub, temp, sizenosign);

            if (nok)
                return;
            
            int fullsize = sizemod16 + sigecc.length() +1;
            uint8_t sendbuff[fullsize+2];
            sendbuff[0] = GROUP_LEADER_INFORM;
            sendbuff[1] = vid;
            memcpy(sendbuff+2, cypher, sizemod16);
            memcpy(sendbuff+sizemod16+2, sigecc.c_str(), sigecc.length());
            sendbuff[fullsize+1] = 0;

            Ptr<Node> n1 =  ns3::NodeList::GetNode(rsuid);
            Ptr <NetDevice> d0 = n1->GetDevice(0);
            Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

            Ptr<Node> n0 = ns3::NodeList::GetNode(vid);
            Ptr <NetDevice> nd0 = n0->GetDevice(0);

            Ptr <Packet> packet_i = Create<Packet>(sendbuff, fullsize+2);
            Mac48Address dest = Mac48Address::ConvertFrom (nd0->GetAddress());

            uint16_t protocol = 0x88dc;
            TxInfo tx;
            tx.preamble = WIFI_PREAMBLE_LONG;
            tx.channelNumber = CCH;
            tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
            tx.priority = 7;	//We set the AC to highest prior
            tx.txPowerLevel = 7; //When we define TxPowerStar
            wd0->SendX(packet_i, dest, protocol, tx);
            rsuec[0].glid = vid;

            break;
        }
        case 2: {
            ZZ ptest = to_ZZ(pg3);
            field_t::init(ptest);
            int size = NumBytes(ptest);
            
            auto t = std::time(nullptr);
            auto tm = *std::localtime(&t);
            
            std::ostringstream oss;
            oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
            auto str = oss.str();
            std::string str11 = "Leader ";
            std::string finalstr = str11 + str;


            int signsize = NumBytes(to_ZZ(pg2));
            int sizenosign = finalstr.length()+1 + 31 + 6*size;

            int sizemod16 = sizenosign + 16 - sizenosign%16;
            int fullsize = sizemod16 + 2*signsize + 62;

            uint8_t sendbuff[fullsize+2];

            uint8_t temp[sizenosign];
            memcpy(temp, finalstr.c_str(), finalstr.length());
            temp[finalstr.length()] = '\0';
            memcpy(temp + finalstr.length()+1, rsug3[0].certs[vid], 31+6*size);


            /* Encrypt using symmetric key: */
            uint8_t cypher[sizemod16];

            encrypt_message_AES(cypher, temp, sizenosign, rsug3[0].symm_perveh[vid], rsug3[0].iv_perveh[vid]);
            

            ZZ sigb;
            uint8_t *siga = new uint8_t[2*signsize+1];

            sign_genus2(siga, sigb, temp, sizenosign, ptest);
            int nok = verify_sig2(siga, sigb, temp, sizenosign, hpk);
            
            if(nok)
                return;

            sendbuff[0] = GROUP_LEADER_INFORM;
            sendbuff[1] = vid;
            memcpy(sendbuff+2, cypher, sizemod16);
            memcpy(sendbuff+sizemod16+2, siga, 2*signsize+1);
            BytesFromZZ(sendbuff+sizemod16+2+2*signsize+1, sigb, 61);

            Ptr<Node> n1 =  ns3::NodeList::GetNode(rsuid);
            Ptr <NetDevice> d0 = n1->GetDevice(0);
            Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

            Ptr<Node> n0 = ns3::NodeList::GetNode(vid);
            Ptr <NetDevice> nd0 = n0->GetDevice(0);

            Ptr <Packet> packet_i = Create<Packet>(sendbuff, fullsize+2);
            Mac48Address dest = Mac48Address::ConvertFrom (nd0->GetAddress());

            uint16_t protocol = 0x88dc;
            TxInfo tx;
            tx.preamble = WIFI_PREAMBLE_LONG;
            tx.channelNumber = CCH;
            tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
            tx.priority = 7;	//We set the AC to highest prior
            tx.txPowerLevel = 7; //When we define TxPowerStar
            wd0->SendX(packet_i, dest, protocol, tx);
            rsug3[0].glid = vid;

            break;
        }
        
        default:
            break;
    }
}



void extract_GLProof_Broadcast(uint8_t *buffrc, int ec_algo, int vid) {
    switch (ec_algo)
    {
    case 0:
    {
        Vehicle_data_g2 *veh1g2 = &vehg2[vid];
        ZZ ptest = to_ZZ(pt);
        field_t::init(ptest);
        int size = NumBytes(ptest);
        
        int sizenosign = 27 + 31 + 2*size + 1;
        int sizemod16 = sizenosign + 16 - sizenosign%16;
        uint8_t decrypted[sizemod16];
        
        decrypt_message_AES(decrypted, buffrc, sizemod16, veh1g2->symm, veh1g2->iv);
        
        std::string lead((char*)decrypted, 27);
        std::string tocmp = "Leader";
        if(memcmp(lead.c_str(), tocmp.c_str(), 6) != 0) {
            return;
        }
        else
            std::cout << BOLD_CODE << GREEN_CODE << "Node " << vid << " is selected as GL!" << END_CODE << std::endl;

        int nok = validate_timestamp(lead.substr(7, 27));
        if(nok)
            return;
        else 
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;

        NS_G2_NAMESPACE::divisor g, capub, mypub;
        bytes_to_divisor(g, veh1g2->g, veh1g2->curve, ptest);
        bytes_to_divisor(capub, veh1g2->capub, veh1g2->curve, ptest);
        bytes_to_divisor(mypub, veh1g2->pub, veh1g2->curve, ptest);
        g2HECQV cert2(veh1g2->curve, ptest, g);
        cert2.cert_pk_extraction(decrypted+27, capub);
        if(mypub != cert2.get_calculated_Qu()) {
            std::cout << BOLD_CODE << RED_CODE << "Certificate provided to GL is incorrect." << END_CODE << std::endl;
            return;
        }

        int signsize = NumBytes(to_ZZ(pg2));
        uint8_t *siga = new uint8_t[2*signsize+1];
        ZZ sigb;

        memcpy(siga, buffrc+sizemod16, 2*signsize+1);
        sigb = -ZZFromBytes(buffrc+sizemod16+2*signsize+1, 61);

        nok = verify_sig2(siga, sigb, decrypted, sizenosign, hpk);

        if(nok) {
            sigb = -sigb;
            nok = verify_sig2(siga, sigb, decrypted, sizenosign, hpk);
            if(nok)
                return;
        }

        gl2.mydata = veh1g2;
        gl2.mydata->state = IS_GROUP_LEADER;
        std::cout << BOLD_CODE << YELLOW_CODE << "Group Leader " << vid << " broadcasting proof of leadership for new vehicles..." << END_CODE << std::endl << std::endl;

        int sendsize1 = 2 + sizenosign + 2*signsize + 62;
        int finalsendsize = sendsize1;
        uint8_t sendbuff[finalsendsize];

        sendbuff[0] = IS_GROUP_LEADER;
        sendbuff[1] = vid;
        memcpy(sendbuff+2, decrypted, sizenosign);
        memcpy(sendbuff+2+sizenosign, siga, 2*signsize+1);
        memcpy(sendbuff+2+sizenosign+2*signsize+1, buffrc+sizemod16+2*signsize+1, 61);
        
        Ptr<Node> n1 =  ns3::NodeList::GetNode(vid);
        Ptr <NetDevice> d0 = n1->GetDevice(0);
        Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

        Ptr <Packet> packet_i;
        Mac48Address dest = Mac48Address::GetBroadcast();

        uint16_t protocol = 0x88dc;
        TxInfo tx;
        tx.preamble = WIFI_PREAMBLE_LONG;
        tx.channelNumber = CCH;
        tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
        tx.priority = 7;	//We set the AC to highest prior
        tx.txPowerLevel = 7; //When we define TxPowerStar

        for(uint32_t i=0; i < 250; i+=2) {
            packet_i = Create<Packet>(sendbuff, finalsendsize);
            Simulator::Schedule(Seconds(i), &WaveNetDevice::SendX, wd0, packet_i, dest, protocol, tx);
        }

        break;
    }
    
    case 1: {
        Vehicle_data_ec *veh1ec = &vehec[vid];
        CryptoPP::AutoSeededRandomPool prng;  
        int size = veh1ec->group.GetCurve().FieldSize().ByteCount();

        int sizenosign = 27 + 31 + 2*size + 1;
        int sizemod16 = sizenosign + 16 - sizenosign%16;
        uint8_t decrypted[sizemod16];
        
        decrypt_message_AES(decrypted, buffrc, sizemod16, veh1ec->symm, veh1ec->iv);
        std::string lead((char*)decrypted, 27);
        std::string tocmp = "Leader";
        if(memcmp(lead.c_str(), tocmp.c_str(), 6) != 0) {
            return;
        }
        else
            std::cout << BOLD_CODE << GREEN_CODE << "Node " << vid << " is selected as GL!" << END_CODE << std::endl;

        int nok = validate_timestamp(lead.substr(7, 27));
        if(nok)
            return;
        else 
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;


        ECQV cert(veh1ec->group);
        cert.cert_pk_extraction(decrypted+27, veh1ec->capub);
        if(veh1ec->pub.x != cert.get_calculated_Qu().x) {
            std::cout << BOLD_CODE << RED_CODE << "Certificate provided to GL is incorrect." << END_CODE << std::endl;
            return;
        }

        char sig[2*size+1];
        memcpy(sig, buffrc+sizemod16, 2*size+1);
        std::string sigecc(sig, 2*size+1);

        nok = verify_ec(sigecc, veh1ec->rsupub, decrypted, sizenosign);

        if(nok) {
            return;
        }

        glec.mydata = veh1ec;
        glec.mydata->state = IS_GROUP_LEADER;
        std::cout << BOLD_CODE << YELLOW_CODE << "Group Leader " << vid << " broadcasting proof of leadership for new vehicles..." << END_CODE << std::endl << std::endl;

        int sendsize = 2 + sizenosign + 2*size + 1;
        uint8_t sendbuff[sendsize];

        sendbuff[0] = IS_GROUP_LEADER;
        sendbuff[1] = vid;
        memcpy(sendbuff+2, decrypted, sizenosign);
        memcpy(sendbuff+2+sizenosign, buffrc+sizemod16, 2*size+1);

        Ptr<Node> n1 =  ns3::NodeList::GetNode(vid);
        Ptr <NetDevice> d0 = n1->GetDevice(0);
        Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

        Ptr <Packet> packet_i;
        Mac48Address dest = Mac48Address::GetBroadcast();

        uint16_t protocol = 0x88dc;
        TxInfo tx;
        tx.preamble = WIFI_PREAMBLE_LONG;
        tx.channelNumber = CCH;
        tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
        tx.priority = 7;	//We set the AC to highest prior
        tx.txPowerLevel = 7; //When we define TxPowerStar

        for(uint32_t i=0; i < 250; i+=2) {
            packet_i = Create<Packet>(sendbuff, sendsize);
            Simulator::Schedule(Seconds(i), &WaveNetDevice::SendX, wd0, packet_i, dest, protocol, tx);
        }

        break;
    }

    case 2: {
        Vehicle_data_g3 *veh1g3 = &vehg3[vid];
        ZZ ptest = to_ZZ(pg3);
        field_t::init(ptest);
        int size = NumBytes(ptest);
        
        int sizenosign = 27 + 31 + 6*size;
        int sizemod16 = sizenosign + 16 - sizenosign%16;
        uint8_t decrypted[sizemod16];
        
        decrypt_message_AES(decrypted, buffrc, sizemod16, veh1g3->symm, veh1g3->iv);
        
        std::string lead((char*)decrypted, 27);
        std::string tocmp = "Leader";
        if(memcmp(lead.c_str(), tocmp.c_str(), 6) != 0) {
            return;
        }
        else
            std::cout << BOLD_CODE << GREEN_CODE << "Node " << vid << " is selected as GL!" << END_CODE << std::endl;

        int nok = validate_timestamp(lead.substr(7, 27));
        if(nok)
            return;
        else 
            std::cout << BOLD_CODE << GREEN_CODE << "Timestamp is valid." << END_CODE << std::endl;

        g3HEC::g3divisor g, capub, mypub;
        bytes_to_divisorg3(g, veh1g3->g, veh1g3->curve, ptest);
        bytes_to_divisorg3(capub, veh1g3->capub, veh1g3->curve, ptest);
        bytes_to_divisorg3(mypub, veh1g3->pub, veh1g3->curve, ptest);
        g3HECQV cert2(veh1g3->curve, ptest, g);
        cert2.cert_pk_extraction(decrypted+27, capub);
        if(mypub != cert2.get_calculated_Qu()) {
            std::cout << BOLD_CODE << RED_CODE << "Certificate provided to GL is incorrect." << END_CODE << std::endl;
            return;
        }

        int signsize = NumBytes(to_ZZ(pg2));
        uint8_t *siga = new uint8_t[2*signsize+1];
        ZZ sigb;

        memcpy(siga, buffrc+sizemod16, 2*signsize+1);
        sigb = -ZZFromBytes(buffrc+sizemod16+2*signsize+1, 61);

        nok = verify_sig2(siga, sigb, decrypted, sizenosign, hpk);

        if(nok) {
            sigb = -sigb;
            nok = verify_sig2(siga, sigb, decrypted, sizenosign, hpk);
            if(nok)
                return;
        }

        gl3.mydata = veh1g3;
        gl3.mydata->state = IS_GROUP_LEADER;
        std::cout << BOLD_CODE << YELLOW_CODE << "Group Leader " << vid << " broadcasting proof of leadership for new vehicles..." << END_CODE << std::endl << std::endl;

        int sendsize1 = 2 + sizenosign + 2*signsize + 62;
        int finalsendsize = sendsize1;
        uint8_t sendbuff[finalsendsize];

        sendbuff[0] = IS_GROUP_LEADER;
        sendbuff[1] = vid;
        memcpy(sendbuff+2, decrypted, sizenosign);
        memcpy(sendbuff+2+sizenosign, siga, 2*signsize+1);
        memcpy(sendbuff+2+sizenosign+2*signsize+1, buffrc+sizemod16+2*signsize+1, 61);
        

        Ptr<Node> n1 =  ns3::NodeList::GetNode(vid);
        Ptr <NetDevice> d0 = n1->GetDevice(0);
        Ptr <WaveNetDevice> wd0 = DynamicCast<WaveNetDevice> (d0);

        Ptr <Packet> packet_i;
        Mac48Address dest = Mac48Address::GetBroadcast();

        uint16_t protocol = 0x88dc;
        TxInfo tx;
        tx.preamble = WIFI_PREAMBLE_LONG;
        tx.channelNumber = CCH;
        tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");
        tx.priority = 7;	//We set the AC to highest prior
        tx.txPowerLevel = 7; //When we define TxPowerStar

        for(uint32_t i=0; i < 250; i+=2) {
            packet_i = Create<Packet>(sendbuff, finalsendsize);
            Simulator::Schedule(Seconds(i), &WaveNetDevice::SendX, wd0, packet_i, dest, protocol, tx);
        }

        break;
    }
    default:
        break;
    }
}
