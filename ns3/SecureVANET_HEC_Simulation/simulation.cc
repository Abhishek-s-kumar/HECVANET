#include "ns3/wave-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "custom-mobility-model.h"
#include "ns3/node.h"
#include "ns3/basic-energy-source-helper.h"
#include "hec_cert.h"
#include "sign.h"
#include "crypto_ecc.h"
#include "messages.h"
#include "ns2-node-utility.h"
#include "wave-energy-helper.h"

#include <set>
#include <chrono>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("WaveExample1");

uint32_t ec_algo = 0;
uint32_t get_metrics = 0;
int rsuid = 63;
uint16_t seq, seq2;

Vehicle_data_g2 vehg2[100];
RSU_data_g2 rsug2[5];
GroupLeader_data_g2 gl2;

Vehicle_data_g3 vehg3[100];
RSU_data_g3 rsug3[5];
GroupLeader_data_g3 gl3;

Vehicle_data_ec vehec[100];
RSU_data_ec rsuec[5];
GroupLeader_data_ec glec;

uint8_t hpk[23] = {0x87,0x75,0x6e,0x0e,0x30,0x8e,0x59,0xa4,0x04,0x48,0x01,
0x17,0x4c,0x4f,0x01,0x4d,0x16,0x78,0xe8,0x56,0x6e,0x03,0x02};

double exit_time[63];
float vehicle_Energy_Consumption[64];
float prev_energy[64];
double prev_times[64];
Ptr<EnergySourceContainer> Vehicle_sources;


//Note: this is a promiscuous trace for all packet reception. This is also on physical layer, so packets still have WifiMacHeader
void Rx (std::string context, Ptr <const Packet> packet, uint16_t channelFreqMhz,  WifiTxVector txVector,MpduInfo aMpdu, SignalNoiseDbm signalNoise)
{

  //context will include info about the source of this event. Use string manipulation if you want to extract info.
  
  Ptr <Packet> myPacket = packet->Copy();
  //Print the info.
  

  //We can also examine the WifiMacHeader
  WifiMacHeader hdr;
  WifiMacHeader hdr1;
  WifiMacTrailer trl;

  uint8_t *buffrc = new uint8_t[packet->GetSize()];
  int vid = 0;
  if(context[11] == '/') 
    vid = context[10] - 48;
  else
    vid = (context[10] - 48)*10 + (context[11] - 48);

  if(Now() >= Seconds(exit_time[vid])) {
    return;
  }

  int state, onglstate=0;
  if(ec_algo == 0) {
    state = vehg2[vid].state;
  } 
  else if(ec_algo == 1) {
    state = vehec[vid].state;
  }
  else{
    state = vehg3[vid].state;
  }
  
  if (packet->PeekHeader(hdr))
  {
    myPacket->RemoveHeader(hdr1);
    myPacket->RemoveTrailer(trl);
    myPacket->CopyData(buffrc, packet->GetSize());

    Ptr<Node> n1 = ns3::NodeList::GetNode(vid);
    Ptr <NetDevice> nd0 = n1->GetDevice(0);

    if(hdr1.GetAddr1() != nd0->GetAddress() && hdr1.GetAddr1() != "ff:ff:ff:ff:ff:ff") {
      return;
    }

    // std::cout << std::endl << BOLD_CODE <<  context << END_CODE << std::endl;

    // std::cout << "\tSize=" << packet->GetSize()
    //     << " Freq="<<channelFreqMhz
    //     << " Mode=" << txVector.GetMode()
    //     << " Signal=" << signalNoise.signal
    //     << " Noise=" << signalNoise.noise << std::endl;
    // std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2() << std::endl << std::endl;
  }
  else {
    return;
  }

  switch (ec_algo)
  {
  case 0: {
    onglstate = gl2.states[buffrc[9]];
    break;
  }
  case 1: {
    onglstate = glec.states[buffrc[9]];
    break;
  }
  case 2: {
    onglstate = gl3.states[buffrc[9]];
    break;
  }
  default:
    break;
  }

  if(buffrc[8] == RECEIVE_CERT && state == RECEIVE_CERT && (packet->GetSize()) > 20) {
    receive_Cert_Send_Join(buffrc, ec_algo, vid);
  }

  else if(buffrc[8] == RECEIVE_ACCEPT_KEY && state == RECEIVE_ACCEPT_KEY && (packet->GetSize()) > 20) {
    int rid = buffrc[9];
    extract_Symmetric(buffrc+10, ec_algo, vid, rid);
  }

  else if(buffrc[8] == GROUP_LEADER_INFORM && state == ON_SYMMETRIC_ENC && (packet->GetSize()) > 20) {
    extract_GLProof_Broadcast(buffrc+10, ec_algo, vid);
  }

  else if(buffrc[8] == IS_GROUP_LEADER && state == ON_SYMMETRIC_ENC && vid%2 == 0 && (packet->GetSize()) > 20) {
    int glid = buffrc[9];
    receive_GLCert_Send_Join(buffrc+10, ec_algo, vid, glid);
  }

  else if(buffrc[8] == RECEIVE_ACCEPT_GL && state == IS_GROUP_LEADER && onglstate != RECEIVE_ACCEPT_GL  && (packet->GetSize()) > 20) { 
    extract_GLJoin_SendAccept(buffrc+10, ec_algo, buffrc[9], vid);
  }

  else if(buffrc[8] == RECEIVE_ACCEPT_GL && state == RECEIVE_ACCEPT_GL && (packet->GetSize()) > 20) {
    extract_Symmetric(buffrc+10, ec_algo, vid, buffrc[9], 1);
  }

  else if(buffrc[8] == INFORM_MSG && state == IS_GROUP_LEADER && (packet->GetSize()) > 20) {
    extract_Inform_Aggregate(buffrc+10, ec_algo, buffrc[9], vid);
  }
}

void Rx1(std::string context, Ptr <const Packet> packet, uint16_t channelFreqMhz,  WifiTxVector txVector,MpduInfo aMpdu, SignalNoiseDbm signalNoise) {
  
  Ptr <Packet> myPacket = packet->Copy();


  //We can also examine the WifiMacHeader
  WifiMacHeader hdr;
  WifiMacHeader hdr1;
  WifiMacTrailer trl;

  uint8_t *buffrc = new uint8_t[packet->GetSize()];
  int prot,vid, rid=0, glid=0;
  
  if (packet->PeekHeader(hdr))
  {
    myPacket->RemoveHeader(hdr1);
    myPacket->RemoveTrailer(trl);
    myPacket->CopyData(buffrc, packet->GetSize());

    Ptr<Node> n0 = ns3::NodeList::GetNode(rsuid);
    Ptr <NetDevice> nd0 = n0->GetDevice(0);
    if(hdr1.GetAddr1() != nd0->GetAddress() && hdr1.GetAddr1() != "ff:ff:ff:ff:ff:ff") {
      return;
    }
    
    prot = (int)buffrc[8];
    vid = (int)buffrc[9];

    switch (ec_algo)
    {
    case 0: {
      glid = rsug2[rid].glid;
      break;
    }
    case 1: {
      glid = rsuec[rid].glid;
      break;
    }
    case 2: {
      glid = rsug3[rid].glid;
      break;
    }
    default:
      break;
    }

  }
  else {
    return;
  }
  if(prot == RECEIVE_CERT && (packet->GetSize()) > 20) {
    // std::cout << std::endl << BOLD_CODE <<  context << END_CODE << std::endl;
    // std::cout << "\tSize=" << packet->GetSize()
    //     << " Freq="<<channelFreqMhz
    //     << " Mode=" << txVector.GetMode()
    //     << " Signal=" << signalNoise.signal
    //     << " Noise=" << signalNoise.noise << std::endl;
    // std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2() << std::endl << std::endl;

    if(ec_algo == 0 && rsug2[rid].states[vid] == RECEIVE_CERT) {
      extract_RSU_SendAccept_g2(buffrc+10, vid, rid);
    }
    else if (ec_algo == 1 && rsuec[rid].states[vid] == RECEIVE_CERT) {
      extract_RSU_SendAccept_ec(buffrc+10, vid, rid);
    }
    else if (ec_algo == 2 && rsug3[rid].states[vid] == RECEIVE_CERT){
      extract_RSU_SendAccept_g3(buffrc+10, vid, rid);
    }
  }
  else if(prot == INFORM_MSG && glid == vid && (packet->GetSize()) > 20) {
    extract_Info_RSU(buffrc+11, buffrc[10], ec_algo, glid);
  }
}


/*
 * This function works for ns-3.30 onwards. For previous version, remove the last parameter (the "WifiPhyRxfailureReason")
 */
void RxDrop (std::string context, Ptr<const Packet> packet, ns3::WifiPhyRxfailureReason reason)
{
  WifiMacHeader hdr;
	if (packet->PeekHeader(hdr))
	{
    if(seq == hdr.GetSequenceNumber() || hdr.GetAddr2() == "00:00:00:00:00:00") {
      return;
    }
    std::cout << std::endl << BOLD_CODE << YELLOW_CODE << "Packet Rx Dropped!" << END_CODE << std::endl;
    //From ns-3.30, the reasons are defined in an enum type in ns3::WifiPhy class.
    std::cout << " Reason : " << reason << std::endl;
    std::cout << context << std::endl;

    seq = hdr.GetSequenceNumber();

		std::cout << " Destination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2() << "\tSeq No. " << seq << std::endl << std::endl;
	}
}

//Fired when a packet is Enqueued in MAC
void EnqueueTrace(std::string context, Ptr<const WifiMacQueueItem> item)
{
	//std::cout << TEAL_CODE << "A Packet was enqueued : " << context << END_CODE << std::endl;

	Ptr <const Packet> p = item->GetPacket();
	/*
	 * Do something with the packet, like attach a tag. ns3 automatically attaches a timestamp for enqueued packets;
	 */

}
//Fired when a packet is Dequeued from MAC layer. A packet is dequeued before it is transmitted.
void DequeueTrace(std::string context, Ptr<const WifiMacQueueItem> item)
{
	//std::cout << TEAL_CODE << "A Packet was dequeued : " << context << END_CODE << std::endl;

	Ptr <const Packet> p = item->GetPacket();
	Time queue_delay = Simulator::Now() - item->GetTimeStamp();

	//Keep in mind that a packet might get dequeued (dropped_ if it exceeded MaxDelay (default is 500ms)
	//std::cout << "\tQueuing delay=" << queue_delay << std::endl;


}


void PrintInfo ()
{
    std::set<int> vehreg, vehgl;
    int numrsu, numgl=0, numacc=0, numsymgl;
    if(ec_algo == 0) {
      numrsu = rsug2[0].numveh;
      numgl = gl2.numveh;
    }
    else if(ec_algo == 1) {
      numrsu = rsuec[0].numveh;
      numgl = glec.numveh;
    }
    else{
      numrsu = rsug3[0].numveh;
      numgl = gl3.numveh;
    }

    for(int i=0; i < rsuid; i++) {
      switch (ec_algo)
      {
      case 0:
        if(vehg2[i].state >= 2) {
          numacc++;
          vehreg.insert(i);
        }
        if(vehg2[i].state == ON_SYMM_GL) {
          numsymgl++;
          vehgl.insert(i);
        }
        break;
      case 1:
        if(vehec[i].state >= 2) {
          numacc++;
          vehreg.insert(i);
        }
        if(vehec[i].state == ON_SYMM_GL) {
          numsymgl++;
          vehgl.insert(i);
        }
        break;
      case 2:
        if(vehg3[i].state >= 2) {
          numacc++;
          vehreg.insert(i);
        }
        if(vehg3[i].state == ON_SYMM_GL) {
          numsymgl++;
          vehgl.insert(i);
        }
        break;
      default:
        break;
      }
    }

    std::cout << BOLD_CODE << "Registered vehicles in RSU: " << numrsu << " Received Symmetric: ";
    for(auto& id : vehreg) {
      std::cout << id << ' ';
    }
    std::cout << END_CODE << std::endl;

    if(Now() > Seconds(150)) {
      std::cout << BOLD_CODE << "Registered vehicles in GL: " << numgl << " Received Symmetric: ";
      for(auto& id : vehgl) {
        std::cout << id << ' ';
      }
      std::cout << END_CODE << std::endl;
    }

    Simulator::Schedule (Seconds (4), &PrintInfo);
}

void SelectGL(std::set<double> endsim_cars) {
    int rand_id;
    do {
      std::random_device rd;
      std::mt19937 gen(rd());
      std::uniform_int_distribution<> dis(0, 58);
      
      rand_id = dis(gen);
    } while((endsim_cars.find(rand_id) == endsim_cars.end()));

    std::cout << std::endl << BOLD_CODE << YELLOW_CODE << "Selected GL: " << rand_id << END_CODE << std::endl;
    
    for (auto it: endsim_cars) {
      prev_energy[(int)it] = Vehicle_sources->Get((int)it)->GetRemainingEnergy();
      if((int) it != 60 && (int) it != 61 && (int) it != 62)
        prev_times[(int)it] = Simulator::Now().GetSeconds();
    }

    RSU_inform_GL(ec_algo, rand_id);
    std::string conn = "/NodeList/";
    conn += to_string(rand_id) + "/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/PhyRxDrop";
    Config::Connect(conn, MakeCallback (&RxDrop) );

}

void set_Initial_Energy(int vid) {
  prev_energy[vid] = Vehicle_sources->Get(vid)->GetRemainingEnergy();
}

int main (int argc, char *argv[])
{
  CommandLine cmd;
  cmd.AddValue("algo", "Encryption Algorithm", ec_algo);
  cmd.AddValue("metrics", "Get the metrics for a specific algo", get_metrics);

  cmd.Parse (argc, argv);

  if(ec_algo < 0 || ec_algo > 2) {
    std::cout << "Encryption algorithm ids are:\n\tHEC genus 2: 0\n\tECC: 1\n\tHEC genus 3: 2" << std::endl;
    exit(1);
  }

  int fullsize=0;
  uint8_t *cypher_buff;

  if(ec_algo == 0) {
    std::cout << "Using ElGamal with Genus 2 HEC for message encryption\nHECQV for certificates\nElGamal HEC genus 2 signatures" << std::endl;
    ZZ ptest = to_ZZ(pt);
    field_t::init(ptest);
    std::cout << "Using p: " << ptest << " of size: " << NumBits(ptest) << std::endl;
            
    NS_G2_NAMESPACE::g2hcurve curve;

    NS_G2_NAMESPACE::divisor g, h, rsupub, capub;
    ZZ rsupriv;
    UnifiedEncoding enc(ptest, 10, 4, 2);
    rsug2[0].u = 10;
    rsug2[0].w = 4;
    std::string base = "BaseforGenerator";

    auto start = chrono::high_resolution_clock::now();

    int rt = text_to_divisor(g, base, ptest, curve, enc);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Text to divisor: "
         << duration.count() << " microseconds" << endl;
    }

    if(rt) {
      exit(1);
    }

    ZZ capriv = to_ZZ("15669032110011017415376799675649225245106855015484313618141721121181084494176");
    ZZ x;
    capub = capriv*g;
    /* private key x */

    start = chrono::high_resolution_clock::now();

    RandomBnd(x, ptest*ptest);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Private key generation: "
         << duration.count() << " microseconds" << endl;
    }

    divisor_to_bytes(rsug2[0].capub, capub, curve, ptest);

    start = chrono::high_resolution_clock::now();
    
    h = x * g;

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Public key generation: "
         << duration.count() << " microseconds" << endl;
    }

    g2HECQV cert2(curve, ptest, g);
    int size = NumBytes(ptest);
    uint8_t *encoded2 = new uint8_t[31 + 2*size+1];

    start = chrono::high_resolution_clock::now();

    cert2.cert_generate(encoded2, "RSU0001", h, capriv);


    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Certificate generation: "
         << duration.count() << " microseconds" << endl;
    }

    start = chrono::high_resolution_clock::now();
    
    cert2.cert_pk_extraction(encoded2, capub);
    
    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Certificate public key extraction: "
         << duration.count() << " microseconds" << endl;
    }

    start = chrono::high_resolution_clock::now();

    cert2.cert_reception(encoded2, x);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Certificate private key reception: "
         << duration.count() << " microseconds" << endl;
    }
    
    rsupub = cert2.get_calculated_Qu();
    rsupriv = cert2.get_extracted_du();

    rsug2[0].priv = rsupriv;
    rsug2[0].curve = curve;
    divisor_to_bytes(rsug2[0].rsupub, rsupub, curve, ptest);
    divisor_to_bytes(rsug2[0].g, g, curve, ptest);

    fullsize = 1 + 31 + 2*size+1 + 2 + base.length() + 1;

    cypher_buff = new uint8_t[fullsize];
    cypher_buff[0] = 0;
    memcpy(cypher_buff+1, encoded2, 31 + 2*size+1);
    uint8_t w, u;
    w = 10;
    u = 4;
    cypher_buff[31+2*size+2] = w;
    cypher_buff[31+2*size+3] = u;
    memcpy(cypher_buff+31+2*size+4, base.c_str(), base.length()+1);
    if(get_metrics != 0)
      std::cout << "RSU_CERT_BROADCAST message size: " << fullsize << std::endl;
  }

  else if (ec_algo == 1) {
    std::cout << "Using ElGamal with ECC for message encryption\nECQV for certificates\nECDSA signatures" << std::endl;
    std::cout << "Using curve secp256r1 parameters" << std::endl;
    
    
    CryptoPP::AutoSeededRandomPool prng;    
    GroupParameters group;
    group.Initialize(CryptoPP::ASN1::secp256r1());
    
    rsuec[0].group = group;

    ECQV cert(group);

    // private key
    auto start = chrono::high_resolution_clock::now();

    CryptoPP::Integer priv_ecc(prng, CryptoPP::Integer::One(), group.GetMaxExponent());


    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Private key generation: "
         << duration.count() << " microseconds" << endl;
    }

    CryptoPP::Integer capriv("99904945320188894543539641655649253921899278606834393872940151579788317849983");
    
    start = chrono::high_resolution_clock::now();

    Element pub = group.ExponentiateBase(priv_ecc);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Public key generation: "
         << duration.count() << " microseconds" << endl;
    }

    int size = group.GetCurve().FieldSize().ByteCount();
    uint8_t *encoded = new uint8_t[31 + size+1];
    vector<unsigned char> cert_vec;
    
    start = chrono::high_resolution_clock::now();

    cert_vec = cert.cert_generate("RSU0001", pub);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Certificate generation: "
         << duration.count() << " microseconds" << endl;
    }

    memcpy(encoded, cert_vec.data(), 31 + size + 1);

    start = chrono::high_resolution_clock::now();

    Element rsupub = cert.cert_pk_extraction(cert_vec);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Certificate public key extraction: "
         << duration.count() << " microseconds" << endl;
    }
    
    start = chrono::high_resolution_clock::now();

    CryptoPP::Integer rsupriv = cert.cert_reception(cert_vec, priv_ecc);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Certificate private key extraction: "
         << duration.count() << " microseconds" << endl;
    }

    rsuec[0].capub = group.ExponentiateBase(capriv);

    // Element rsupub = cert.get_calculated_Qu();
    // CryptoPP::Integer rsupriv = cert.get_extracted_du();

    rsuec[0].priv = rsupriv;
    rsuec[0].rsupub = rsupub;
    
    fullsize = 1 + 31 + size + 1;

    cypher_buff = new uint8_t[fullsize];
    cypher_buff[0] = 0;
    memcpy(cypher_buff+1, encoded, 31 + size+1);
    if(get_metrics != 0)
      std::cout << "RSU_CERT_BROADCAST message size: " << fullsize << std::endl;
  }

  else{
    std::cout << "Using ElGamal with Genus 3 HEC for message encryption\nHECQV for certificates\nElGamal HEC genus 3 signatures" << std::endl;
    ZZ ptest = to_ZZ(pg3);
    field_t::init(ptest);
    std::cout << "Using p: " << ptest << " of size: " << NumBits(ptest) << std::endl;
    g3HEC::g3hcurve curve;

    g3HEC::g3divisor g, h, rsupub, capub;
    ZZ rsupriv;
    UnifiedEncoding enc(ptest, 10, 4, 3);
    rsug3[0].u = 10;
    rsug3[0].w = 4;

    std::string base = "BaseforGenerator";

    auto start = chrono::high_resolution_clock::now();
    int rt = text_to_divisorg3(g, base, ptest, curve, enc);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Text to divisor: "
         << duration.count() << " microseconds" << endl;
    }

    if(rt) {
      exit(1);
    }

    ZZ capriv = to_ZZ("247253210584643408262663087671537517974691545498905118366998662050233012073014");
    ZZ x;

    capub = capriv*g;

    divisorg3_to_bytes(rsug3[0].capub, capub, curve, ptest);
    
    /* private key x */
    start = chrono::high_resolution_clock::now();

    RandomBnd(x, ptest*ptest*ptest);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Private key generation: "
         << duration.count() << " microseconds" << endl;
    }

    start = chrono::high_resolution_clock::now();

    h = x * g;

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Public key generation: "
         << duration.count() << " microseconds" << endl;
    }

    rsug3[0].curve = curve;
    divisorg3_to_bytes(rsug3[0].g, g, curve, ptest);

    g3HECQV cert2(curve, ptest, g);
    int size = NumBytes(ptest);
    uint8_t *encoded2 = new uint8_t[31 + 6*size];

    start = chrono::high_resolution_clock::now();

    cert2.cert_generate(encoded2, "RSU0001", h, capriv);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Certificate generation: "
         << duration.count() << " microseconds" << endl;
    }

    start = chrono::high_resolution_clock::now();

    cert2.cert_pk_extraction(encoded2, capub);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Certificate public key extraction: "
         << duration.count() << " microseconds" << endl;
    }
    
    start = chrono::high_resolution_clock::now();

    cert2.cert_reception(encoded2, x);

    if(get_metrics != 0) {
      auto stop = chrono::high_resolution_clock::now();
      auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
 
      cout << "Certificate private key reception: "
         << duration.count() << " microseconds" << endl;
    }
    
    rsupub = cert2.get_calculated_Qu();
    rsupriv = cert2.get_extracted_du();

    rsug3[0].priv = rsupriv;
    divisorg3_to_bytes(rsug3[0].rsupub, rsupub, curve, ptest);

    fullsize = 1 + 31 + 6*size + 2 + base.length() + 1;

    cypher_buff = new uint8_t[fullsize];
    cypher_buff[0] = 0;
    memcpy(cypher_buff+1, encoded2, 31 + 6*size);
    uint8_t w, u;
    w = 10;
    u = 4;
    cypher_buff[31+6*size+1] = w;
    cypher_buff[31+6*size+2] = u;
    memcpy(cypher_buff+31+6*size+3, base.c_str(), base.length()+1);
    if(get_metrics != 0)
      std::cout << "RSU_CERT_BROADCAST message size: " << fullsize << std::endl;
  }

  //Number of nodes
  uint32_t nNodes = 64;

  std::string sumo_file = "/home/el18018/ns-allinone-3.30/ns-3.30/scratch/WaveTest/ns2mobility.tcl";

  ns3::PacketMetadata::Enable ();
  double simTime = 426;
  NodeContainer nodes;
  nodes.Create(nNodes);

  Ns2NodeUtility ns2_util(sumo_file);

  //Nodes MUST have some sort of mobility because that's needed to compute the received signal strength
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (100.0, 250.0, 0.0));

  mobility.SetPositionAllocator (positionAlloc);
  mobility.SetMobilityModel ("ns3::CustomMobilityModel");
  mobility.Install (nodes.Get(rsuid));

  Ptr<CustomMobilityModel> m0 = DynamicCast<CustomMobilityModel>(nodes.Get(rsuid)->GetObject<MobilityModel> ());
  

  m0->SetVelocityAndAcceleration (Vector (0,0,0), Vector (0,0,0));


  Ns2MobilityHelper sumo_trace (sumo_file);
  sumo_trace.Install();

  for(uint32_t i=0; i < nNodes-1; i++) {
    Ptr<MobilityModel> mob = nodes.Get(i)->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();
    pos.x *= 0.5;
    pos.y *= 0.5;
    mob->SetPosition(pos);
    //std::cout << "Node " << i << " Entry time: " << ns2_util.GetEntryTimeForNode(i) << " exit time: " << ns2_util.GetExitTimeForNode(i) << std::endl;
  }
  //I prefer using WaveHelper to create WaveNetDevice
  YansWifiChannelHelper waveChannel = YansWifiChannelHelper::Default ();
  YansWavePhyHelper wavePhy =  YansWavePhyHelper::Default ();
  wavePhy.SetChannel (waveChannel.Create ());
  wavePhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);

  /*
   * If you create applications that control TxPower, define the low & high end of TxPower.
   * This is done by using 'TxInfo' as shown below.
   * 33 dBm is the highest allowed for non-government use (as per 802.11-2016 standard, page 3271
   * 44.8 dBm is for government use.
   *
   * Setting them to the same value is the easy way to go.
   * I can instead set TxPowerStart to a value lower than 33, but then I need to set the number of levels for each PHY
   */
  wavePhy.Set ("TxPowerStart", DoubleValue (8) );
  wavePhy.Set ("TxPowerEnd", DoubleValue (33) );



  QosWaveMacHelper waveMac = QosWaveMacHelper::Default ();
  WaveHelper waveHelper = WaveHelper::Default ();

  waveHelper.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
  						"DataMode", StringValue ("OfdmRate6MbpsBW10MHz"	),
  						"ControlMode",StringValue ("OfdmRate6MbpsBW10MHz"),
  						"NonUnicastMode", StringValue ("OfdmRate6MbpsBW10MHz"));


  NetDeviceContainer devices = waveHelper.Install (wavePhy, waveMac, nodes);
  wavePhy.EnablePcap ("WaveTest", devices);

  //destination MAC
  Mac48Address dest	= Mac48Address::GetBroadcast();

  /*
   * 0x88dc is the ethertype corresponding to WSMP. IPv4's etherType is 0x0800, and IPv6 is 0x86DD
   * The standard doesn't allow sending IP packets over CCH channel
   */
  uint16_t protocol = 0x88dc;

  //We can also set the transmission parameters at the higher layeres
  TxInfo tx;
  tx.preamble = WIFI_PREAMBLE_LONG;
  //We set the channel on which the packet is sent. The WaveNetDevice must have access to the channel
  //CCH is enabled by default.
  tx.channelNumber = CCH;

  //We can set per-packet data rate. This packet will have a rate of 12Mbps.
  tx.dataRate = WifiMode ("OfdmRate12MbpsBW10MHz");

  /*
   * Set the Access Catogory (AC) of the packet.
   * The 802.11e EDCA standard defines 4 AC's named Voice, Video, Best Effort & Background in order of priority.
   * The value determines the EdcaQueue in which the packet will be enqueued.
   *
   * The 'tid' is a value from 0-7 that maps to ACs as follows
   * 1 or 2 : Background (Lowest priority)
   * 0 or 3 : Best effort
   * 4 or 5 : Video
   * 6 or 7 : Voice (Highest priority)
   */
  tx.priority = 7;	//We set the AC to highest priority. We can set this per packet.

  /*
   * We can also set TxPower. This maps to the user define TxPowerStart & TxPowerEnd.
   * 7 : corresponds to the highest user-defined power (TxPowerEnd). In this code, it's 33 dBm
   * 1 : lowest (TxPowerStart). In this code, it's 8.3 dBm
   *
   * We'll have N equally spaced power levels.
   * A value of 8 indicates application don't want to set power or data rate. Values >8 are invalid.
   */
  tx.txPowerLevel = 7; //When we define TxPowerStart & TxPowerEnd for a WifiPhy, 7 is correspond to TxPowerEnd, and 1 TxPowerStart, and numbers in between are levels.


  /**************** Energy model: ****************/

  for(uint32_t i=0; i < nNodes; i++) {
    prev_energy[i] = 1000.0; 
    prev_times[i] = 0;
  }

  Vehicle_sources = new EnergySourceContainer();

  BasicEnergySourceHelper energyHelper;
  energyHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue (1000.0));
  *Vehicle_sources = energyHelper.Install(nodes);

  // WifiRadioEnergyModelHelper wifiEnergyHelper;
  // DeviceEnergyModelContainer deviceModels = wifiEnergyHelper.Install(devices, Vehicle_sources);
  WaveRadioEnergyModelHelper waveEnergyHelper;
  DeviceEnergyModelContainer deviceModels = waveEnergyHelper.Install(devices, *Vehicle_sources);
  
  
  /*************** Sending a packet ***************/

  /*
   * In order to send a packet, we will call SendX function of WaveNetDevice.
   */
  Ptr <NetDevice> d0 = devices.Get (rsuid);
  Ptr <WaveNetDevice> wd0 = DynamicCast <WaveNetDevice> (d0);

  //wd0->GetPhy(0)->SetWifiRadioEnergyModel(energymodel);

  /*
   * We want to call
   *     wd0->SendX (packet, destination, protocol, tx);
   * By scheduling a simulator event as follows:
   */
  
   //Simulator::Schedule ( Seconds (2) , &WaveNetDevice::SendX, wd0, packet_i, dest, protocol, tx);
   Ptr <Packet> packet_j;
   std::set<double> endsim_cars;

   uint32_t gl_phase = 150;

   for (uint32_t t=2; t < simTime-1; t+=2) {
      packet_j = Create<Packet>((uint8_t*)cypher_buff, fullsize);
      Simulator::Schedule ( Seconds (t) , &WaveNetDevice::SendX, wd0, packet_j, dest, protocol, tx);
   }

  /* Using tracesources to trace some simulation events */

  /*
   * Connecting to a promiscous Rx trace source. This will invoke the 'Rx' function everytime a packet is received.
   *
   * The MonitorSnifferRx trace is defined in WifiPhy.
   */

  for(uint32_t i=0; i < nNodes-1; i++) {
    double entryt = ns2_util.GetEntryTimeForNode(i);
    if( entryt > 300){
      entryt -= 200;
    }
    std::string conn = "/NodeList/";
    conn = conn + to_string(i);
    conn = conn + "/DeviceList/0/$ns3::WaveNetDevice/PhyEntities/0/MonitorSnifferRx";
    //Config::Connect(conn, MakeCallback(&Rx));
    Simulator::Schedule(Seconds(entryt), &Config::Connect, conn, MakeCallback(&Rx));
    if(i != 0) {
      Simulator::Schedule(Seconds(entryt + (int)entryt%2), &set_Initial_Energy, i);
      prev_times[i] = entryt + (int)entryt%2;
    }
    else {
      Simulator::Schedule(Seconds(entryt + 2), &set_Initial_Energy, i);
      prev_times[i] = entryt + 2;
    }
    double exit=0;
    if(ns2_util.GetExitTimeForNode(i) > 200) {
      exit = 426;
      endsim_cars.insert(i);
    }
    else {
      exit = ns2_util.GetExitTimeForNode(i);
    }
    exit_time[i] = exit;
  }

  
  std::string rsuconn = "/NodeList/" + to_string(rsuid) + "/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/MonitorSnifferRx";
  Config::Connect(rsuconn, MakeCallback (&Rx1) );

  Simulator::Schedule(Seconds(gl_phase), &SelectGL, endsim_cars);
  
  //Set the number of power levels.
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/TxPowerLevels", ns3::UintegerValue(7));


  /*
   * What if some packets were dropped due to collision, or whatever? We use this trace to fire RxDrop function
   */
  
  Config::Connect("/NodeList/63/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/PhyRxDrop", MakeCallback (&RxDrop) );

  /*
   * We can also trace some MAC layer details
   */
  Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/MacEntities/*/$ns3::OcbWifiMac/*/Queue/Enqueue", MakeCallback (&EnqueueTrace));

  Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/MacEntities/*/$ns3::OcbWifiMac/*/Queue/Dequeue", MakeCallback (&DequeueTrace));


  Simulator::Schedule (Seconds (4), &PrintInfo);
  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();

}
