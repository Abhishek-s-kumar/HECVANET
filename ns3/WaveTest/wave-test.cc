#include "ns3/wave-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "custom-mobility-model.h"
#include "ns3/node.h"
#include "hec_cert.h"
#include "sign.h"
#include "messages.h"

//For colorful console printing
/*
 * Usage example :
 *    std::cout << BOLD_CODE << "some bold text << END_CODE << std::endl;
 *
 *    std::cout << YELLOW_CODE << BOLD_CODE << "some bold yellow text << END_CODE << std::endl;
 *
 */
#define YELLOW_CODE "\033[33m"
#define TEAL_CODE "\033[36m"
#define BOLD_CODE "\033[1m"
#define END_CODE "\033[0m"
#undef MAX_STRING_LEN 
#define MAX_STRING_LEN 300

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("WaveExample1");

int ec_algo = 1;

Vehicle_data_g2 veh1g2;
RSU_data_g2 rsu1g2;

Vehicle_data_g3 veh1g3;
RSU_data_g3 rsu1g3;

Vehicle_data_ec veh1ec;
RSU_data_ec rsu1ec;

uint8_t hpk[23] = {0x87,0x75,0x6e,0x0e,0x30,0x8e,0x59,0xa4,0x04,0x48,0x01,
0x17,0x4c,0x4f,0x01,0x4d,0x16,0x78,0xe8,0x56,0x6e,0x03,0x02};


void PrintInfo ()
{
    Ptr<Node> n0 =  ns3::NodeList::GetNode(0);
    Ptr<Node> n1 =  ns3::NodeList::GetNode(1);
    //Ptr<Node> n2 =  ns3::NodeList::GetNode(2);

    Ptr<MobilityModel> m0 = n0->GetObject<MobilityModel> ();
    Ptr<MobilityModel> m1 = n1->GetObject<MobilityModel> ();
    //Ptr<MobilityModel> m2 = n2->GetObject<MobilityModel> ();
    
    std::cout << "n0 Vel:" << m0->GetVelocity() << "\t\tn1 Vel: " << m1->GetVelocity() << "\t\tn2 Vel: " << std::endl;

    // if (Now() == Seconds (3))
    // {
    //     Ptr<CustomMobilityModel> cmm = DynamicCast<CustomMobilityModel> (m0);
    //     cmm->SetAccelerationValue (0.5);
    // }

    Simulator::Schedule (Seconds (1), &PrintInfo);

}

//Note: this is a promiscuous trace for all packet reception. This is also on physical layer, so packets still have WifiMacHeader
void Rx (std::string context, Ptr <const Packet> packet, uint16_t channelFreqMhz,  WifiTxVector txVector,MpduInfo aMpdu, SignalNoiseDbm signalNoise)
{

  //context will include info about the source of this event. Use string manipulation if you want to extract info.
  
  std::cout << BOLD_CODE <<  context << END_CODE << std::endl;
  Ptr <Packet> myPacket = packet->Copy();
  //Print the info.
  std::cout << "\tSize=" << packet->GetSize()
        << " Freq="<<channelFreqMhz
        << " Mode=" << txVector.GetMode()
        << " Signal=" << signalNoise.signal
        << " Noise=" << signalNoise.noise << std::endl;

  //We can also examine the WifiMacHeader
  WifiMacHeader hdr;
  WifiMacHeader hdr1;
  WifiMacTrailer trl;

  uint8_t *buffrc = new uint8_t[packet->GetSize()];

  int state;
  if(ec_algo == 0) {
    state = veh1g2.state;
  } 
  else if(ec_algo == 1) {
    state = veh1ec.state;
  }
  else{
    state = veh1g3.state;
  }
  
  if (packet->PeekHeader(hdr))
  {
    std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2() << std::endl;
    myPacket->RemoveHeader(hdr1);
    myPacket->RemoveTrailer(trl);
    myPacket->CopyData(buffrc, packet->GetSize());
  }
  else {
    return;
  }

  if(buffrc[8] == RECEIVE_CERT && state == RECEIVE_CERT && (packet->GetSize()) > 20) {
    receive_Cert_Send_Join(buffrc, ec_algo);
  }

  else if(buffrc[8] == RECEIVE_ACCEPT_KEY && state == RECEIVE_ACCEPT_KEY && (packet->GetSize()) > 20) {
    extract_Symmetric(buffrc+9, ec_algo);
  }
}

void Rx1(std::string context, Ptr <const Packet> packet, uint16_t channelFreqMhz,  WifiTxVector txVector,MpduInfo aMpdu, SignalNoiseDbm signalNoise) {
  std::cout << BOLD_CODE <<  context << END_CODE << std::endl;
  Ptr <Packet> myPacket = packet->Copy();
  //Print the info.
  std::cout << "\tSize=" << packet->GetSize()
        << " Freq="<<channelFreqMhz
        << " Mode=" << txVector.GetMode()
        << " Signal=" << signalNoise.signal
        << " Noise=" << signalNoise.noise << std::endl;

  //We can also examine the WifiMacHeader
  WifiMacHeader hdr;
  WifiMacHeader hdr1;
  WifiMacTrailer trl;

  uint8_t *buffrc = new uint8_t[packet->GetSize()];
  int prot,vid;
  
  if (packet->PeekHeader(hdr))
  {
    std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2() << std::endl;
    myPacket->RemoveHeader(hdr1);
    myPacket->RemoveTrailer(trl);
    myPacket->CopyData(buffrc, packet->GetSize());

    prot = (int)buffrc[8];
    vid = (int)buffrc[9];

  }
  else {
    return;
  }
  if(prot == RECEIVE_CERT && (packet->GetSize()) > 20) {
    if(ec_algo == 0 && rsu1g2.states[vid-1] == RECEIVE_CERT) {
      extract_RSU_SendAccept_g2(buffrc+10, vid);
    }
    else if (ec_algo == 1 && rsu1ec.states[vid-1] == RECEIVE_CERT) {
      extract_RSU_SendAccept_ec(buffrc+10, vid);
    }
    else if (ec_algo == 2 && rsu1g3.states[vid-1] == RECEIVE_CERT){
      extract_RSU_SendAccept_g3(buffrc+10, vid);
    }
  }
}


/*
 * This function works for ns-3.30 onwards. For previous version, remove the last parameter (the "WifiPhyRxfailureReason")
 */
void RxDrop (std::string context, Ptr<const Packet> packet, ns3::WifiPhyRxfailureReason reason)
{
	std::cout << BOLD_CODE << YELLOW_CODE << "Packet Rx Dropped!" << END_CODE << std::endl;
	//From ns-3.30, the reasons are defined in an enum type in ns3::WifiPhy class.
	std::cout << " Reason : " << reason << std::endl;
	std::cout << context << std::endl;

	WifiMacHeader hdr;
	if (packet->PeekHeader(hdr))
	{

		std::cout << " Destination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2() << "\tSeq No. " << hdr.GetSequenceNumber() << std::endl;
	}
}

//Fired when a packet is Enqueued in MAC
void EnqueueTrace(std::string context, Ptr<const WifiMacQueueItem> item)
{
	std::cout << TEAL_CODE << "A Packet was enqueued : " << context << END_CODE << std::endl;

	Ptr <const Packet> p = item->GetPacket();
	/*
	 * Do something with the packet, like attach a tag. ns3 automatically attaches a timestamp for enqueued packets;
	 */

}
//Fired when a packet is Dequeued from MAC layer. A packet is dequeued before it is transmitted.
void DequeueTrace(std::string context, Ptr<const WifiMacQueueItem> item)
{
	std::cout << TEAL_CODE << "A Packet was dequeued : " << context << END_CODE << std::endl;

	Ptr <const Packet> p = item->GetPacket();
	Time queue_delay = Simulator::Now() - item->GetTimeStamp();

	//Keep in mind that a packet might get dequeued (dropped_ if it exceeded MaxDelay (default is 500ms)
	std::cout << "\tQueuing delay=" << queue_delay << std::endl;


}


int main (int argc, char *argv[])
{
  CommandLine cmd;
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
    rsu1g2.u = 10;
    rsu1g2.w = 4;
    std::string base = "BaseforGenerator";
    int rt = text_to_divisor(g, base, ptest, curve, enc);
    if(rt) {
      exit(1);
    }

    ZZ capriv = to_ZZ("15669032110011017415376799675649225245106855015484313618141721121181084494176");
    ZZ x;
    capub = capriv*g;
    /* private key x */
    RandomBnd(x, ptest*ptest);
    divisor_to_bytes(rsu1g2.capub, capub, curve, ptest);

    h = x * g;

    g2HECQV cert2(curve, ptest, g);
    int size = NumBytes(ptest);
    uint8_t *encoded2 = new uint8_t[31 + 2*size+1];
    cert2.cert_generate(encoded2, "RSU0001", h, capriv);

    cert2.cert_pk_extraction(encoded2, capub);
    cert2.cert_reception(encoded2, x);
    
    rsupub = cert2.get_calculated_Qu();
    rsupriv = cert2.get_extracted_du();

    rsu1g2.priv = rsupriv;
    rsu1g2.curve = curve;
    divisor_to_bytes(rsu1g2.rsupub, rsupub, curve, ptest);
    divisor_to_bytes(rsu1g2.g, g, curve, ptest);

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
  }

  else if (ec_algo == 1) {
    std::cout << "Using ElGamal with ECC for message encryption\nECQV for certificates\nECDSA signatures" << std::endl;
    std::cout << "Using curve secp256r1 parameters" << std::endl;
    
    CryptoPP::AutoSeededRandomPool prng;    
    GroupParameters group;
    group.Initialize(CryptoPP::ASN1::secp256r1());

    rsu1ec.group = group;

    ECQV cert(group);

    // private key
    CryptoPP::Integer priv_ecc(prng, CryptoPP::Integer::One(), group.GetMaxExponent());

    CryptoPP::Integer capriv("99904945320188894543539641655649253921899278606834393872940151579788317849983");
    
    Element pub = group.ExponentiateBase(priv_ecc);

    int size = group.GetCurve().FieldSize().ByteCount();
    uint8_t *encoded = new uint8_t[31 + 2*size+1];
    cert.cert_generate(encoded, "RSU0001", pub, capriv);
    cert.cert_pk_extraction(encoded, group.ExponentiateBase(capriv));
    cert.cert_reception(encoded, priv_ecc);

    rsu1ec.capub = group.ExponentiateBase(capriv);

    Element rsupub = cert.get_calculated_Qu();
    CryptoPP::Integer rsupriv = cert.get_extracted_du();

    rsu1ec.priv = rsupriv;
    rsu1ec.rsupub = rsupub;
    
    fullsize = 1 + 31 + 2*size + 1;

    cypher_buff = new uint8_t[fullsize];
    cypher_buff[0] = 0;
    memcpy(cypher_buff+1, encoded, 31 + 2*size+1);
  }

  else{
    std::cout << "Using ElGamal with Genus 3 HEC for message encryption\nHECQV for certificates\nElGamal HEC genus 2 signatures" << std::endl;
    ZZ ptest = to_ZZ(pg3);
    field_t::init(ptest);
    std::cout << "Using p: " << ptest << " of size: " << NumBits(ptest) << std::endl;
    g3HEC::g3hcurve curve;

    g3HEC::g3divisor g, h, rsupub, capub;
    ZZ rsupriv;
    UnifiedEncoding enc(ptest, 10, 4, 3);
    rsu1g3.u = 10;
    rsu1g3.w = 4;

    std::string base = "BaseforGenerator";
    int rt = text_to_divisorg3(g, base, ptest, curve, enc);
    if(rt) {
      exit(1);
    }

    ZZ capriv = to_ZZ("247253210584643408262663087671537517974691545498905118366998662050233012073014");
    ZZ x;

    capub = capriv*g;

    divisorg3_to_bytes(rsu1g3.capub, capub, curve, ptest);
    /* private key x */
    RandomBnd(x, ptest*ptest*ptest);

    h = x * g;

    rsu1g3.curve = curve;
    divisorg3_to_bytes(rsu1g3.g, g, curve, ptest);

    g3HECQV cert2(curve, ptest, g);
    int size = NumBytes(ptest);
    uint8_t *encoded2 = new uint8_t[31 + 6*size];
    cert2.cert_generate(encoded2, "RSU0001", h, capriv);

    cert2.cert_pk_extraction(encoded2, capub);
    cert2.cert_reception(encoded2, x);
    
    rsupub = cert2.get_calculated_Qu();
    rsupriv = cert2.get_extracted_du();

    rsu1g3.priv = rsupriv;
    divisorg3_to_bytes(rsu1g3.rsupub, rsupub, curve, ptest);

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
  }

  //Number of nodes
  uint32_t nNodes = 2;

  cmd.AddValue ("n","Number of nodes", nNodes);

  cmd.Parse (argc, argv);

  ns3::PacketMetadata::Enable ();
  double simTime = 100;
  NodeContainer nodes;
  nodes.Create(nNodes);

  //Nodes MUST have some sort of mobility because that's needed to compute the received signal strength
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (0.0, 0.0, 0.0));
  positionAlloc->Add (Vector (5.0, 0.0, 0.0));
  //positionAlloc->Add (Vector (5.0, 10.0, 0.0));

  mobility.SetPositionAllocator (positionAlloc);
  mobility.SetMobilityModel ("ns3::CustomMobilityModel");
  mobility.Install (nodes);

  Ptr<CustomMobilityModel> m0 = DynamicCast<CustomMobilityModel>(nodes.Get(0)->GetObject<MobilityModel> ());
  Ptr<CustomMobilityModel> m1 = DynamicCast<CustomMobilityModel>(nodes.Get(1)->GetObject<MobilityModel> ());
  //Ptr<CustomMobilityModel> m2 = DynamicCast<CustomMobilityModel>(nodes.Get(2)->GetObject<MobilityModel> ());
  m0->SetVelocityAndAcceleration (Vector (0,0,0), Vector (3,0,0));
  m1->SetVelocityAndAcceleration (Vector (0,0,0), Vector (3,0,0));
  //m2->SetVelocityAndAcceleration (Vector (0,0,0), Vector (3,0,0));

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

  //prepare a packet with a payload of 500 Bytes. Basically it has zeros in the payload
  Ptr <Packet> packet 	= Create <Packet> (1000);

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
  tx.txPowerLevel = 3; //When we define TxPowerStart & TxPowerEnd for a WifiPhy, 7 is correspond to TxPowerEnd, and 1 TxPowerStart, and numbers in between are levels.

  /*************** Sending a packet ***************/

  /*
   * In order to send a packet, we will call SendX function of WaveNetDevice.
   */

  //Get the WaveNetDevice for the first devices, using node 0.
  Ptr <NetDevice> d0 = devices.Get (0);
  Ptr <WaveNetDevice> wd0 = DynamicCast <WaveNetDevice> (d0);
  /*
   * We want to call
   *     wd0->SendX (packet, destination, protocol, tx);
   * By scheduling a simulator event as follows:
   */
  //wd0->SetReceiveCallback(MakeCallback(&PrintPayload));
   //Simulator::Schedule ( Seconds (1) , &WaveNetDevice::SendX, wd0, packet, dest, protocol, tx);

   std::ostringstream msg;
   msg << "Hello World!" << "\0";
   uint16_t packetSize = msg.str().length() + 1;
   Ptr <Packet> packet_i = Create<Packet>((uint8_t*)msg.str().c_str(), packetSize);
   //Simulator::Schedule ( Seconds (2) , &WaveNetDevice::SendX, wd0, packet_i, dest, protocol, tx);
   Ptr <Packet> packet_j;

   for (uint32_t t=2; t<simTime; t+=2) {
      packet_j = Create<Packet>((uint8_t*)cypher_buff, fullsize);
      Simulator::Schedule ( Seconds (t) , &WaveNetDevice::SendX, wd0, packet_j, dest, protocol, tx);
   }

  //  Ptr <Packet> packet_ecc = Create<Packet>(public1, 64);
  //  Simulator::Schedule ( Seconds (4) , &WaveNetDevice::SendX, wd0, packet_ecc, dest, protocol, tx);
    
  // //Let us schedule try to have all three nodes schedule messages for broadcast
  // for (uint32_t t=0 ; t<simTime-2; t++)
  // {
	//   //Go over all the nodes.
	//   for (uint32_t i=0; i<devices.GetN() ; i++)
	//   {
	// 	  Ptr <NetDevice> di = devices.Get (i);
	// 	  Ptr <WaveNetDevice> wdi = DynamicCast <WaveNetDevice> (di);

  //     //wdi->SetReceiveCallback(MakeCallback(&PrintPayload));

	// 	  Ptr <Packet> packet_i = Create<Packet>((uint8_t*)msg.str().c_str(), packetSize);

	// 	  Ptr <Packet> low_priority_packet = Create <Packet> ((uint8_t*)msg.str().c_str(), packetSize); // A low priority packet

	// 	  TxInfo txi;
  //     txi.preamble = WIFI_PREAMBLE_LONG;
	// 	  txi.channelNumber = CCH;
	// 	  //We always need to set TxPower to something. Otherwise, default data rate would be used.
	// 	  txi.txPowerLevel = 3;
	// 	  switch (i)
	// 	  {
	// 	  case 0:
	// 		  //I am going to make node 0 broadcast at 27Mbps, with priority 5.
	// 		  txi.dataRate = WifiMode ("OfdmRate27MbpsBW10MHz");
	// 		  txi.priority = 5; //check the pcap file for the TID value in the Wifi MAC header
	// 		  Simulator::Schedule ( Seconds (t) , &WaveNetDevice::SendX, wdi, packet_i, dest, protocol, txi);
	// 		  //We also are going to schedule another packet with lowest priority
	// 		  txi.priority = 1; //1 is for BK (Background) priority.
	// 		  Simulator::Schedule ( Seconds (t) , &WaveNetDevice::SendX, wdi, low_priority_packet, dest, protocol, txi);

	// 		  break;

	// 	  case 1:
	// 		  //I am going to set only the data rate for packets sent by node1
	// 		  txi.dataRate = WifiMode ("OfdmRate9MbpsBW10MHz");
	// 		  Simulator::Schedule ( Seconds (t) , &WaveNetDevice::SendX, wdi, packet_i, dest, protocol, txi);
	// 		  break;

	// 	  case 2:
	// 		  /* I am not going to set data rate for packets out of node 2.
	// 		   * The data rate will be whatever we used for NonUnicastMode when we set WifiRemoteStationManager
	// 		   */
	// 		  Simulator::Schedule ( Seconds (t) , &WaveNetDevice::SendX, wdi, packet_i, dest, protocol, txi);
	// 		  break;
	// 	  }
	//   }
  // }
  /****** Unicast Example *******/
  //Let's send a Unicast packet from n0 to n2
  //Get the MAC address of the target node
  Ptr <WaveNetDevice> d2 = DynamicCast<WaveNetDevice>(devices.Get(1));
  //Mac48Address target_mac = Mac48Address::ConvertFrom (d2->GetAddress());

  Ptr <Packet> unicast_packet = Create<Packet> (200);
  TxInfo tx_u;
  /*
   * Schedule sending from WaveNetDevice 0.
   * Since this is a unicast, the frame will be acknowledged with an acknowledgment frame
   */
  //Simulator::Schedule ( Seconds(simTime-1) , &WaveNetDevice::SendX, wd0, unicast_packet, target_mac, protocol, tx_u );


  /* Using tracesources to trace some simulation events */

  /*
   * Connecting to a promiscous Rx trace source. This will invoke the 'Rx' function everytime a packet is received.
   *
   * The MonitorSnifferRx trace is defined in WifiPhy.
   */
  
  Config::Connect("/NodeList/1/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/MonitorSnifferRx", MakeCallback (&Rx) );
  Config::Connect("/NodeList/0/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/MonitorSnifferRx", MakeCallback (&Rx1) );
  //Config::Connect("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/ReceiveCallback", MakeCallback (&PrintPayload) );
  //Set the number of power levels.
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/TxPowerLevels", ns3::UintegerValue(7));


  /*
   * What if some packets were dropped due to collision, or whatever? We use this trace to fire RxDrop function
   */
  Config::Connect("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/PhyRxDrop", MakeCallback (&RxDrop) );

  /*
   * We can also trace some MAC layer details
   */
  Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/MacEntities/*/$ns3::OcbWifiMac/*/Queue/Enqueue", MakeCallback (&EnqueueTrace));

  Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/MacEntities/*/$ns3::OcbWifiMac/*/Queue/Dequeue", MakeCallback (&DequeueTrace));


  Simulator::Schedule (Seconds (1), &PrintInfo);
  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();

}
