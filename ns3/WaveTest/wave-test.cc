#include "ns3/wave-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "custom-mobility-model.h"
#include "ns3/node.h"
#include "hec_cert.h"

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

uint8_t *buff;
ZZ x, k;

void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
}

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
  ZZ ptest = to_ZZ(pt);
  field_t::init(ptest);
  UnifiedEncoding enc(ptest, 10, 4, 2, ZZ_p::zero());
  int size = NumBytes(ptest);
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
  buff = new uint8_t[packet->GetSize()];
  uint8_t *buffa = new uint8_t[2*size+1];
  uint8_t *buffb = new uint8_t[2*size+1];
  if (packet->PeekHeader(hdr))
  {
    std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2() << std::endl;
    myPacket->RemoveHeader(hdr1);
    myPacket->RemoveTrailer(trl);
    myPacket->CopyData(buff, packet->GetSize());
    // for(unsigned int i=8; i < packet->GetSize(); i++){
    //   std::cout << +buff[i];
    // }
    // std::cout << std::endl;

    std::cout << "Received Cypher Text: ";

    memcpy(buffa, buff+8, 2*size+1);
    memcpy(buffb, buff+9+2*size, 2*size+1);

  }
  else {
    return;
  }

  NS_G2_NAMESPACE::g2hcurve curve;
  
  
  curve = enc.getcurve();
  NS_G2_NAMESPACE::divisor m, a, b;
  bytes_to_divisor(a, buffa, curve, ptest);
  bytes_to_divisor(b, buffb, curve, ptest);

  m = b - x * a;
  std::string str22;
  int rt = divisor_to_text(str22, m, ptest, enc);
  if(rt)
    std::cout << "Could not decode divisor!" << std::endl;
  else 
    std::cout << "Decrypted message on node 1: " << str22 << std::endl;
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
    NTL::SetSeed(to_ZZ(19800729));
    
    CryptoPP::AutoSeededRandomPool prng;    
    GroupParameters group;
    group.Initialize(CryptoPP::ASN1::secp256r1());
    
    std::string messtr = "Accept";
    Element messecc = text_to_ecpoint(messtr, messtr.length(), group, 32);
    bool f = group.GetCurve().VerifyPoint(messecc);

    if(!f)
      std::cout << "Failed to encode message to point" << std::endl;
    
    // private key
    CryptoPP::Integer priv2(prng, CryptoPP::Integer::One(), group.GetMaxExponent());

    CryptoPP::Integer kecc(prng, CryptoPP::Integer::One(), group.GetMaxExponent());

    CryptoPP::Integer randecc(prng, CryptoPP::Integer::One(), group.GetMaxExponent());
    
    ECQV cert(group);
    

    std::cout << "Private exponent:" << std::endl;
    std::cout << "  " << std::hex << priv2 << std::endl;
  
    // public key
    Element y1 = group.ExponentiateBase(priv2);
    
    int size1 = group.GetCurve().FieldSize().ByteCount();
    uint8_t *encoded = new uint8_t[31 + 2*size1+1];
    cert.cert_generate(encoded, "VEH0001", y1, kecc);

    cert.cert_pk_extraction(encoded);
    cert.cert_reception(encoded, priv2);

    uint8_t buffecc[65] = {0};
    
    group.GetCurve().EncodePoint(buffecc, y1, false);
    vli_print(buffecc, 65);
    printf("\n");

    Element check;

    group.GetCurve().DecodePoint(check, buffecc, 65);


    Element aecc = group.ExponentiateBase(kecc);

    //Element messecc = group.ExponentiateBase(randecc);
    Element becctemp = group.GetCurve().ScalarMultiply(y1, kecc);

    std::cout << "Public element:" << std::endl;
    std::cout << "  " << std::hex << check.x << std::endl;
    std::cout << "  " << std::hex << check.y << std::endl;
    
    // element addition
    Element becc = group.GetCurve().Add(becctemp, messecc);
    std::cout << "Add:" << std::endl;
    std::cout << "  " << std::hex << becc.x << std::endl;
    std::cout << "  " << std::hex << becc.y << std::endl;

    Element dectemp = group.GetCurve().ScalarMultiply(aecc, priv2);
    Element decmess = group.GetCurve().Subtract(becc, dectemp);

    std::cout << "Mess:" << std::endl;
    std::cout << "  " << std::hex << messecc.x << std::endl;
    std::cout << "  " << std::hex << messecc.y << std::endl;

    std::cout << "Decrypted Mess:" << std::endl;
    std::cout << "  " << std::hex << decmess.x << std::endl;
    std::cout << "  " << std::hex << decmess.y << std::endl;
    std::string decrymes = ecpoint_to_text(decmess, 32);
    std::cout << decrymes << std::endl;

  CommandLine cmd;

  /* HECC of genus 2 encrypted message using ElGamal Encryption: */


  ZZ ptest = to_ZZ(pt);
  field_t::init(ptest);

  NS_G2_NAMESPACE::g2hcurve curve;

  NS_G2_NAMESPACE::divisor m, g, h, a, b, achk, bchk;
  UnifiedEncoding enc(ptest, 10, 4, 2);
  std::string str11 = "Join 01234";
  std::string base = "BaseforGenerat";
  int rt = text_to_divisor(m, str11, ptest, curve, enc);
  rt = text_to_divisor(g, base, ptest, curve, enc);
  if(rt) {
    exit(1);
  }
  
  std::cout << curve << std::endl;
   /* private key x */
  RandomBnd(x, ptest*ptest);
   /* random number k */
  RandomBnd(k, ptest*ptest);


   /* random message m as divisor */
  
  //g.random();
   /* public key h */
  h = x * g;

  g2HECQV cert2(curve, ptest, g);
  int size2 = NumBytes(ptest);
    uint8_t *encoded2 = new uint8_t[31 + 2*size2+1];
    cert2.cert_generate(encoded2, "VEH0001", h, k);

    cert2.cert_pk_extraction(encoded2);
    cert2.cert_reception(encoded2, x);

   /* cipher text (a, b) */
  a = k * g;
  b = k * h + m;

  int size = NumBytes(ptest);
  uint8_t *buffa = new uint8_t[2*size+1];

  divisor_to_bytes(buffa, a, curve, ptest);
  bytes_to_divisor(achk, buffa, curve, ptest);


  uint8_t *buffb = new uint8_t[2*size+1];

  divisor_to_bytes(buffb, b, curve, ptest);
  bytes_to_divisor(bchk, buffb, curve, ptest);

  std::cout << "Is it correct? " << (b == bchk) << std::endl;
  
  uint8_t *cypher_buff = new uint8_t[4*size+2];
  memcpy(cypher_buff, buffa, 2*size+1);
  memcpy(cypher_buff+2*size+1, buffb, 2*size+1);

  std::cout << "Message to send for HECC genus 2: " << m << std::endl;



  /* Genus 3 HECC ElGamal: */
  UnifiedEncoding enc3(ptest, 10, 4, 3);


  g3HEC::g3hcurve curveg3;
  
  ZZ x1, k1;
  RandomBnd(x1, ptest*ptest*ptest);
  RandomBnd(k1, ptest*ptest*ptest);
  g3HEC::g3divisor m3t, m3, g1, h1, a1, b1;



  std::string g3str = "Accept 01234";
  int fl3 = text_to_divisorg3(m3, g3str, ptest, curveg3, enc3);
  if(fl3) {
    std::cout << "Conv from text to divisorG3 failed!" << std::endl;
  }

  std::cout << m3 << std::endl;

  std::string g3dec;
  divisorg3_to_text(g3dec, m3, ptest, enc3);

  std::cout << "Decoded from divisorG3: " << g3dec << std::endl;
  uint8_t *buff3 = new uint8_t[6*size];
  divisorg3_to_bytes(buff3, m3, curveg3, ptest); 
  bytes_to_divisorg3(m3t, buff3, curveg3, ptest);

  std::cout << "Is it okay? " << (m3t == m3) << std::endl;
  g1.random();
  h1 = x1 * g1;
  a1 = k1*g1;
  b1 = k1*h1 + m3;

  if( b1 - x1 * a1 == m3)
    std::cout << "ElGamal of g3 curve ok!" << std::endl;
  else 
    std::cout << "Not ok :/" << std::endl;

  //Number of nodes
  uint32_t nNodes = 2;

  cmd.AddValue ("n","Number of nodes", nNodes);

  cmd.Parse (argc, argv);

  ns3::PacketMetadata::Enable ();
  double simTime = 10;
  NodeContainer nodes;
  nodes.Create(nNodes);

  //Nodes MUST have some sort of mobility because that's needed to compute the received signal strength
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (0.0, 0.0, 0.0));
  positionAlloc->Add (Vector (5.0, 0.0, 0.0));
  positionAlloc->Add (Vector (5.0, 10.0, 0.0));

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
  
   Ptr <Packet> packet_j = Create<Packet>((uint8_t*)cypher_buff, 4*size+2);
   Simulator::Schedule ( Seconds (2) , &WaveNetDevice::SendX, wd0, packet_j, dest, protocol, tx);

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
  
  Config::Connect("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/MonitorSnifferRx", MakeCallback (&Rx) );
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
