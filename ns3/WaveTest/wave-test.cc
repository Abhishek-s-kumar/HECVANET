#include "ns3/wave-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "custom-mobility-model.h"
#include <g2hec_nsfieldtype.h>
#include <assert.h>
#include <g2hec_Genus2_ops.h>
#include <cstdlib>
#include <cstring>
#include "uECC.h"
#include "ns3/node.h"

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
ZZ pZZ;
ZZ x, k;
int flag=0;

char p[MAX_STRING_LEN];
uint8_t private1[32] = {0};
uint8_t public1[64] = {0};
uint8_t private2[32] = {0};
uint8_t public2[64] = {0};

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
  if(flag == 1) {
	  //std::cout << BOLD_CODE << context << END_CODE << std::endl;
    std::string::iterator it;
    it = context.begin();
    it += 10;
    int nodeId = *it - '0';
    std::cout << "Node ID: " << nodeId << std::endl;
    std::cout << "Now computing shared secret based on ECC: " << std::endl;
    uint8_t secret_comp[32] = {0};
    const struct uECC_Curve_t *ecc_curve = uECC_secp160r1();

    Ptr<Packet> ecc_pack = packet->Copy();
    WifiMacHeader h1;
    WifiMacTrailer tr1;
    ecc_pack->RemoveHeader(h1);
    ecc_pack->RemoveTrailer(tr1);
    uint8_t *rec = (uint8_t *)malloc(packet->GetSize()*sizeof(uint8_t));
    uint8_t *public_from_packet = new uint8_t[64];
    ecc_pack->CopyData(rec, packet->GetSize());
    memcpy(public_from_packet, rec+8, 64);
    if (!uECC_shared_secret(public_from_packet, private2, secret_comp, ecc_curve)) {
                printf("shared_secret() failed (2)\n");
                exit(1);
            }
    else{
      printf("Computed secret on node 2 = ");
      vli_print(secret_comp, 32);
      printf("\n");
    }
  }
  else{
    flag=1;
    //context will include info about the source of this event. Use string manipulation if you want to extract info.
    unsigned int len1=0, len2=0, len3=0, len4=0;
    std::cout << BOLD_CODE <<  context << END_CODE << std::endl;
    Ptr <Packet> myPacket = packet->Copy();
    ZZ *cypher_received = new ZZ[packet->GetSize()];
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
    buff = (uint8_t *) malloc((packet->GetSize())*sizeof(uint8_t));
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

      len1 = buff[8];
      len2 = buff[9 + len1*120];
      len3 = buff[10 + len1*120 + len2*120];
      len4 = buff[11 + len1*120 + len2*120 + len3*120];
      uint8_t *temp;
      for(unsigned int i=0; i < len1; i++){
        temp = new uint8_t[120];
        memcpy(temp, buff+9+120*i, 120);
        cypher_received[i] = NTL::ZZFromBytes(temp, 120);
        free(temp);
      }

      for(unsigned int i=0; i < len2; i++){
        temp = new uint8_t[120];
        memcpy(temp, buff+10+120*(len1+i), 120);
        cypher_received[len1 + i] = NTL::ZZFromBytes(temp, 120);
        free(temp);
      }

      for(unsigned int i=0; i < len3; i++){
        temp = new uint8_t[120];
        memcpy(temp, buff+11+120*(len1+len2+i), 120);
        cypher_received[len1 + len2 + i] = NTL::ZZFromBytes(temp, 120);
        free(temp);
      }

      for(unsigned int i=0; i < len4; i++){
        temp = new uint8_t[120];
        memcpy(temp, buff+12+120*(len1+len2+len3+i), 120);
        cypher_received[len1 + len2 + len3 + i] = NTL::ZZFromBytes(temp, 120);
        free(temp);
      }

      for(unsigned int i=0; i < len1+len2+len3+len4; i++){
        std::cout << cypher_received[i] << " ";
      }
      std::cout << std::endl;
    }
    pZZ = to_ZZ(p);
    field_t::init(pZZ); 

    NS_G2_NAMESPACE::g2hcurve curve;
    
    poly_t hx;
    NTL::SetCoeff(hx, 0, 0);
    NTL::SetCoeff(hx, 1, 1);
    NTL::SetCoeff(hx, 2, 12);

    poly_t fx;
    NTL::SetCoeff(fx, 0, 7);
    NTL::SetCoeff(fx, 1, 7);
    NTL::SetCoeff(fx, 2, 8);
    NTL::SetCoeff(fx, 3, 12);
    NTL::SetCoeff(fx, 4, 6);
    NTL::SetCoeff(fx, 5, 1);

    curve.set_f(fx);
    curve.set_h(hx);
    curve.update();
    if(!curve.is_valid_curve()) {
      std::cout << "Not a valid curve." << std::endl;
      exit(1);
    }
    poly_t au, av, bu, bv;
    for(unsigned int i=0; i < len1; i++) {
      NTL::SetCoeff(au, i, to_ZZ_p(cypher_received[i]));
    }
    for(unsigned int i=0; i < len2; i++) {
      NTL::SetCoeff(av, i, to_ZZ_p(cypher_received[len1+i]));
    }
    for(unsigned int i=0; i < len3; i++) {
      NTL::SetCoeff(bu, i, to_ZZ_p(cypher_received[len1 + len2 + i]));
    }
    for(unsigned int i=0; i < len4; i++) {
      NTL::SetCoeff(bv, i, to_ZZ_p(cypher_received[len1 + len2 + len3 + i]));
    }

    NS_G2_NAMESPACE::divisor m;
    NS_G2_NAMESPACE::divisor a(au, av, curve);
    NS_G2_NAMESPACE::divisor b(bu, bv, curve);
    a.update();
    b.update();
    m = b - x * a;
    std::cout << "Calculated m: " << m << std::endl;
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

  /* HECC of genus 2 encrypted message using ElGamal Encryption: */

  NTL::SetSeed(to_ZZ(19800729));
  cout << "Please choose your modulus p (up to " 
       << MAX_STRING_LEN << " decimal digits):" << endl;
  cout << "p = ";
  cin.getline(p, MAX_STRING_LEN);

  pZZ = to_ZZ(p);
  field_t::init(pZZ); 

  NS_G2_NAMESPACE::g2hcurve curve;

  NS_G2_NAMESPACE::divisor m, g, h, a, b;
  
  poly_t hx;
  NTL::SetCoeff(hx, 0, 0);
  NTL::SetCoeff(hx, 1, 1);
  NTL::SetCoeff(hx, 2, 12);

  poly_t fx;
  NTL::SetCoeff(fx, 0, 7);
  NTL::SetCoeff(fx, 1, 7);
  NTL::SetCoeff(fx, 2, 8);
  NTL::SetCoeff(fx, 3, 12);
  NTL::SetCoeff(fx, 4, 6);
  NTL::SetCoeff(fx, 5, 1);

  curve.set_f(fx);
  curve.set_h(hx);
  curve.update();
  if(!curve.is_valid_curve()) {
    std::cout << "Not a valid curve." << std::endl;
    exit(1);
  }

  std::cout << curve << std::endl;
   /* private key x */
  RandomBnd(x, pZZ*pZZ);
   /* random number k */
  RandomBnd(k, pZZ*pZZ);

  m.set_curve(curve);

   /* random message m as divisor */
  m.random();
  g.random();

   /* public key h */
  h = x * g;

   /* cipher text (a, b) */
  a = k * g;
  b = k * h + m;
  

  NTL::vec_ZZ_p aupoly;
  aupoly = NTL::VectorCopy(a.get_upoly(), 10);
  NTL::vec_ZZ_p avpoly;
  avpoly = NTL::VectorCopy(a.get_vpoly(), 10);
  NTL::vec_ZZ_p bupoly;
  bupoly = NTL::VectorCopy(b.get_upoly(), 10);
  NTL::vec_ZZ_p bvpoly;
  bvpoly = NTL::VectorCopy(b.get_vpoly(), 10);

  uint8_t len1=0, len2=0, len3=0, len4=0;
  int counter = 0;
  do {
    len1++;
    counter++;
  }
  while (aupoly[counter] != 0);

  counter = 0;
  do {
    len2++;
    counter++;
  }
  while (avpoly[counter] != 0);

  counter = 0;
  do {
    len3++;
    counter++;
  }
  while (bupoly[counter] != 0);

  counter = 0;
  do {
    len4++;
    counter++;
  }
  while (bvpoly[counter] != 0);

  uint8_t *temp;
  uint8_t *cypher_buff = new uint8_t[120*(len1 + len2 + len3 + len4) + 4];
  unsigned int full_length = 120*(len1+len2+len3+len4)+4;
  cypher_buff[0] = len1;
  for(unsigned int i=0; i < len1; i++) {
    temp = new uint8_t[120];
    NTL::BytesFromZZ(temp, NTL::rep(aupoly[i]), 120);
    memcpy(cypher_buff+1+120*i, temp, 120);
    free(temp);
  }
  cypher_buff[120*len1+1] = len2;
  for(unsigned int i=0; i < len2; i++) {
    temp = new uint8_t[120];
    NTL::BytesFromZZ(temp, NTL::rep(avpoly[i]), 120);
    memcpy(cypher_buff+120*len1+2+120*i, temp, 120);
    free(temp);
    //NTL::conv(cypher_buff[len1 + i + 2], NTL::rep(avpoly[i]));
  }

  cypher_buff[120*(len1+len2)+2] = len3;
  for(unsigned int i=0; i < len3; i++) {
    temp = new uint8_t[120];
    NTL::BytesFromZZ(temp, NTL::rep(bupoly[i]), 120);
    memcpy(cypher_buff+120*(len1+len2+i)+3, temp, 120);
    free(temp);
    //NTL::conv(cypher_buff[len1 + len2 + i + 3], NTL::rep(bupoly[i]));
  }
  cypher_buff[120*(len1+len2+len3)+3] = len4;
  for(unsigned int i=0; i < len4; i++) {
    temp = new uint8_t[120];
    NTL::BytesFromZZ(temp, NTL::rep(bvpoly[i]), 120);
    memcpy(cypher_buff+120*(len1+len2+len3+i)+4, temp, 120);
    free(temp);
    //NTL::conv(cypher_buff[len1 + len2 + len3 + i + 4], NTL::rep(bvpoly[i]));
  }

  std::cout << "Message to send for HECC genus 2: " << m << std::endl;

  /* Simple ECC Diffie Hellman shared secret exchange: */
  
  uint8_t secret1[32] = {0};
  uint8_t secret2[32] = {0};


  const struct uECC_Curve_t *ecc_curve = uECC_secp160r1();
  if(!uECC_make_key(public1, private1, ecc_curve) || !uECC_make_key(public2, private2, ecc_curve)){
    std::cout << "Failed to create key pair!" << std::endl;
    exit(1);
  }
  if (!uECC_shared_secret(public2, private1, secret1, ecc_curve)) {
    printf("shared_secret() failed (1)\n");
    return 1;
  }

  if (!uECC_shared_secret(public1, private2, secret2, ecc_curve)) {
    printf("shared_secret() failed (2)\n");
    return 1;
  }
  if (memcmp(secret1, secret2, sizeof(secret1)) != 0) {
    printf("Shared secrets are not identical!\n");
    printf("Private key 1 = ");
    vli_print(private1, 32);
    printf("\n");
    printf("Private key 2 = ");
    vli_print(private2, 32);
    printf("\n");
    printf("Public key 1 = ");
    vli_print(public1, 64);
    printf("\n");
    printf("Public key 2 = ");
    vli_print(public2, 64);
    printf("\n");
    printf("Shared secret 1 = ");
    vli_print(secret1, 32);
    printf("\n");
    printf("Shared secret 2 = ");
    vli_print(secret2, 32);
    printf("\n");
  }
  else{
    printf("Shared secret computed successfully!\n");
    std::cout << "Secret on node 1 is: ";
    vli_print(secret1, 32);
    std::cout << std::endl;
  }

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
  
   Ptr <Packet> packet_j = Create<Packet>((uint8_t*)cypher_buff, full_length);
   Simulator::Schedule ( Seconds (2) , &WaveNetDevice::SendX, wd0, packet_j, dest, protocol, tx);

   Ptr <Packet> packet_ecc = Create<Packet>(public1, 64);
   Simulator::Schedule ( Seconds (4) , &WaveNetDevice::SendX, wd0, packet_ecc, dest, protocol, tx);
    
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
