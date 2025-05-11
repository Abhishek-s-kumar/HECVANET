#include "secure-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("SecureVanetRoutingProtocol");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(SecureRoutingProtocol);

TypeId SecureRoutingProtocol::GetTypeId() {
  static TypeId tid = TypeId("ns3::SecureRoutingProtocol")
    .SetParent<Ipv4RoutingProtocol>()
    .SetGroupName("SecureVanet")
    .AddConstructor<SecureRoutingProtocol>()
    .AddAttribute("HelloInterval", "HELLO messages interval",
                  TimeValue(Seconds(1.0)),
                  MakeTimeAccessor(&SecureRoutingProtocol::m_helloInterval),
                  MakeTimeChecker());
  return tid;
}

SecureRoutingProtocol::SecureRoutingProtocol() 
  : m_crypto(CreateObject<CryptoHelpers>()) {
  m_uniformRandomVariable = CreateObject<UniformRandomVariable>();
}

bool SecureRoutingProtocol::VerifyPacket(Ptr<Packet> packet) {
  VanetHeader header;
  packet->PeekHeader(header);
  
  if (!m_crypto->VerifySignature(header.GetMessage(), header.GetSignature())) {
    NS_LOG_WARN("Invalid packet signature from " << header.GetSourceAddress());
    return false;
  }
  return true;
}

Ptr<Packet> SecureRoutingProtocol::SignPacket(Ptr<Packet> packet) {
  VanetHeader header;
  packet->RemoveHeader(header);
  
  std::string signature = m_crypto->SignMessage(header.GetMessage());
  header.SetSignature(signature);
  
  packet->AddHeader(header);
  return packet;
}

bool SecureRoutingProtocol::DetectSybilAttack(Ipv4Address address) {
  // Check if this address appears too frequently
  uint32_t count = std::count_if(m_neighborTable.begin(), m_neighborTable.end(),
    [address](const auto& entry) { return entry.first == address; });
  
  return (count > SYBIL_THRESHOLD);
}

Ptr<Ipv4Route> SecureRoutingProtocol::RouteOutput(Ptr<Packet> p, const Ipv4Header &header,
                                                 Ptr<NetDevice> oif, Socket::SocketErrno &sockerr) {
  // Secure routing logic implementation
  if (m_blacklist.count(header.GetDestination()) > 0) {
    sockerr = Socket::ERROR_NOROUTETOHOST;
    return nullptr;
  }
  
  Ptr<Ipv4Route> route = Create<Ipv4Route>();
  route->SetDestination(header.GetDestination());
  
  // Simplified routing - real implementation would use neighbor table
  route->SetOutputDevice(m_ipv4->GetNetDevice(1));
  route->SetGateway(Ipv4Address("10.0.0.2"));
  
  return route;
}

} // namespace ns3
