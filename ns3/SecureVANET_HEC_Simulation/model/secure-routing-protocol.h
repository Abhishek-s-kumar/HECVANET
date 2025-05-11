#ifndef SECURE_VANET_ROUTING_PROTOCOL_H
#define SECURE_VANET_ROUTING_PROTOCOL_H

#include "ns3/ipv4-routing-protocol.h"
#include "ns3/vector.h"
#include "ns3/random-variable-stream.h"
#include "crypto-helpers.h"

namespace ns3 {

class SecureRoutingProtocol : public Ipv4RoutingProtocol {
public:
  static TypeId GetTypeId();
  SecureRoutingProtocol();
  virtual ~SecureRoutingProtocol();

  // Ipv4RoutingProtocol interface
  virtual Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p, const Ipv4Header &header,
                                    Ptr<NetDevice> oif, Socket::SocketErrno &sockerr);
  virtual bool RouteInput(Ptr<const Packet> p, const Ipv4Header &header,
                         Ptr<const NetDevice> idev, UnicastForwardCallback ucb,
                         MulticastForwardCallback mcb, LocalDeliverCallback lcb,
                         ErrorCallback ecb);
  virtual void NotifyInterfaceUp(uint32_t interface);
  virtual void NotifyInterfaceDown(uint32_t interface);
  virtual void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address);
  virtual void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address);
  virtual void SetIpv4(Ptr<Ipv4> ipv4);
  virtual void PrintRoutingTable(Ptr<OutputStreamWrapper> stream) const;

  // Security functions
  bool VerifyPacket(Ptr<Packet> packet);
  Ptr<Packet> SignPacket(Ptr<Packet> packet);
  void HandleMaliciousNode(Ipv4Address address);

protected:
  void DoInitialize();
  
private:
  // Cryptographic operations
  Ptr<CryptoHelpers> m_crypto;
  
  // Routing tables
  std::map<Ipv4Address, Vector> m_neighborTable;
  std::set<Ipv4Address> m_blacklist;

  // Attack detection
  bool DetectSybilAttack(Ipv4Address address);
  bool DetectBlackhole(Ptr<const Packet> packet);
  void LogAttack(Ipv4Address attacker, std::string attackType);
};

} // namespace ns3

#endif
