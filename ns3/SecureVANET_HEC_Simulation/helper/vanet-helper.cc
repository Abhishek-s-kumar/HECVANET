#include "vanet-helper.h"
#include "ns3/secure-routing-protocol.h"

namespace ns3 {

VanetHelper::VanetHelper() {
  m_routingFactory.SetTypeId("ns3::SecureRoutingProtocol");
}

void VanetHelper::Install(NodeContainer nodes) const {
  for (NodeContainer::Iterator i = nodes.Begin(); i != nodes.End(); ++i) {
    Ptr<Node> node = *i;
    Ptr<SecureRoutingProtocol> routing = m_routingFactory.Create<SecureRoutingProtocol>();
    node->AggregateObject(routing);
    
    // Configure crypto for this node
    Ptr<CryptoHelpers> crypto = CreateObject<CryptoHelpers>();
    routing->SetCryptoHelpers(crypto);
  }
}

} // namespace ns3
