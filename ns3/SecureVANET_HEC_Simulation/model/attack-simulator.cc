#include "attack-simulator.h"
#include "ns3/random-variable-stream.h"

namespace ns3 {

AttackSimulator::AttackSimulator() {
  m_attackType = ATTACK_NONE;
  m_attackProbability = 0.0;
}

void AttackSimulator::ConfigureAttack(AttackType type, double probability) {
  m_attackType = type;
  m_attackProbability = probability;
}

bool AttackSimulator::ShouldExecuteAttack() {
  if (m_attackProbability <= 0.0) return false;
  
  Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
  return (uv->GetValue(0.0, 1.0) < m_attackProbability);
}

void AttackSimulator::ExecuteSybilAttack(Ptr<Packet> packet) {
  VanetHeader header;
  packet->RemoveHeader(header);
  
  // Clone packet with fake source
  for (int i = 0; i < 3; i++) {
    Ptr<Packet> fakePacket = packet->Copy();
    VanetHeader fakeHeader = header;
    fakeHeader.SetSourceAddress(Ipv4Address(192,168,1,100+i));
    fakePacket->AddHeader(fakeHeader);
    
    // Send to network
    m_sendCallback(fakePacket);
  }
}

} // namespace ns3
