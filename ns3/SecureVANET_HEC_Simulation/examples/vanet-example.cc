#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "vanet-helper.h"

using namespace ns3;

int main(int argc, char *argv[]) {
  // Create nodes
  NodeContainer nodes;
  nodes.Create(50);
  
  // Setup mobility
  MobilityHelper mobility;
  mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                               "MinX", DoubleValue(0.0),
                               "MinY", DoubleValue(0.0),
                               "DeltaX", DoubleValue(20.0),
                               "DeltaY", DoubleValue(20.0),
                               "GridWidth", UintegerValue(5),
                               "LayoutType", StringValue("RowFirst"));
  mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                           "Bounds", RectangleValue(Rectangle(0, 500, 0, 500)));
  mobility.Install(nodes);
  
  // Install VANET protocol
  VanetHelper vanet;
  vanet.Install(nodes);
  
  // Configure attacks on some nodes
  Ptr<AttackSimulator> attack = CreateObject<AttackSimulator>();
  attack->ConfigureAttack(AttackSimulator::ATTACK_SYBIL, 0.3);
  nodes.Get(10)->AggregateObject(attack);
  
  // Run simulation
  Simulator::Stop(Seconds(100.0));
  Simulator::Run();
  Simulator::Destroy();
  
  return 0;
}
