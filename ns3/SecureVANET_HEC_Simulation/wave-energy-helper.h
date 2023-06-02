#include "ns3/energy-model-helper.h"
 #include "ns3/wifi-radio-energy-model.h"
 
 namespace ns3 {
 
 class WaveRadioEnergyModelHelper : public DeviceEnergyModelHelper
 {
 public:
   WaveRadioEnergyModelHelper ();
 
   ~WaveRadioEnergyModelHelper ();
 
   void Set (std::string name, const AttributeValue &v);
 
   void SetDepletionCallback (
     WifiRadioEnergyModel::WifiRadioEnergyDepletionCallback callback);
 
   void SetRechargedCallback (
     WifiRadioEnergyModel::WifiRadioEnergyRechargedCallback callback);
 
   void SetTxCurrentModel (std::string name,
                           std::string n0 = "", const AttributeValue &v0 = EmptyAttributeValue (),
                           std::string n1 = "", const AttributeValue &v1 = EmptyAttributeValue (),
                           std::string n2 = "", const AttributeValue &v2 = EmptyAttributeValue (),
                           std::string n3 = "", const AttributeValue &v3 = EmptyAttributeValue (),
                           std::string n4 = "", const AttributeValue &v4 = EmptyAttributeValue (),
                           std::string n5 = "", const AttributeValue &v5 = EmptyAttributeValue (),
                           std::string n6 = "", const AttributeValue &v6 = EmptyAttributeValue (),
                           std::string n7 = "", const AttributeValue &v7 = EmptyAttributeValue ());
 
 private:
   virtual Ptr<DeviceEnergyModel> DoInstall (Ptr<NetDevice> device,
                                             Ptr<EnergySource> source) const;
 
 private:
   ObjectFactory m_radioEnergy; 
   WifiRadioEnergyModel::WifiRadioEnergyDepletionCallback m_depletionCallback; 
   WifiRadioEnergyModel::WifiRadioEnergyRechargedCallback m_rechargedCallback; 
   ObjectFactory m_txCurrentModel; 
 
 };
 
 } // namespace ns3