#include "wave-energy-helper.h"
 #include "ns3/wifi-net-device.h"
 #include "ns3/wifi-tx-current-model.h"
 #include "ns3/wifi-phy.h"
 #include "ns3/wave-module.h"
 
 namespace ns3 {
 
 WaveRadioEnergyModelHelper::WaveRadioEnergyModelHelper ()
 {
   m_radioEnergy.SetTypeId ("ns3::WifiRadioEnergyModel");
   m_depletionCallback.Nullify ();
   m_rechargedCallback.Nullify ();
 }
 
 WaveRadioEnergyModelHelper::~WaveRadioEnergyModelHelper ()
 {
 }
 
 void
 WaveRadioEnergyModelHelper::Set (std::string name, const AttributeValue &v)
 {
   m_radioEnergy.Set (name, v);
 }
 
 void
 WaveRadioEnergyModelHelper::SetDepletionCallback (
   WifiRadioEnergyModel::WifiRadioEnergyDepletionCallback callback)
 {
   m_depletionCallback = callback;
 }
 
 void
 WaveRadioEnergyModelHelper::SetRechargedCallback (
   WifiRadioEnergyModel::WifiRadioEnergyRechargedCallback callback)
 {
   m_rechargedCallback = callback;
 }
 
 void
 WaveRadioEnergyModelHelper::SetTxCurrentModel (std::string name,
                                                std::string n0, const AttributeValue& v0,
                                                std::string n1, const AttributeValue& v1,
                                                std::string n2, const AttributeValue& v2,
                                                std::string n3, const AttributeValue& v3,
                                                std::string n4, const AttributeValue& v4,
                                                std::string n5, const AttributeValue& v5,
                                                std::string n6, const AttributeValue& v6,
                                                std::string n7, const AttributeValue& v7)
 {
   ObjectFactory factory;
   factory.SetTypeId (name);
   factory.Set (n0, v0);
   factory.Set (n1, v1);
   factory.Set (n2, v2);
   factory.Set (n3, v3);
   factory.Set (n4, v4);
   factory.Set (n5, v5);
   factory.Set (n6, v6);
   factory.Set (n7, v7);
   m_txCurrentModel = factory;
 }
 
 
 /*
  * Private function starts here.
  */
 
 Ptr<DeviceEnergyModel>
 WaveRadioEnergyModelHelper::DoInstall (Ptr<NetDevice> device,
                                        Ptr<EnergySource> source) const
 {
   NS_ASSERT (device != NULL);
   NS_ASSERT (source != NULL);
   // check if device is WifiNetDevice
   std::string deviceName = device->GetInstanceTypeId ().GetName ();
   
   if ((deviceName.compare ("ns3::WifiNetDevice") != 0) && (deviceName.compare ("ns3::WaveNetDevice") != 0))
     {
       NS_FATAL_ERROR ("NetDevice type is not WifiNetDevice!");
     }
   Ptr<Node> node = device->GetNode ();
   Ptr<WifiRadioEnergyModel> model = m_radioEnergy.Create ()->GetObject<WifiRadioEnergyModel> ();
   NS_ASSERT (model != NULL);
 
   // set energy depletion callback
   // if none is specified, make a callback to WifiPhy::SetOffMode
   
   Ptr<WaveNetDevice> waveDevice = DynamicCast<WaveNetDevice> (device);
   Ptr<WifiPhy> wifiPhy = waveDevice->GetPhy (0);
   wifiPhy->SetWifiRadioEnergyModel (model);
   if (m_depletionCallback.IsNull ())
     {
       model->SetEnergyDepletionCallback (MakeCallback (&WifiPhy::SetOffMode, wifiPhy));
     }
   else
     {
       model->SetEnergyDepletionCallback (m_depletionCallback);
     }
   // set energy recharged callback
   // if none is specified, make a callback to WifiPhy::ResumeFromOff
   if (m_rechargedCallback.IsNull ())
     {
       model->SetEnergyRechargedCallback (MakeCallback (&WifiPhy::ResumeFromOff, wifiPhy));
     }
   else
     {
       model->SetEnergyRechargedCallback (m_rechargedCallback);
     }
   // add model to device model list in energy source
   source->AppendDeviceEnergyModel (model);
   // set energy source pointer
   model->SetEnergySource (source);
   // create and register energy model phy listener
   wifiPhy->RegisterListener (model->GetPhyListener ());
   //
   if (m_txCurrentModel.GetTypeId ().GetUid ())
     {
       Ptr<WifiTxCurrentModel> txcurrent = m_txCurrentModel.Create<WifiTxCurrentModel> ();
       model->SetTxCurrentModel (txcurrent);
     }
   return model;
 }
 
 } // namespace ns3