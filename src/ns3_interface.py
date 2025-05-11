import ns.core
import ns.network
import ns.mobility
import ns.wifi
import ns.wave
import ns.applications
from typing import Dict, List, Tuple
import numpy as np

class Ns3VanetController:
    def __init__(self, simulation_time: float = 100.0):
        """
        Initialize NS-3 VANET simulation environment
        
        Args:
            simulation_time: Total simulation time in seconds
        """
        self.simulation_time = simulation_time
        self.nodes = ns.network.NodeContainer()
        self.devices = ns.network.NetDeviceContainer()
        self.vehicles = {}  # veh_id: (node, mobility_model)
        self.stats = {
            "sent_packets": 0,
            "received_packets": 0,
            "dropped_packets": 0
        }

    def configure_80211p(self):
        """Configure 802.11p PHY and MAC layers"""
        wifi = ns.wifi.WifiHelper()
        mac = ns.wave.WifiMacHelper()
        phy = ns.wifi.YansWifiPhyHelper()
        channel = ns.wifi.YansWifiChannelHelper.Default()
        
        # Set channel parameters
        phy.SetChannel(channel.Create())
        phy.SetPcapDataLinkType(phy.DLT_IEEE802_11)
        
        # Configure 802.11p
        wifi.SetStandard(ns.wifi.WIFI_STANDARD_80211p)
        wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                   "DataMode", ns.core.StringValue("OfdmRate6MbpsBW10MHz"),
                                   "ControlMode", ns.core.StringValue("OfdmRate6MbpsBW10MHz"))
        
        # Install devices
        mac.SetType("ns3::AdhocWifiMac")
        self.devices = wifi.Install(phy, mac, self.nodes)

    def add_vehicle(self, veh_id: str, position: Tuple[float, float, float]):
        """
        Add a vehicle to the NS-3 simulation
        
        Args:
            veh_id: Unique vehicle identifier
            position: (x, y, z) coordinates in meters
        """
        node = ns.network.Node()
        self.nodes.Add(node)
        
        # Configure mobility
        mobility = ns.mobility.ConstantPositionMobilityModel()
        mobility.SetPosition(ns.core.Vector(*position))
        node.AggregateObject(mobility)
        
        # Store reference
        self.vehicles[veh_id] = (node, mobility)
        return node

    def update_vehicle_position(self, veh_id: str, position: Tuple[float, float]):
        """Update vehicle position in NS-3"""
        if veh_id in self.vehicles:
            _, mobility = self.vehicles[veh_id]
            mobility.SetPosition(ns.core.Vector(position[0], position[1], 0))

    def setup_routing(self):
        """Configure OLSR routing with security extensions"""
        internet = ns.internet.InternetStackHelper()
        internet.SetRoutingHelper(ns.internet.OlsrHelper())
        internet.Install(self.nodes)
        
        # Assign IP addresses
        ipv4 = ns.internet.Ipv4AddressHelper()
        ipv4.SetBase(ns.network.Ipv4Address("10.1.0.0"), ns.network.Ipv4Mask("255.255.0.0"))
        ipv4.Assign(self.devices)

    def setup_applications(self, packet_size: int = 512, interval: float = 0.1):
        """Configure VANET applications (beaconing)"""
        # Setup broadcast sender on all nodes
        app = ns.applications.OnOffHelper(
            "ns3::UdpSocketFactory",
            ns.network.Address(ns.network.InetSocketAddress(ns.network.Ipv4Address("10.1.255.255"), 9))
        )
        app.SetAttribute("PacketSize", ns.core.UintegerValue(packet_size))
        app.SetAttribute("OnTime", ns.core.StringValue("ns3::ConstantRandomVariable[Constant=1]"))
        app.SetAttribute("OffTime", ns.core.StringValue("ns3::ConstantRandomVariable[Constant=0]"))
        app.SetAttribute("DataRate", ns.network.DataRateValue(ns.network.DataRate("500kb/s")))
        
        apps = app.Install(self.nodes)
        apps.Start(ns.core.Seconds(1.0))
        apps.Stop(ns.core.Seconds(self.simulation_time))

    def start(self):
        """Start NS-3 simulation"""
        self.configure_80211p()
        self.setup_routing()
        self.setup_applications()
        
        # Enable PCAP tracing
        ns.wifi.PhyHelper.EnablePcap("vanet", self.devices)
        
        ns.core.Simulator.Run()
        ns.core.Simulator.Destroy()

    def get_stats(self) -> Dict[str, int]:
        """Get current simulation statistics"""
        return self.stats

    def send_packet(self, src_veh_id: str, payload: str) -> bool:
        """
        Send packet from specified vehicle
        
        Args:
            src_veh_id: Source vehicle ID
            payload: Message content to send
            
        Returns:
            bool: True if packet was successfully sent
        """
        if src_veh_id not in self.vehicles:
            return False
            
        src_node, _ = self.vehicles[src_veh_id]
        socket = ns.network.Socket.CreateSocket(src_node, ns.network.UdpSocketFactory())
        
        packet = ns.network.Packet(payload.encode())
        socket.Send(packet)
        
        self.stats["sent_packets"] += 1
        return True

    def configure_attack(self, veh_id: str, attack_type: str, params: Dict = None):
        """
        Configure attack simulation
        
        Args:
            veh_id: Vehicle ID to launch attack from
            attack_type: "sybil", "blackhole", or "dos"
            params: Attack-specific parameters
        """
        if veh_id not in self.vehicles:
            return
            
        node, _ = self.vehicles[veh_id]
        
        if attack_type == "sybil":
            num_fake_nodes = params.get("num_fake_nodes", 3)
            self._launch_sybil_attack(node, num_fake_nodes)
        elif attack_type == "blackhole":
            drop_rate = params.get("drop_rate", 0.8)
            self._configure_blackhole(node, drop_rate)

    def _launch_sybil_attack(self, node: ns.network.Node, num_fake_nodes: int):
        """Internal method to simulate Sybil attack"""
        for i in range(num_fake_nodes):
            fake_id = f"sybil_{i}"
            self.add_vehicle(fake_id, (0, 0, 0))
            # Associate fake node with attacker
            self.vehicles[fake_id][0].AggregateObject(node.GetObject[ns.wifi.WifiNetDevice]())

    def _configure_blackhole(self, node: ns.network.Node, drop_rate: float):
        """Internal method to configure blackhole attack"""
        device = node.GetDevice(0)
        device.SetReceiveCallback(self._make_blackhole_callback(drop_rate))

    def _make_blackhole_callback(self, drop_rate: float):
        """Create packet dropping callback"""
        def callback(device, packet, protocol, src, dst, packet_type):
            if np.random.random() < drop_rate:
                self.stats["dropped_packets"] += 1
                return False
            self.stats["received_packets"] += 1
            return True
        return callback

# Example usage
if __name__ == "__main__":
    # Initialize simulation
    ns3 = Ns3VanetController(simulation_time=60.0)
    
    # Add vehicles
    ns3.add_vehicle("car1", (100, 50, 0))
    ns3.add_vehicle("car2", (150, 50, 0))
    
    # Configure attack
    ns3.configure_attack("car2", "blackhole", {"drop_rate": 0.5})
    
    # Run simulation
    ns3.start()
    
    # Print results
    print("Simulation statistics:")
    print(ns3.get_stats())
