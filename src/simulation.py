import random
import hashlib
import matplotlib.pyplot as plt
import time
import pandas as pd
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple
import numpy as np

# NS-3 imports
try:
    import ns.core
    import ns.network
    import ns.mobility
    import ns.applications
    import ns.wifi
    NS3_AVAILABLE = True
except ImportError:
    NS3_AVAILABLE = False

@dataclass
class VehicleMetrics:
    speeds: List[float] = None
    positions: List[Tuple[float, float]] = None
    hash_performance: Dict[str, List[float]] = None
    message_count: int = 0
    collision_count: int = 0
    security_metrics: Dict[str, List] = None
    network_metrics: Dict[str, List] = None

    def __post_init__(self):
        self.speeds = []
        self.positions = []
        self.hash_performance = {
            "sha256": [], "md5": [], "sha1": [],
            "blake2b": [], "sha3_256": []
        }
        self.security_metrics = {
            "signature_times": [],
            "verification_times": [],
            "failed_verifications": 0
        }
        self.network_metrics = {
            "latency": [],
            "throughput": []
        }

class Vehicle:
    def __init__(self, vehicle_id: str, speed: float, position: Tuple[float, float]):
        self.id = vehicle_id
        self.speed = speed
        self.position = position
        self.salt = "vanet_shared_salt"
        self.metrics = VehicleMetrics()
        self.net_device = None

        if NS3_AVAILABLE:
            self.node = ns.network.Node()
            self.mobility = ns.mobility.ConstantPositionMobilityModel()
            self.mobility.SetPosition(ns.core.Vector(position[0], position[1], 0))
            self.node.AggregateObject(self.mobility)
            self.net_device = self._setup_network_device()

    def _setup_network_device(self):
        if not NS3_AVAILABLE:
            return None

        wifi = ns.wifi.WifiHelper()
        mac = ns.wifi.WifiMacHelper()
        phy = ns.wifi.YansWifiPhyHelper()
        channel = ns.wifi.YansWifiChannelHelper.Default()

        phy.SetChannel(channel.Create())
        wifi.SetStandard(ns.wifi.WIFI_STANDARD_80211p)

        devices = wifi.Install(phy, mac, self.node)
        return devices.Get(0)

    def move(self, dt: float):
        dx = self.speed * dt * random.uniform(0.9, 1.1)
        dy = self.speed * dt * random.uniform(-0.1, 0.1)
        self.position = (self.position[0] + dx, self.position[1] + dy)
        self.metrics.positions.append(self.position)
        self.metrics.speeds.append(self.speed)
        if NS3_AVAILABLE:
            self.mobility.SetPosition(ns.core.Vector(self.position[0], self.position[1], 0))

    def send_message(self):
        try:
            import ns.network
            message, hashes = self.generate_message()
            payload = str({"message": message, "hashes": hashes}).encode()
            packet = ns.network.Packet(payload)
            if self.net_device:
                success = self.net_device.Send(packet)
                print(f"Vehicle {self.id} sent a message via NS-3: {success}")
        except ImportError:
            print("NS-3 Python bindings not available. Skipping NS-3 send.")

    def send_secure_message(self, message: Dict):
        if not NS3_AVAILABLE:
            return False

        packet = ns.network.Packet(str(message).encode())
        return self.net_device.Send(packet)

    def check_collision(self, other: 'Vehicle', threshold: float = 1.0) -> bool:
        distance = np.sqrt((self.position[0] - other.position[0])**2 +
                           (self.position[1] - other.position[1])**2)
        return distance < threshold

    def generate_message(self) -> Tuple[Dict, Dict]:
        message = {
            "vehicle_id": self.id,
            "speed": self.speed,
            "position": self.position,
            "timestamp": time.time()
        }
        return message, self.hash_message(message)

    def hash_message(self, message: Dict) -> Dict:
        message_bytes = str(message).encode()
        hashes = {}

        for algo in ["sha256", "md5", "sha1", "blake2b", "sha3_256"]:
            start_time = time.perf_counter()
            hasher = getattr(hashlib, algo)
            hashes[algo] = hasher(message_bytes + self.salt.encode()).hexdigest()
            hashes[f"{algo}_time"] = time.perf_counter() - start_time
            self.metrics.hash_performance[algo].append(hashes[f"{algo}_time"])

        return hashes

    def check_integrity(self, message: Dict, hashes: Dict) -> bool:
        current_hashes = self.hash_message(message)
        for algo in ["sha256", "md5", "sha1", "blake2b", "sha3_256"]:
            if hashes[algo] != current_hashes[algo]:
                return False
        return True

    def receive_message(self, message: Dict, hashes: Dict):
        self.metrics.message_count += 1
        print(f"Vehicle {self.id} received message from {message['vehicle_id']}")

        if not self.check_integrity(message, hashes):
            print("ALERT: Message integrity check failed!")
            return False

        print(f"Valid message: Speed={message['speed']}, Position={message['position']}")
        return True

    def save_metrics(self, output_dir: str = "metrics"):
        Path(output_dir).mkdir(exist_ok=True)
        metrics = {
            "id": self.id,
            "average_speed": np.mean(self.metrics.speeds),
            "total_messages": self.metrics.message_count,
            "collisions": self.metrics.collision_count,
            "hash_performance": {k: np.mean(v) for k, v in self.metrics.hash_performance.items()}
        }

        with open(f"{output_dir}/{self.id}_metrics.json", "w") as f:
            json.dump(metrics, f, indent=2)

def simulate(vehicles: List[Vehicle], dt: float, num_steps: int):
    print(f"Starting simulation with {len(vehicles)} vehicles for {num_steps} steps")

    for step in range(num_steps):
        for vehicle in vehicles:
            vehicle.move(dt)

            collisions = [v for v in vehicles if v != vehicle and vehicle.check_collision(v)]
            if collisions:
                vehicle.metrics.collision_count += 1
                print(f"Collision: {vehicle.id} with {[v.id for v in collisions]}")

            message, hashes = vehicle.generate_message()
            for other in vehicles:
                if other != vehicle:
                    other.receive_message(message.copy(), hashes.copy())

    for vehicle in vehicles:
        vehicle.save_metrics()

    generate_performance_plots(vehicles)
    generate_movement_plots(vehicles)

def generate_performance_plots(vehicles: List[Vehicle]):
    hash_data = []
    for vehicle in vehicles:
        for algo, times in vehicle.metrics.hash_performance.items():
            for t in times:
                hash_data.append({"vehicle": vehicle.id, "algorithm": algo, "time": t})

    hash_df = pd.DataFrame(hash_data)
    plt.figure(figsize=(12, 6))
    hash_df.boxplot(column="time", by="algorithm", showfliers=False)
    plt.title("Hash Algorithm Performance Comparison")
    plt.ylabel("Time (seconds)")
    plt.xlabel("Hash Algorithm")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("metrics/hash_performance.png")
    plt.close()

def generate_movement_plots(vehicles: List[Vehicle]):
    plt.figure(figsize=(10, 8))

    for vehicle in vehicles:
        positions = np.array(vehicle.metrics.positions)
        plt.plot(positions[:, 0], positions[:, 1], label=f"Vehicle {vehicle.id}")
        plt.scatter(positions[-1, 0], positions[-1, 1], marker='o')

    plt.title("Vehicle Movement Paths")
    plt.xlabel("X Position")
    plt.ylabel("Y Position")
    plt.legend()
    plt.grid(True)
    plt.savefig("metrics/movement_paths.png")
    plt.close()

if __name__ == "__main__":
    vehicles = [
        Vehicle("V1", 60, (0, 0)),
        Vehicle("V2", 55, (100, 50)),
        Vehicle("V3", 65, (50, 100)),
        Vehicle("V4", 50, (200, 0))
    ]

    simulate(vehicles, dt=0.1, num_steps=500)

    msg, hashes = vehicles[0].generate_message()
    vehicles[1].receive_message(msg, hashes)
    tampered_msg = msg.copy()
    tampered_msg["speed"] = 100
    vehicles[1].receive_message(tampered_msg, hashes)
