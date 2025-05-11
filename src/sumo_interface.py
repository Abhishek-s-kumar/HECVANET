import traci
import time
from typing import Dict, List, Tuple
import numpy as np

class SumoSimulator:
    def __init__(self, config_file: str):
        """
        Initialize SUMO simulation
        
        Args:
            config_file: Path to SUMO configuration file (.sumocfg)
        """
        self.config = config_file
        self.simulation = None
        self.vehicle_ids = []
        self.step_length = 0.1  # 100ms per step (matches NS-3)

    def start(self, port: int = 8813):
        """Start SUMO simulation with TraCI connection"""
        traci.start(["sumo", "-c", self.config], port=port)
        self.simulation = traci
        self.vehicle_ids = self.simulation.vehicle.getIDList()

    def step(self):
        """Advance simulation by one step"""
        self.simulation.simulationStep()
        self.vehicle_ids = self.simulation.vehicle.getIDList()

    def get_vehicle_positions(self) -> Dict[str, Tuple[float, float]]:
        """Get current positions of all vehicles"""
        return {
            veh_id: self.simulation.vehicle.getPosition(veh_id)
            for veh_id in self.vehicle_ids
        }

    def get_vehicle_speeds(self) -> Dict[str, float]:
        """Get current speeds of all vehicles"""
        return {
            veh_id: self.simulation.vehicle.getSpeed(veh_id)
            for veh_id in self.vehicle_ids
        }

    def get_vehicle_routes(self) -> Dict[str, List[Tuple[float, float]]]:
        """Get planned routes for all vehicles"""
        routes = {}
        for veh_id in self.vehicle_ids:
            edges = self.simulation.vehicle.getRoute(veh_id)
            routes[veh_id] = [
                self.simulation.simulation.convert2D(edge) 
                for edge in edges
            ]
        return routes

    def add_vehicle(self, veh_id: str, route_id: str, pos: float = 0.0):
        """
        Add a new vehicle to the simulation
        
        Args:
            veh_id: Unique vehicle identifier
            route_id: Existing route in SUMO network
            pos: Initial position along route
        """
        self.simulation.vehicle.add(
            veh_id, route_id, 
            departPos=pos,
            departSpeed="random"
        )
        self.vehicle_ids.append(veh_id)

    def set_vehicle_speed(self, veh_id: str, speed: float):
        """Set vehicle's target speed"""
        self.simulation.vehicle.setSpeed(veh_id, speed)

    def get_traffic_metrics(self) -> Dict[str, float]:
        """Collect traffic performance metrics"""
        return {
            "avg_speed": np.mean(list(self.get_vehicle_speeds().values())),
            "vehicle_count": len(self.vehicle_ids),
            "time": self.simulation.simulation.getTime()
        }

    def close(self):
        """Cleanly terminate SUMO connection"""
        if self.simulation:
            self.simulation.close()
            self.simulation = None

    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

# Example usage:
if __name__ == "__main__":
    sumo_config = "sumo_config/map.sumocfg"
    
    with SumoSimulator(sumo_config) as sumo:
        for _ in range(100):  # Run 100 simulation steps
            sumo.step()
            
            # Example data collection
            positions = sumo.get_vehicle_positions()
            metrics = sumo.get_traffic_metrics()
            
            print(f"Step {_}: {len(positions)} vehicles, Avg speed: {metrics['avg_speed']:.2f}")
