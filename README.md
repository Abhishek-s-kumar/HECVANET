# Secure VANET with HECC (Hyperelliptic Curve Cryptography)  
*A lightweight, attack-resistant VANET simulation using NS-3 + SUMO with HECC-based authentication.*

---

## 🔍 Overview  
This project simulates a **secure Vehicular Ad-Hoc Network (VANET)** with:  
- **NS-3** (802.11p/WAVE) for network modeling + **SUMO** for traffic dynamics.  
- **HECC (G2/G3 curves)** for efficient digital signatures and certificates.  
- Secure **OLSR routing** with attack mitigation (Sybil/Blackhole/DoS).  
- Performance metrics: PDR, latency, energy use, and cryptographic benchmarks.  

---

## 🛠️ Features  
✅ **Lightweight Security**: HECC reduces computational overhead vs ECC/RSA.  
✅ **Attack Simulation**: Sybil, Blackhole, and DoS attacks with defenses.  
✅ **Modular Design**: Easily extendable (add new cryptosystems/attacks).  
✅ **Reproducible**: Dockerized NS-3+SUMO environment.  

---

## 📊 Results  
- **Network Metrics**: Packet delivery ratio (PDR), end-to-end delay.  
- **Security Benchmarks**: HECC signing/verification times, energy consumption.  
- **Visualizations**: Movement paths, hash performance, attack success rates.  
*(See [`metrics/`](metrics/) for plots and raw data.)*  

---

## 🚀 Quick Start  
1. **Build & Run**:  
   ```bash
   docker build -t vanet-sim . && docker run -v $(pwd)/output:/app/output vanet-sim











├── ns3/                  # NS-3 custom module (HECC, secure routing)  
├── sumo_config/          # SUMO traffic scenarios  
├── src/                  # Python scripts (SUMO/NS-3 interfaces)  
├── metrics/              # Performance plots and benchmarks  
├── Dockerfile            # NS-3+SUMO simulation environment  
└── README.md  
