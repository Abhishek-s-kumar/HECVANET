# Simulation of Secure VANET communication scheme using ECC/HECC

NS-3 simulation for investigating potential ECC/HECC usage for improvements on security and efficiency of authentication and secure message exchange of vehicles and infrastructure in VANETs.

Simulated scheme: [A Low-Overhead Message Authentication and Secure Message Dissemination Scheme for VANETs](https://www.mdpi.com/2673-8732/2/1/10) [[1]](#1).

Simulation tested on NS-3 version 3.30.

## Simulation implementation

Traffic simulation was produced using SUMO and exported to tcl file. Using *Ns2MobilityHelper* and [*Ns2Util*](https://github.com/addola/NS3-HelperScripts/tree/master) the traffic is imported to NS-3 as moving nodes. The current tcl file produces 63 vehicles in circa 100 seconds and one more node is added to act as an RSU.

Every node is assigned WAVE net devices for communication.

Communication is implemented in WAVE layer for better performance evaluation.

## Cryptographic methods

Implemented using Crypto++ library for ECC, libg2hec for HECC genus 2 and g3hec that is implemented in this repository.

* ElGamal Encryption/Decryption
* ECDSA signatures for ECC, ElGamal signatures for HECC
* HECQV certificates
* Koblitz encodings for ECC, [UnifiedEncoding](https://link.springer.com/chapter/10.1007/978-3-319-89339-6_11#citeas) [[2]](#2) method for HECC
* Point compression for ECC, divisor compression for HECC genus 2

**Note:** Since HECC is still being researched, not many algorithms for encodings have been produced. Also, there are not a lot of secure curves already generated in bibliography. UnifiedEncoding is used to generate the curves for genus 2 and 3 HECC for all the cryptographic methods instead of signatures, because the Group Order is required to be known. For simulation purposes, different curves are used for signatures (on same security level) that are known from bibliography to produce an "almost" prime Group Order. Different key-pairs are needed, but in the current implementation only one key-pair is exchanged per vehicle/RSU and the key-pair for signatures is fixed. This enables more realistic results of the simulation, because exchanging more key-pairs would create bigger traffic than actually needed.

## Metrics

The simulation takes measurements on the same level of security for ECC and HECC implementations for:

* Computation time of cryptographic methods
* Message sizes
* Energy consumption

Time measurements are done using chrono.
For energy consumption measurements a slight modification was made to WifiEnergyHelper classes. See *wave-energy-helper*.

**Note:** Measurements on signatures are done in different security levels, specifically in 256-bit for ECC and 168-bit for HECC, because of the limitations on the known secure curves.

## How-To run simulation

1. Copy the SecureVANET_HEC_Simulation folder on your NS-3 scartch folder.
2. Edit the wscript file by linking NS-3 with libraries Crypto++, libg2hec and g3HEC (see g3hec folder).
3. run ./waf --run "SecureVANET_HEC_Simulation --algo=*0: HECC genus 2, 1: ECC, 2: HECC genus 3* --metrics=*0: no measurements, 1: take measurements*" --vis (if PyViz is enabled)

<a id="1">[1]</a>
Hassan Mistareehi and D. Manivannan, "A Low-Overhead Message
Authentication and Secure Message Dissemination Scheme for VANETs,"
*Network*, vol. 2, pp. 139-152, 2022

<a id="2">[2]</a>
Michel Seck & Nafissatou Diarra , "Unified Formulas for Some Deterministic
Almost-Injective Encodings into Hyperelliptic Curves," *Joux, A., Nitaj, A., Rachidi,
T. (eds) Progress in Cryptology – AFRICACRYPT*, vol. 10831, 2018.
