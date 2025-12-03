# 🔐 Centralized Context-Aware Firewall

![Java](https://img.shields.io/badge/Java-11%2B-orange?style=flat-square&logo=java)
![Build](https://img.shields.io/badge/Build-Maven-blue?style=flat-square&logo=apachemaven)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Prototype-lightgrey?style=flat-square)

A Java-based firewall prototype that monitors and controls network traffic using **context-aware policies**. Unlike traditional firewalls, it filters packets based on application identity, protocol, and destination context.

## 🚀 Key Features

* **Context-Aware Filtering**: Decisions based on App Name, Domain, Protocol, and Port.
* **Real-Time Packet Capture**: Live traffic monitoring using `Pcap4J` and `Npcap`/`Libpcap`.
* **Interactive GUI**: Dashboard to view live traffic flows and allowed/denied statistics.
* **Anomaly Detection**: Alerts on suspicious activities like excessive denied requests.
* **Hot-Configurable**: Update rules in `policies.txt` without restarting.

## 🛠 Tech Stack

* **Core**: Java 11, Apache Maven
* **Networking**: Pcap4J (Packet Capture)
* **UI**: Java Swing

## 📋 Prerequisites

1.  **Java JDK 11+**
2.  **Apache Maven**
3.  **Packet Capture Driver**:
    * *Windows*: [Npcap](https://npcap.com/) (Install in "WinPcap API-compatible Mode")
    * *Linux*: `libpcap` (`sudo apt install libpcap-dev`)

## ⚠️ Disclaimer
* **This application is a Proof of Concept (PoC) and Simulation.**
* **Not a Kernel Firewall**: It captures and analyzes copies of packets using Pcap4J but does not sit inline to block traffic at the OS level.
* **Purpose**: Demonstrates context-aware logic and deep packet inspection (DPI) concepts in Java.

## ⚡ Quick Start

**Clone & Build**
```bash
git clone [https://github.com/vishalchoudhary07/centralized-context-aware-firewall.git](https://github.com/vishalchoudhary07/centralized-context-aware-firewall.git)
cd centralized-context-aware-firewall
mvn clean install
