
# 🔐 Centralized Application – Context-Aware Firewall

A Java-based prototype firewall system that monitors, logs, and analyzes application-level network traffic using real-time packet capture. It applies context-aware policies and allows centralized control of firewall rules per application.

## 📌 Project Overview

This project simulates a **Context-Aware Firewall** that goes beyond traditional firewalls by considering:

- Which **application** is generating the traffic
- The **time** and **destination** of the request
- Network parameters like **IP**, **port**, and **protocol**

The system applies allow/deny decisions based on this context and provides real-time visibility through a GUI.

## 🚀 Features

- 🔍 **Real-Time Packet Capture** using Npcap and Pcap4J
- ⚙️ **Context-Aware Rule Enforcement** based on application identity and destination
- 📄 **Logging System** (`network_usage.log` and `alerts.log`) for network usage and anomalies
- 🖥️ **Interactive GUI** to start/stop capture and view live traffic logs
- 📁 **Centralized Policy Configuration** via `policies.txt`
- 📊 **Traffic Analysis Panel** with statistics and colored decision indicators

## 🧱 Architecture

- **FirewallAgent** – Core engine that checks packets against policies
- **PolicyManager** – Parses and applies rules from policy files
- **Npcap Integration** – Captures real network packets
- **AlertEngine & Logger** – Logs activity and triggers alerts
- **GUI (Swing-based)** – Real-time interface for monitoring and control

  ## ❗ Note
This is a simulation and proof-of-concept, not a production firewall. It does not block traffic at the OS level but shows how context-aware logic can be applied on real traffic data.
