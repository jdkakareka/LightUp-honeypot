# Honeypot RGB Threat Board

An automated cybersecurity observability pipeline connecting an internet-facing Cowrie SSH/Telnet honeypot to physical RGB lighting panels via zero-latency local UDP control.

---

## Overview

Public-facing cloud instances endure continuous background credential-stuffing, botnet probing, and persistence scripting within minutes of exposure. This project converts live telemetry from an Azure-hosted SSH honeypot into an interactive, real-world physical threat dashboard.

Incoming network interactions, credential attempts, command execution, and staged payloads trigger distinct visual lighting states across an array of 10 lighting slots, translating raw security logs into physical intrusion awareness.

---

## Architectural Workflow

```text
       [ Public Internet Scanners / Botnets ]
                         │
                         ▼
        ┌───────────────────────────────────┐
        │             Azure VPS             │
        │                                   │
        │   iptables NAT PREROUTING         │
        │   Port 22/23  ──► Port 2222/2223  │
        │                                   │
        │   Cowrie Container (Docker)       │
        │   Writes JSON Stream ─────────┐   │
        └───────────────────────────────┼───┘
                                        │
                         Tail / Telemetry Stream (SSH Pipe)
                                        │
                                        ▼
        ┌───────────────────────────────────┐
        │       Local Network Bridge        │
        │                                   │
        │   Python Event Processor          │
        │   - Session Slot Allocator (0-9)  │
        │   - MITRE ATT&CK Stage Parser     │
        │   - Asynchronous Strobe & Latch   │
        │                                   │
        │   Direct UDP Control (Port 4003)  │
        └─────────────────┬─────────────────┘
                          │
                          ▼
            [ Physical Govee RGB Array ]
         Slot 1  Slot 2  Slot 3 ... Slot 10
```

---

## Repository Files

| File | Purpose | Description |
| :--- | :--- | :--- |
| [`goveeDaemon.py`] | **Production Multi-Panel Threat Matrix** | Primary daemon. Streams remote Cowrie JSON logs over an encrypted SSH pipe, allocates attacker sessions across 10 physical panel slots, parses MITRE ATT&CK stages, and generates raw 20-byte `ptReal` UDP datagrams with per-panel bitmasks and XOR checksums. Includes asynchronous stroboscopic animations, latching hold phases, auto-reconnect logic, and graceful disconnect cooldowns. |
| [`vpsPipeline.py`] | **Whole-Array / Single-Panel Stream Listener** | Lightweight event processor using Govee's high-level JSON UDP API (`colorwc`). Dispatches whole-fixture color changes responding to login success, commands, file downloads, and TCP/IP proxy events directly over the local network. |
| [`swarmSimulator.py`] | **Multi-Attacker Swarm Simulator** | Multi-threaded penetration and validation tool built with `paramiko`. Spawns up to 10 concurrent bot sessions with staggered entry (domino wave effect) targeting the honeypot on public port 22. Delivers realistic botnet credential pairs and post-exploitation payloads (reconnaissance, persistence, miner drops) while holding sessions open for visual demos and video capture. |
| [`testLightConnection.py`] | **Hardware Diagnostic Utility** | Minimal UDP socket test script. Emits a single `colorwc` datagram to confirm the Govee hardware is powered on, connected to the local Wi-Fi, and responding to LAN control broadcasts on UDP port 4003. |

---

## MITRE ATT&CK Phase & Color Scheme

The threat board maps specific Cowrie telemetry events to MITRE ATT&CK tactics, illuminating corresponding panels in real time:

| Cowrie Event ID | MITRE ATT&CK Tactic | RGB Value | Color Representation | Visual Effect |
| :--- | :--- | :--- | :--- | :--- |
| `cowrie.session.connect` | **Initial Probe / Reconnaissance** (TA0043) | `(0, 140, 255)` | 🟦 **Dim Cyan** | Rapid strobe then solid latch indicating an active TCP handshake. |
| `cowrie.login.success` | **Initial Access / Breach** (TA0001) | `(255, 0, 0)` | 🟥 **Crimson Red** | High-intensity strobe alerting an attacker has compromised credentials. |
| `cowrie.command.input` | **Execution / Scripting** (TA0002) | `(180, 0, 255)` | 🟪 **Deep Purple** | Pulses when an attacker enters interactive shell commands. |
| `cowrie.session.file_download` | **Ingress Tool Transfer** (TA0011) | `(0, 255, 0)` | 🟩 **Toxic Green** | Latches green when malicious binaries or scripts are staged via `curl`/`wget`. |
| `cowrie.direct-tcpip.request` | **Lateral Movement / Pivot** (TA0008) | `(255, 140, 0)` | 🟧 **Warning Amber** | Indicates the attacker is attempting to use the honeypot as an outbound proxy. |
| `cowrie.session.closed` | **Session Termination** | `(0, 0, 0)` | ⬛ **Dark / Off** | Triggers a 14-second cooldown before clearing the panel to dark idle. |

---

## Hardware & Protocol Mechanics

### 1. High-Level JSON UDP (`colorwc`)
Used by `testLightConnection.py` and `vpsPipeline.py`. Sends standard Govee LAN JSON commands over UDP port 4003 to control the entire fixture or light strip uniformly:
```json
{
  "msg": {
    "cmd": "colorwc",
    "data": {
      "color": { "r": 255, "g": 0, "b": 0 },
      "colorTemInKelvin": 0
    }
  }
}
```

### 2. Low-Level Segment UDP (`ptReal`)
Used by `goveeDaemon.py` for per-panel individual targeting across 10 discrete slots. Constructs an uncompressed 20-byte payload containing an operation header, segment index bitmask, RGB values, and an XOR checksum:
- **Header:** `0x33, 0x05, 0x15, 0x01` (ptReal segment command)
- **Color:** `R, G, B, 0x00, 0x00`
- **Panel Bitmask (16-bit):** `mh, ml` specifying the physical segment (Panels 1–10)
- **Padding:** 8 trailing zero-bytes
- **Checksum:** XOR sum of the preceding 19 bytes appended at byte 20
- **Dispatch:** Base64-encoded and sent within a `{"msg": {"cmd": "ptReal", "data": {"command": [b64_str]}}}` datagram.

---

## Project Setup & Installation

### Prerequisites

1. **Hardware:**
   - Govee RGB lighting hardware that supports LAN Control (e.g., Govee Glide Hexa light panels, Wall Light, or LED strips).
   - Local 2.4 GHz Wi-Fi network shared by both your local bridge machine and the Govee device.
2. **Cloud Infrastructure:**
   - Linux Virtual Machine (e.g., Azure VM, AWS EC2, or DigitalOcean Droplet) with a public static IPv4 address.
   - Host management SSH relocated to an alternate port (e.g., `22222`).
   - Standard ports `22` and `23` dedicated to the Cowrie honeypot.
3. **Local Bridge Machine:**
   - Windows, macOS, or Linux running Python 3.8+.
   - OpenSSH client installed with key-based authentication configured to access the VPS.

---

### Step 1: Physical Govee Device Setup

1. Connect your Govee device to your local Wi-Fi network using the **Govee Home** mobile application.
2. In the device settings in the Govee Home app, enable **LAN Control**.
3. Identify your device's local IP address (e.g., from your router's DHCP table or via network scan). Default port is `4003`.

---

### Step 2: Cloud VPS & Cowrie Honeypot Configuration

#### 1. Relocate VPS Host SSH Management Port
To allow Cowrie to listen on standard SSH port 22, move your real administrative SSH daemon to an alternative port:
```bash
# Edit sshd_config
sudo nano /etc/ssh/sshd_config
# Set: Port 22222

# Restart SSH service
sudo systemctl restart ssh
```
> [!IMPORTANT]
> Verify your cloud firewall / Network Security Group (NSG) allows inbound traffic on port `22222` before closing your current SSH session!

#### 2. Deploy Cowrie in Docker
Deploy Cowrie mapped to internal container ports:
```bash
docker run -d \
  --name cowrie \
  -p 2222:2222 \
  -p 2223:2223 \
  -v ~/cowrie/var/log/cowrie:/cowrie/cowrie-git/var/log/cowrie \
  cowrie/cowrie:latest
```

#### 3. Route Public Ports 22 & 23 to Cowrie
Use `iptables` NAT PREROUTING rules to transparently redirect incoming public SSH and Telnet traffic to Cowrie:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
```
Ensure Cowrie output logs are continuously written to `~/cowrie/var/log/cowrie/cowrie.json`.

---

### Step 3: Local Bridge Environment Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/jdkakareka/LightUp-honeypot.git
   cd LightUp-honeypot
   ```

2. **Create and activate a virtual environment (optional but recommended):**
   ```bash
   # Windows
   python -m venv .venv
   .venv\Scripts\activate

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   The daemon and pipeline scripts rely purely on the Python standard library (`socket`, `json`, `subprocess`, `threading`, `base64`). For the swarm attack simulator, install `paramiko`:
   ```bash
   pip install paramiko
   ```

4. **Configure Network and Target Variables:**
   Open [`goveeDaemon.py`] (and [`vpsPipeline.py`]) and adjust the configuration constants:
   ```python
   LIGHT_IP = "192.168.1.100"                             # Local IP of your Govee fixture
   UDP_PORT = 4003                                        # Standard Govee UDP LAN port
   VPS_IP = "198.51.100.1"                                # Public IP of your Azure VPS
   VPS_PORT = "22222"                                     # Host management SSH port
   VPS_USER = "honeypot_admin"                            # SSH username on VPS
   LOG_PATH = "~/cowrie/var/log/cowrie/cowrie.json"       # Path to cowrie.json
   SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")     # Private SSH key for log streaming
   ```

---

## Execution Guide

### 1. Test Hardware Communication
Verify your local machine can transmit datagrams to the Govee lights:
```bash
python testLightConnection.py
```
*Expected Result:* The Govee array illuminates in solid red.

### 2. Start the Production 10-Panel Threat Daemon
Run the multi-panel matrix listener:
```bash
python goveeDaemon.py
```
*Behavior:*
- Establishes a persistent SSH pipeline executing `tail -n 0 -F` against the remote Cowrie log.
- Maps distinct attacker session IDs to slots 1 through 10.
- Strobes and latches individual panels according to attacker actions.
- Automatically clears panels after disconnect cooldowns and reconnects the SSH stream if dropped.

### 3. Alternative: Run Whole-Array Pipeline
If you prefer uniform, single-color lighting alerts across the entire fixture:
```bash
python vpsPipeline.py
```

### 4. Run the Swarm Attack Simulator
To validate the setup or record demonstration footage without waiting for wild internet traffic:
```bash
python swarmSimulator.py
```
*Behavior:*
- Fires 10 concurrent attacker threads staggered by 0.75 seconds.
- Connects to public port 22 on the VPS (hits iptables -> Cowrie).
- Authenticates using common botnet credentials, runs reconnaissance and miner payloads, and holds sessions open for 15 seconds so all 10 panels remain fully illuminated.

---

## AI Acknowledgement

Artificial intelligence assistance was utilized in the development and documentation of this project, specifically for:
- **README Formatting & Architecture Documentation:** Structuring, formatting, and drafting this comprehensive guide, technical tables, and architectural flowcharts for clear presentation.
- **Code Readability & Commenting:** Enhancing inline documentation, adding detailed comments across all Python scripts, clarifying variable naming, and structuring modules for improved readability and long-term maintainability.
- **Technical Debugging & Protocol Analysis:** Assisting with reverse-engineering and framing the low-level Govee `ptReal` 20-byte UDP datagrams (calculating 16-bit panel bitmasks and XOR checksums), resolving thread-safety and session slot allocation edge cases, and refining SSH subprocess stream piping with non-blocking line buffering.
