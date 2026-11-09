import os
import sys
import json
import socket
import subprocess

# --- Network & Target Configuration (Placeholders) ---
LIGHT_IP = "192.168.1.100"                                  # Replace with your Govee device's local IP address
UDP_PORT = 4003                                             # Standard Govee LAN control UDP port

VPS_IP = "198.51.100.1"                                     # Replace with your Cloud VPS public IP address
VPS_PORT = "22222"                                          # Replace with your VPS management SSH port (non-standard)
VPS_USER = "honeypot_admin"                                 # Replace with your VPS SSH username
LOG_PATH = "~/cowrie/var/log/cowrie/cowrie.json"            # Replace with path to cowrie.json log stream

# Local path to private SSH key used for telemetry streaming
SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")

# --- Color Scheme Definition ---
COLOR_MAP = {
    "cowrie.login.success": {"r": 255, "g": 0, "b": 0},       # Crimson Red
    "cowrie.command.input": {"r": 180, "g": 0, "b": 255},     # Deep Purple
    "cowrie.session.file_download": {"r": 0, "g": 255, "b": 0}, # Toxic Green
    "cowrie.direct-tcpip.request": {"r": 255, "g": 140, "b": 0}, # Amber
    "cowrie.session.closed": {"r": 0, "g": 0, "b": 0}        # Dark / Idle
}

# Initialize UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def set_panel_color(r, g, b):
    """Sends raw Govee LAN control datagram over UDP."""
    payload = {
        "msg": {
            "cmd": "colorwc",
            "data": {
                "color": {"r": r, "g": g, "b": b},
                "colorTemInKelvin": 0
            }
        }
    }
    sock.sendto(json.dumps(payload).encode("utf-8"), (LIGHT_IP, UDP_PORT))

def build_ssh_command():
    return [
        "ssh",
        "-i", SSH_KEY_PATH,
        "-p", VPS_PORT,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        f"{VPS_USER}@{VPS_IP}",
        f"tail -n 0 -F {LOG_PATH}"
    ]

def start_stream():
    cmd = build_ssh_command()
    print(f"[*] Starting SSH pipe to {VPS_USER}@{VPS_IP}:{VPS_PORT}...")
    print(f"[*] Using identity file: {SSH_KEY_PATH}")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    print("[*] Stream active. Listening for honeypot intrusions...\n")

    try:
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
                event_id = event.get("eventid")
                session = event.get("session", "unknown")
                src_ip = event.get("src_ip", "unknown")

                if event_id in COLOR_MAP:
                    color = COLOR_MAP[event_id]
                    print(f"[!] Event: {event_id:<28} | IP: {src_ip:<15} | Session: {session}")
                    
                    # Highlight command execution detail in console
                    if event_id == "cowrie.command.input":
                        print(f"    └── Command: {event.get('input')}")

                    set_panel_color(color["r"], color["g"], color["b"])

            except json.JSONDecodeError:
                continue

    except KeyboardInterrupt:
        print("\n[*] Stopping threat board listener. Resetting light state...")
        set_panel_color(0, 0, 0)
        process.terminate()
        sys.exit(0)

if __name__ == "__main__":
    start_stream()