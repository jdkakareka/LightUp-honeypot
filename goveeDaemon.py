import os
import sys
import time
import json
import base64
import socket
import threading
import subprocess

# ==========================================
# 1. HARDWARE & VPS CONFIGURATION (PLACEHOLDERS)
# ==========================================
LIGHT_IP = "192.168.1.100"                                  # Replace with your Govee device's local IP address
UDP_PORT = 4003                                             # Standard Govee LAN control UDP port
PANEL_COUNT = 10                                            # Number of physical panels / segments

VPS_IP = "198.51.100.1"                                     # Replace with your Cloud VPS public IP address
VPS_PORT = "22222"                                          # Replace with your VPS management SSH port (non-standard)
VPS_USER = "honeypot_admin"                                 # Replace with your VPS SSH username
LOG_PATH = "~/cowrie/var/log/cowrie/cowrie.json"            # Replace with path to cowrie.json log stream

# Local path to private SSH key used for telemetry streaming
SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")

# Timing & Cooldown Configuration (in seconds)
STROBE_DURATION = 4.0      # Seconds spent rapidly flashing
POST_EVENT_HOLD = 10.0     # Minimum seconds to keep panel solid after an event
DISCONNECT_DELAY = 14.0    # Seconds to hold panel after attacker exits before clearing

# 16-bit Panel Bitmasks (Panels 1 through 10)
PANEL_MASKS = [
    (0x01, 0x00),
    (0x02, 0x00), 
    (0x04, 0x00), 
    (0x08, 0x00), 
    (0x10, 0x00), 
    (0x20, 0x00), 
    (0x40, 0x00),
    (0x80, 0x00),
    (0x00, 0x01),
    (0x00, 0x02)
]

# MITRE ATT&CK Phase Colors
COLOR_MAP = {
    "cowrie.session.connect": {"r": 0, "g": 140, "b": 255},       # Dim Cyan (Probe/Handshake)
    "cowrie.login.success": {"r": 255, "g": 0, "b": 0},          # Crimson Red (Breach)
    "cowrie.command.input": {"r": 180, "g": 0, "b": 255},        # Deep Purple (Execution)
    "cowrie.session.file_download": {"r": 0, "g": 255, "b": 0},    # Toxic Green (Staged Payload)
    "cowrie.direct-tcpip.request": {"r": 255, "g": 140, "b": 0},  # Warning Amber (Proxy Pivot)
}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
state_lock = threading.Lock()
slots = [None] * PANEL_COUNT
slot_last_seen = [0.0] * PANEL_COUNT


# ==========================================
# 2. RAW PTREAL UDP PACKET DISPATCHER
# ==========================================
def set_single_panel_color(panel_idx, r, g, b):
    """Constructs 20-byte ptReal segment packet and sends via UDP."""
    mh, ml = PANEL_MASKS[panel_idx]
    pkt = bytearray([0x33, 0x05, 0x15, 0x01, r, g, b, 0x00, 0x00, mh, ml] + [0x00] * 8)
    
    checksum = 0
    for b_val in pkt:
        checksum ^= b_val
    pkt.append(checksum)

    b64_cmd = base64.b64encode(pkt).decode("utf-8")
    payload = {
        "msg": {
            "cmd": "ptReal",
            "data": {
                "command": [b64_cmd]
            }
        }
    }
    try:
        sock.sendto(json.dumps(payload).encode("utf-8"), (LIGHT_IP, UDP_PORT))
    except Exception as e:
        print(f"[!] UDP Socket Error: {e}")


# ==========================================
# 3. SESSION SLOT ALLOCATION
# ==========================================
def get_or_create_slot(session_id):
    with state_lock:
        if session_id in slots:
            return slots.index(session_id)
        if None in slots:
            idx = slots.index(None)
            slots[idx] = session_id
            return idx
        # Saturation fallback: wrap around to slot 0
        slots[0] = session_id
        return 0

def release_slot(session_id):
    with state_lock:
        if session_id in slots:
            idx = slots.index(session_id)
            slots[idx] = None
            return idx
    return None


# ==========================================
# 4. PER-PANEL ASYNC ANIMATOR
# ==========================================
def animate_panel(panel_idx, color):
    """
    Strobes the targeted panel, then latches it solid for POST_EVENT_HOLD seconds.
    """
    def _run():
        r, g, b = color["r"], color["g"], color["b"]
        now = time.time()
        slot_last_seen[panel_idx] = now

        # 1. Strobe Phase (Rapid flashes)
        cycles = int(STROBE_DURATION / 0.5)
        for _ in range(cycles):
            if slot_last_seen[panel_idx] > now:
                return
            set_single_panel_color(panel_idx, r, g, b)
            time.sleep(0.25)
            set_single_panel_color(panel_idx, 0, 0, 0)
            time.sleep(0.25)

        # 2. Solid Latch Phase
        set_single_panel_color(panel_idx, r, g, b)

        # Hold solid until POST_EVENT_HOLD seconds have elapsed since the last event
        while time.time() - slot_last_seen[panel_idx] < POST_EVENT_HOLD:
            time.sleep(0.5)
            if slot_last_seen[panel_idx] > now + POST_EVENT_HOLD:
                return

        # 3. Off / Idle (turn off if the session has closed and cleared)
        with state_lock:
            if slots[panel_idx] is None:
                set_single_panel_color(panel_idx, 0, 0, 0)

    threading.Thread(target=_run, daemon=True).start()


# ==========================================
# 5. STREAM PIPELINE WITH AUTH & RECONNECT
# ==========================================
def stream_honeypot():
    ssh_cmd = [
        "ssh",
        "-i", SSH_KEY_PATH,
        "-p", VPS_PORT,
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        f"{VPS_USER}@{VPS_IP}",
        f"tail -n 0 -F {LOG_PATH}"
    ]

    print(f"[*] Spawning SSH pipe: {VPS_USER}@{VPS_IP}:{VPS_PORT}")
    print(f"[*] Identity: {SSH_KEY_PATH}")

    proc = subprocess.Popen(
        ssh_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    print("[+] Telemetry stream active. Monitoring 10 panel slots...\n")

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
            event_id = event.get("eventid")
            session = event.get("session")
            src_ip = event.get("src_ip", "unknown")

            if not session:
                continue

            # Attacker Disconnected: delayed shutdown so lights don't cut off instantly
            if event_id == "cowrie.session.closed":
                def _delayed_clear(sess_id):
                    time.sleep(DISCONNECT_DELAY)
                    freed_slot = release_slot(sess_id)
                    if freed_slot is not None:
                        print(f"[-] Session {sess_id} cooldown expired -> Cleared Panel [{freed_slot + 1}]")
                        set_single_panel_color(freed_slot, 0, 0, 0)

                threading.Thread(target=_delayed_clear, args=(session,), daemon=True).start()

            # Attacker Action: assign panel and trigger strobe
            elif event_id in COLOR_MAP:
                slot_idx = get_or_create_slot(session)
                color = COLOR_MAP[event_id]
                print(f"[!] Panel [{slot_idx + 1}] <-- {event_id:<28} | IP: {src_ip:<15} | Session: {session}")

                if event_id == "cowrie.command.input":
                    print(f"    └── Injected: {event.get('input')}")

                animate_panel(slot_idx, color)

        except json.JSONDecodeError:
            continue

    stderr_output = proc.stderr.read()
    if stderr_output:
        print(f"[!] SSH Stderr: {stderr_output.strip()}")

    proc.poll()


def main():
    if not os.path.exists(SSH_KEY_PATH):
        print(f"[!] Error: Private key not found at {SSH_KEY_PATH}")
        sys.exit(1)

    print("==================================================")
    print("   10-PANEL THREAT MATRIX (HARDWARE PTREAL)       ")
    print(f"   Target Light: {LIGHT_IP}:{UDP_PORT}             ")
    print(f"   Cloud VPS:    {VPS_IP}:{VPS_PORT}               ")
    print("==================================================")

    while True:
        try:
            stream_honeypot()
        except Exception as e:
            print(f"[!] Stream error: {e}")

        print("[*] Reconnecting in 5 seconds...")
        time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Clearing panels and exiting...")
        for i in range(PANEL_COUNT):
            set_single_panel_color(i, 0, 0, 0)
        sys.exit(0)