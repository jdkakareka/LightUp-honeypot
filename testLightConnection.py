import socket
import json

LIGHT_IP = "192.168.1.100"  # Replace with your Govee device's local IP address
UDP_PORT = 4003

msg = {
  "msg": {
    "cmd": "colorwc",
    "data": {
      "color": {"r": 255, "g": 0, "b": 0},
      "colorTemInKelvin": 0
    }
  }
}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.settimeout(4.0)

sock.sendto(json.dumps(msg).encode(), (LIGHT_IP, UDP_PORT))

sock.close()