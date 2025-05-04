import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import subprocess
import logging
from datetime import datetime
import threading
import signal
import sys

# Configure logging
logging.basicConfig(
    filename='firewall.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Firewall rules (example: block specific IPs and ports)
FIREWALL_RULES = {
    'blocked_ips': ['192.168.10.1', '10.0.0.50'],  # Example IPs to block
    'blocked_ports': [23, 445],  # Example ports (Telnet, SMB)
    'allowed_protocols': ['TCP', 'UDP', 'ICMP']  # Allowed protocols
}

# Suspicious activity thresholds
MAX_CONNECTIONS_PER_IP = 100  # Max connections per IP in a time window
CONNECTION_WINDOW = 60  # Time window in seconds

# Track connections per IP
connection_tracker = {}

def setup_iptables():
    """Initialize iptables rules to drop packets from blocked IPs and ports."""
    try:
        # Flush existing rules
        subprocess.run(['iptables', '-F'], check=True)
        
        # Block specific IPs
        for ip in FIREWALL_RULES['blocked_ips']:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            logging.info(f"Blocked IP: {ip}")
        
        # Block specific ports
        for port in FIREWALL_RULES['blocked_ports']:
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'], check=True)
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP'], check=True)
            logging.info(f"Blocked port: {port}")
        
        # Allow specific protocols
        for proto in FIREWALL_RULES['allowed_protocols']:
            subprocess.run(['iptables', '-A', 'INPUT', '-p', proto.lower(), '-j', 'ACCEPT'], check=True)
            logging.info(f"Allowed protocol: {proto}")
        
        # Default policy: drop all other incoming packets
        subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], check=True)
        logging.info("iptables rules initialized")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set up iptables: {e}")
        sys.exit(1)

def track_connections(src_ip):
    """Track connection attempts to detect potential flooding."""
    current_time = datetime.now().timestamp()
    if src_ip not in connection_tracker:
        connection_tracker[src_ip] = []
    
    # Add current connection timestamp
    connection_tracker[src_ip].append(current_time)
    
    # Remove old connections outside the time window
    connection_tracker[src_ip] = [t for t in connection_tracker[src_ip] if current_time - t < CONNECTION_WINDOW]
    
    # Check for suspicious activity
    if len(connection_tracker[src_ip]) > MAX_CONNECTIONS_PER_IP:
        logging.warning(f"Suspicious activity detected from {src_ip}: {len(connection_tracker[src_ip])} connections")
        block_ip(src_ip)

def block_ip(ip):
    """Dynamically block an IP using iptables."""
    if ip not in FIREWALL_RULES['blocked_ips']:
        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            FIREWALL_RULES['blocked_ips'].append(ip)
            logging.info(f"Dynamically blocked IP: {ip} due to suspicious activity")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to block IP {ip}: {e}")

def packet_callback(packet):
    """Process each captured packet."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        proto = packet[IP].proto
        proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, 'Unknown')
        
        # Log packet details
        logging.info(f"Packet from {src_ip}, Protocol: {proto_name}")
        
        # Track connections for flood detection
        track_connections(src_ip)
        
        # Check if packet matches blocked rules
        if src_ip in FIREWALL_RULES['blocked_ips']:
            logging.warning(f"Dropped packet from blocked IP: {src_ip}")
            return
        
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            if dport in FIREWALL_RULES['blocked_ports']:
                logging.warning(f"Dropped packet to blocked port: {dport}")
                return
            
            # Basic intrusion detection: detect port scanning (simplified)
            if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # SYN packet
                logging.info(f"SYN packet detected from {src_ip} to port {dport}")
                # Could add logic to detect rapid SYN packets indicating a scan
        
        # Allow packet if it matches allowed protocols
        if proto_name in FIREWALL_RULES['allowed_protocols']:
            logging.info(f"Allowed packet from {src_ip}, Protocol: {proto_name}")
        else:
            logging.warning(f"Dropped packet with unallowed protocol: {proto_name}")

def sniff_packets():
    """Start sniffing packets."""
    try:
        logging.info("Starting packet sniffing...")
        scapy.sniff(prn=packet_callback, store=False, filter="ip")
    except Exception as e:
        logging.error(f"Error in packet sniffing: {e}")
        sys.exit(1)

def signal_handler(sig, frame):
    """Handle graceful shutdown."""
    logging.info("Shutting down firewall...")
    subprocess.run(['iptables', '-F'], check=True)  # Clear iptables rules
    subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)  # Reset policy
    sys.exit(0)

def main():
    """Main function to run the firewall."""
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Setup iptables rules
    setup_iptables()
    
    # Start packet sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True
    sniff_thread.start()
    
    # Keep the main thread running
    try:
        while True:
            pass
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    if sys.platform != "linux":
        print("This script requires a Linux environment with iptables.")
        sys.exit(1)
    if os.geteuid() != 0:
        print("This script requires root privileges. Run with sudo.")
        sys.exit(1)
    main()