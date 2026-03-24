import time
import random
import logging

# Configure logging to track data collection progress
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class V7CommandRunner:
    """
    A class to simulate realistic C2 traffic by executing 
    system commands via the Invisible Tunnel (V7) protocol.
    """
    
    def __init__(self, command_list):
        """
        Initialize the runner with a list of 300+ commands.
        """
        self.commands = command_list
        self.total_sent = 0

    def start_session(self, rounds=1):
        """
        Iterates through commands with realistic timing to 
        generate a large-scale capture dataset.
        """
        logging.info(f"Starting Data Collection: {rounds} rounds.")
        
        for r in range(rounds):
            # Shuffling prevents pattern-based detection by simple IDSs
            random.shuffle(self.commands)
            logging.info(f"--- Round {r+1} Initialized ---")
            
            for cmd in self.commands:
                self._send_payload(cmd)
                
                # Jitter: Wait 3-5 seconds (realistic human/malware behavior)
                wait_time = random.uniform(3, 5)
                time.sleep(wait_time)
                
        logging.info(f"Session Complete. Total packets sent: {self.total_sent}")

    def _send_payload(self, cmd):
        """
        Placeholder for your Scapy V7 injection logic.
        """
        # Here you will call your: send_v7_packet(cmd)
        logging.info(f"Transmitting Command: {cmd}")
        self.total_sent += 1