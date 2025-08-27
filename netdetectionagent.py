from scapy.all import sniff, IP, TCP
import pandas as pd
from datetime import datetime
import time
import os
from river import anomaly

# Anomaly Model
model = anomaly.HalfSpaceTrees(seed=42)
THREAT_SCORE_THRESHOLD = 0.75

anomaly_log = []

def process_packet(packet):
    if IP in packet and TCP in packet:
        pkt = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'protocol': 'TCP',
            'packet_len': len(packet),
            'timestamp_unix': time.time(),
            'total_bytes': len(packet)
        }

        features = {'packet_len': pkt['packet_len']}
        score = model.score_one(features)
        model.learn_one(features)

        pkt['score'] = score
        pkt['anomaly'] = 1 if score > THREAT_SCORE_THRESHOLD else 0

        if pkt['anomaly']:
            print(f"[!] Anomaly detected: {pkt}")
            anomaly_log.append(pkt)

print("[*] Anomalyze.io Agent is running... Listening for packets...")

while True:
    sniff(prn=process_packet, store=False, timeout=10)

    if anomaly_log:
        df = pd.DataFrame(anomaly_log)
        file_exists = os.path.exists("anomaly_log.csv")
        df.to_csv("anomaly_log.csv", mode='a', header=not file_exists, index=False)
        print(f"[+] {len(df)} anomalies logged.")
        anomaly_log.clear()
    else:
        print("[✓] No anomalies in this window.")

    time.sleep(5)
