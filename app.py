import scapy.all as scapy
import tensorflow as tf
from tensorflow.keras.models import load_model
import pandas as pd
import time
import numpy as np

# Load your machine learning model from the same directory
MODEL_PATH = "/model/model.weights.h5"
model = load_model(MODEL_PATH)

# Define a function to extract relevant packet features
def extract_packet_features(packet):
    features = {
        "packet_length": len(packet),
        "protocol": packet.proto if hasattr(packet, 'proto') else 0,
        "src_port": packet.sport if hasattr(packet, 'sport') else 0,
        "dst_port": packet.dport if hasattr(packet, 'dport') else 0,
        "packet_time": time.time()
    }
    return features

# Preprocess extracted features for the Keras model
def preprocess_features(features):
    # Convert features to an array and ensure shape matches the model input
    feature_array = np.array([
        features["packet_length"],
        features["protocol"],
        features["src_port"],
        features["dst_port"],
        features["packet_time"]
    ])
    return feature_array.reshape(1, -1)  # Reshape for model input

# Live traffic analysis function
def analyze_traffic(packet):
    try:
        # Check for IP packets only
        if packet.haslayer(scapy.IP):
            # Extract features
            features = extract_packet_features(packet)
            processed_features = preprocess_features(features)
            
            # Predict using the model
            prediction = model.predict(processed_features)
            
            # Display results
            print(f"\n[+] Packet Captured:")
            print(f"   Source IP: {packet[scapy.IP].src}, Destination IP: {packet[scapy.IP].dst}")
            print(f"   Length: {features['packet_length']}, Protocol: {features['protocol']}")
            print(f"   Model Prediction: {prediction[0][0]:.4f}")
    except Exception as e:
        print(f"[-] Error: {e}")

# Main sniffing function
def start_sniffing(interface):
    print("[+] Starting packet capture and analysis... Press CTRL+C to stop.")
    scapy.sniff(iface=interface, prn=analyze_traffic, store=False)

if __name__ == "__main__":
    network_interface = input("Enter the network interface (e.g., eth0, wlan0): ")
    start_sniffing(network_interface)
