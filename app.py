import tensorflow as tf
import scapy.all as scapy
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import pickle
import os

# Load the trained model (your model is expected to be saved as 'best_model.h5' or 'model.keras')
model = tf.keras.models.load_model('best_model.h5')  # Change to 'model.keras' if that is the file name

# Load the scaler used during training
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

# Function to preprocess features just like during training
def preprocess_packet(packet):
    # Extract basic features like payload length, etc.
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        payload_len = len(packet.payload)
        
        # You can add more features based on your model's training
        features = [payload_len]  # Add more features here if required by your model
        
        # Normalize the features
        features = scaler.transform([features])

        # Reshape for LSTM input (1 timestep, number of features)
        features_reshaped = features.reshape((features.shape[0], 1, features.shape[1]))

        return features_reshaped
    return None

# Function to capture packets and detect anomalies
def capture_and_detect(interface="eth0"):
    print(f"Starting packet capture on interface {interface}...")
    
    def packet_callback(packet):
        features = preprocess_packet(packet)
        if features is not None:
            # Use the LSTM model to predict
            prediction = model.predict(features)
            predicted_class = np.argmax(prediction, axis=1)[0]
            
            # Assuming '1' is the label for anomaly, adjust as per your model's output
            if predicted_class == 1:
                print(f"Anomaly detected! Source IP: {packet[scapy.IP].src} -> Destination IP: {packet[scapy.IP].dst}")
            else:
                print(f"Normal traffic: Source IP: {packet[scapy.IP].src} -> Destination IP: {packet[scapy.IP].dst}")
    
    # Start sniffing the network
    scapy.sniff(iface=interface, prn=packet_callback, store=0)

# Start sniffing (use the correct network interface name, e.g., 'wlp2s0' for Wi-Fi)
if __name__ == "__main__":
    capture_and_detect(interface="eth0")  # Change to 'wlp2s0' or your actual interface name
