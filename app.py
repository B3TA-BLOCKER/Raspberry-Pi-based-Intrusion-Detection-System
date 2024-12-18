import tensorflow as tf
import scapy.all as scapy
import numpy as np

# Load the trained model (your model is expected to be saved as 'model.keras')
model = tf.keras.models.load_model('model.keras')  # Adjust the path if needed

# Function to preprocess features from the packet
def preprocess_packet(packet):
    if packet.haslayer(scapy.IP):
        # Extract multiple features to meet the input shape requirement
        features = [
            len(packet),                               # Total packet length
            packet[scapy.IP].ttl,                     # Time to Live (TTL)
            packet[scapy.IP].len,                     # IP packet length
            int(packet[scapy.IP].src.split('.')[0]),  # Source IP (first octet)
            int(packet[scapy.IP].dst.split('.')[0]),  # Destination IP (first octet)
        ]
        
        # Add placeholder zeros to match the expected input shape (78 features)
        while len(features) < 78:
            features.append(0)

        # Convert to a numpy array and reshape to (1, 1, 78)
        features_array = np.array(features, dtype=np.float32).reshape(1, 1, 78)
        return features_array
    return None

# Function to capture packets and detect anomalies
def capture_and_detect(interface="wlan0"):
    print(f"Model loaded successfully.\nStarting packet capture on interface {interface}...")
    
    def packet_callback(packet):
        features = preprocess_packet(packet)
        if features is not None:
            try:
                # Use the model to predict if the packet is normal or anomalous
                prediction = model.predict(features)
                predicted_class = np.argmax(prediction, axis=1)[0]
                
                # Assuming '1' is the label for anomaly, adjust as per your model's output
                if predicted_class == 1:
                    print(f"Anomaly detected! Source IP: {packet[scapy.IP].src} -> Destination IP: {packet[scapy.IP].dst}")
                else:
                    print(f"Normal traffic: Source IP: {packet[scapy.IP].src} -> Destination IP: {packet[scapy.IP].dst}")
            except Exception as e:
                print(f"Error predicting packet: {e}")

    # Start sniffing the network
    scapy.sniff(iface=interface, prn=packet_callback, store=0)

# Correct the name check for script execution
if __name__ == "__main__":
    capture_and_detect(interface="wlan0")  # Use 'wlan0' for wireless network interface
