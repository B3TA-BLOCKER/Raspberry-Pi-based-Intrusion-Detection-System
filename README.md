# Raspberry Pi-based Intrusion Detection System  

This project is a **Raspberry Pi-based Intrusion Detection System (IDS)** that utilizes a Long Short-Term Memory (LSTM) neural network to detect network intrusions. The IDS is trained on the **CSE-CIC-IDS 2018** dataset and is capable of identifying malicious activities in a network.  

---

## Table of Contents  
- [Overview](#overview)  
- [Features](#features)  
- [Project Structure](#project-structure)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Role of the Raspberry Pi](#role-of-the-raspberry-pi)  
- [Dataset](#dataset)  
- [License](#license)  

---

## Overview  
Intrusion detection is a critical aspect of cybersecurity, and this project provides a lightweight yet efficient IDS that can be deployed on a Raspberry Pi. By leveraging LSTM-based neural networks, this system detects anomalous patterns in network traffic and classifies them as malicious or benign.  

---

## Features  
- LSTM neural network for anomaly detection.  
- Supports the CSE-CIC-IDS 2018 dataset for training.  
- Lightweight implementation for Raspberry Pi deployment.  
- Simulation of network traffic using `simulate.py`.  
- Easy-to-extend modular architecture.  

---

## Project Structure  
```
Raspberry-Pi-based-Intrusion-Detection-System/
│
├── app.py                         # Main application script (Raspberry Pi)  
├── CSE-CIC-IDS-2018/              # Dataset directory (CSE-CIC-IDS 2018 dataset)  
├── LICENSE                        # License file  
├── model.keras                    # Pre-trained LSTM model file (Raspberry Pi)  
├── Network_Intrusion_Detection_System_Using_LSTM_Neural_Networks.ipynb  
│                                  # Jupyter Notebook for training and evaluation  
├── Project/                       # Pre-configured Python virtual environment  
├── README.md                      # Project documentation  
└── simulate.py                    # Simulation script for generating network traffic (Local device)  
```

---

## Installation  

### For Raspberry Pi  
1. **Clone the Repository**  
   ```bash  
   git clone https://github.com/B3TA-BLOCKER/Raspberry-Pi-based-Intrusion-Detection-System.git 
   cd Raspberry-Pi-based-Intrusion-Detection-System.git 
   ```  

2. **Activate the Pre-configured Virtual Environment**  
   The project comes with a pre-configured Python virtual environment. Activate it using the following command:  
   ```bash  
   source Project/bin/activate  
   ```  

3. **Prepare the Raspberry Pi**  
   Ensure the Raspberry Pi is connected to your network. The `app.py` script and `model.keras` file must be present on the Raspberry Pi.  

4. **Start the IDS**  
   Run the IDS by executing:  
   ```bash  
   python3 app.py  
   ```  

### For Local Device  
1. Clone the repository on your local device:  
   ```bash  
   git clone https://github.com/B3TA-BLOCKER/Raspberry-Pi-based-Intrusion-Detection-System.git 
   cd Raspberry-Pi-based-Intrusion-Detection-System.git 
   ```  

2. Use the `simulate.py` script to generate synthetic network traffic. Ensure the Raspberry Pi is running the IDS (`app.py`) and connected to the same network.

---

## Usage  

### Running the Application on Raspberry Pi  
1. Start the IDS on the Raspberry Pi:  
   ```bash  
   python app.py  
   ```  

### Simulating Network Traffic on Local Device {and make sure to edit the ip address of the rasberry pi in the script!}
Generate synthetic network traffic to test the IDS:  
```bash  
python simulate.py  
```  

### Training the Model  
If you wish to train a new model, use the provided Jupyter notebook:  
```bash  
jupyter notebook Network_Intrusion_Detection_System_Using_LSTM_Neural_Networks.ipynb  
```  

---

## Role of the Raspberry Pi  
The Raspberry Pi serves as the **deployment platform** for the Intrusion Detection System. Its role includes:  
1. **Processing Network Traffic:**  
   The Raspberry Pi monitors and processes incoming network traffic for intrusion detection.  

2. **Lightweight Deployment:**  
   The Raspberry Pi’s low power consumption and compact size make it ideal for continuous IDS deployment in small networks.  

3. **Running the IDS Model:**  
   The `app.py` script runs the pre-trained LSTM model (`model.keras`) on the Raspberry Pi to classify traffic as benign or malicious.  

4. **Real-Time Detection:**  
   By deploying the IDS on the Raspberry Pi, network traffic is analyzed in real-time for immediate detection of malicious activities.  

---

## Importance of Network Simulation  
To test and evaluate the IDS, the `simulate.py` script is used to simulate network traffic from a local device. This ensures that:  
1. **Traffic Diversity:**  
   Simulated traffic includes both benign and malicious samples to test the accuracy of the IDS.  

2. **Evaluation of the Model:**  
   It allows thorough evaluation of the IDS performance without requiring actual malicious activities.  

3. **Seamless Testing:**  
   By simulating network traffic from a local device, developers can test the IDS remotely without affecting live networks.  

---

## Dataset  

This project uses the **CSE-CIC-IDS 2018** dataset, which is widely used for intrusion detection system training and evaluation. It contains a diverse set of network traffic samples labeled as benign or malicious. For more information on the dataset, visit [CSE-CIC-IDS 2018 Dataset](https://www.unb.ca/cic/datasets/ids-2018.html).  

---

## License  

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.  

---

## Contribution  

Contributions are welcome! If you'd like to contribute, please fork the repository, make your changes, and submit a pull request.  

---

## Contact  

For any queries or feedback, feel free to contact:  
- **Hassaan Ali Bukhari**  
- Email: hassaanalibukhari@gmail.com
- GitHub: [b3ta-blocker](https://github.com/b3ta-blocker)  


