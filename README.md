# 🛡️ Threat-Fusion SOAR
**Automated Vulnerability Assessment & Reporting Engine**

## 🚀 Overview
Threat-Fusion SOAR is a comprehensive security tool designed to automate vulnerability detection. It integrates **Nmap (Network Scanning)** and **Nikto (Web Scanning)** into a unified dashboard with real-time PDF reporting and Visual Analytics.

## ⚙️ Prerequisites (READ FIRST)
Since this tool relies on Linux-native scanners, **Windows users must use WSL (Windows Subsystem for Linux)**.

### 1. System Requirements
* **OS:** Ubuntu (via WSL on Windows) or Native Linux/macOS.
* **Python:** v3.8+
* **Node.js:** v14+

### 2. Install External Tools (Crucial!)
You must install the actual scanner software inside your Ubuntu terminal before running the python code:
```bash
sudo apt update
sudo apt install nmap nikto -y

📦 Installation Guide
Step 1: Clone the Repository
Bash
git clone [https://github.com/05nehaha/Threat-Fusion-SOAR.git](https://github.com/05nehaha/Threat-Fusion-SOAR.git)
cd Threat-Fusion-SOAR
Step 2: Backend Setup (Python)
Open a terminal in the project root:

Bash
cd backend
# Install Python dependencies
pip install -r requirements.txt

# Run the Server
python3 app.py
You should see: Running on http://127.0.0.1:5000

Step 3: Frontend Setup (React)
Open a new terminal window:

Bash
cd frontend/my-app
# Install Node dependencies
npm install

# Start the Dashboard
npm start
The app will open at http://localhost:3000

🛠️ Usage
Dashboard: Navigate to the "Dashboard" tab to see the scan form.

Launch Scan: Enter a target (e.g., scanme.nmap.org) and click Launch.

View Results: Wait for status "Completed", then download the PDF Report or view Visual Analytics.

History: Use the "Full History" tab to view past logs or clear the database.

⚠️ Troubleshooting
"No Web Server Found": Ensure you are scanning a target visible to WSL. Try scanning scanme.nmap.org.

Database Error: If scans.db causes issues, simply delete the file. The backend will recreate a fresh one automatically on startup.