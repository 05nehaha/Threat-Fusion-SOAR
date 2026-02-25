
# Threat-Fusion SOAR

Automated Vulnerability Scanner & Reporting Tool.

This project performs automated vulnerability scanning, CVE mapping, CVSS scoring, and generates detailed PDF reports using NVD API integration.

---

## Features

- Automated vulnerability scanning
- CVE extraction and mapping
- CVSS-based severity scoring
- PDF and visual report generation
- Backend (Flask) + Frontend (React)
- Docker support

---

## Tech Stack

Backend:
- Python
- Flask
- SQLite
- NVD API

Frontend:
- React.js
- Node.js

---

## Prerequisites

Make sure you have installed:

- Python 3.10+
- Node.js (v16+ recommended)
- Git

---

## Setup Instructions

### 1. Clone the Repository

```

git clone [https://github.com/05nehaha/Threat-Fusion-SOAR.git](https://github.com/05nehaha/Threat-Fusion-SOAR.git)
cd Threat-Fusion-SOAR

```

---

### 2. Setup Environment Variables

Create a `.env` file in the root directory:

```

cp .env.example .env

```

Open `.env` and add your NVD API key:

```

NVD_API_KEY=your_actual_key_here

```

---

### 3. Setup Backend

```

python -m venv venv
source venv/bin/activate   # On Windows use: venv\Scripts\activate

pip install -r requirements.txt
python backend/app.py

```

Backend will run on:
```

[http://localhost:5000](http://localhost:5000)

```

---

### 4. Setup Frontend

Open a new terminal:

```

cd frontend/my-app
npm install
npm start

```

Frontend will run on:
```

[http://localhost:3000](http://localhost:3000)

```

---

## Project Structure

```

backend/
frontend/
.env.example
Dockerfile
requirements.txt

```
⚙️ Platform Notes

If using:

WSL / Linux / Mac:

source venv/bin/activate



🚨 ALSO ADD THIS (To Avoid Most Common Error)

Very important for Node:

Add this under Frontend section:

If you get dependency issues, run:

npm install --legacy-peer-deps