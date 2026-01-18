import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [target, setTarget] = useState('');
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  // 1. Function to fetch scan history from the Backend
  const fetchHistory = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:5000/api/history');
      setHistory(response.data);
    } catch (error) {
      console.error("Error fetching history:", error);
    }
  };

  // 2. Fetch history when the page first loads
  useEffect(() => {
    fetchHistory();
  }, []);

  // 3. Function to start a new scan
  const handleScan = async (e) => {
    e.preventDefault();
    if (!target) return alert("Please enter a target IP or Domain");

    setLoading(true);
    try {
      await axios.post('http://127.0.0.1:5000/api/scan', { target });
      setTarget('');
      fetchHistory(); // Refresh table after scan
    } catch (error) {
      alert("Scan failed. Check if Backend is running.");
    }
    setLoading(false);
  };

  return (
    <div className="App">
      <header>
        <h1>THREAT-FUSION SOAR</h1>
        <p>Vulnerability Assessment & Automated Reporting</p>
      </header>

      <section className="scan-form">
        <form onSubmit={handleScan}>
          <input 
            type="text" 
            placeholder="Enter Target (e.g., 127.0.0.1)" 
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={loading}
          />
          <button type="submit" disabled={loading}>
            {loading ? 'Scanning...' : 'Launch Scan'}
          </button>
        </form>
      </section>

      <section className="history-section">
        <h2>Scan Activity Log</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Target</th>
              <th>Status</th>
              <th>Time</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody>
            {history.map((scan) => (
              <tr key={scan.id}>
                <td>{scan.id}</td>
                <td>{scan.target}</td>
                <td>
                  <span className={`status-${scan.status.toLowerCase()}`}>
                    {scan.status}
                  </span>
                </td>
                <td>{scan.created_at}</td>
                <td>
                  {scan.status === 'Completed' ? (
                    <a 
                      href={`http://127.0.0.1:5000/api/download/${scan.pdf_path}`} 
                      className="download-link"
                      target="_blank" 
                      rel="noreferrer"
                    >
                      Download PDF
                    </a>
                  ) : '---'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

export default App;