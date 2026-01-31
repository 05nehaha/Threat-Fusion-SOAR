import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [target, setTarget] = useState('');
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [view, setView] = useState('dashboard'); // 'dashboard' or 'history'

  // Fetch History
  const fetchHistory = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:5000/api/history');
      setHistory(response.data);
    } catch (error) {
      console.error("Error fetching history:", error);
    }
  };

  // Clear History Function
  const clearHistory = async () => {
    if(!window.confirm("⚠️ Are you sure? This will permanently delete all scan logs.")) return;
    
    try {
      await axios.delete('http://127.0.0.1:5000/api/clear_history');
      setHistory([]); // Clear the UI immediately
      alert("History Cleared!");
    } catch (error) {
      alert("Failed to clear history");
    }
  };

  // Polling (Auto-Refresh)
  useEffect(() => {
    fetchHistory();
    const intervalId = setInterval(fetchHistory, 5000);
    return () => clearInterval(intervalId);
  }, []);

  // Handle Scan
  const handleScan = async (e) => {
    e.preventDefault();
    if (!target) return alert("Please enter a target IP or Domain");
    setLoading(true);
    try {
      await axios.post('http://127.0.0.1:5000/api/scan', { target });
      setTarget('');
      fetchHistory();
      setView('dashboard'); // Switch to dashboard to see the running scan
    } catch (error) {
      alert("Scan failed. Check Backend.");
    }
    setLoading(false);
  };

  // Logic: Show only 5 items in Dashboard, or ALL items in History
  const displayedHistory = view === 'dashboard' ? history.slice(0, 5) : history;

  return (
    <div className="App">
      {/* 1. Header Navigation */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem 2rem' }}>
        <div>
          <h1>THREAT-FUSION SOAR</h1>
          <p style={{ margin: 0, opacity: 0.8 }}>Vulnerability Assessment & Automated Reporting</p>
        </div>
        <nav>
          <button 
            onClick={() => setView('dashboard')} 
            className={view === 'dashboard' ? 'nav-active' : ''}
            style={{ marginRight: '10px' }}
          >
            🏠 Dashboard
          </button>
          <button 
            onClick={() => setView('history')} 
            className={view === 'history' ? 'nav-active' : ''}
          >
            📜 Full History
          </button>
        </nav>
      </header>

      {/* 2. Main Content Area */}
      <main>
        {/* VIEW: DASHBOARD (Scan Form) */}
        {view === 'dashboard' && (
          <section className="scan-form">
            <h2>🚀 Launch New Assessment</h2>
            <form onSubmit={handleScan}>
              <input 
                type="text" 
                placeholder="Enter Target (e.g., scanme.nmap.org)" 
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={loading}
              />
              <button type="submit" disabled={loading}>
                {loading ? 'Initializing Scanner...' : 'Launch Scan'}
              </button>
            </form>
          </section>
        )}

        {/* VIEW: TABLE (Shared) */}
        <section className="history-section">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2>
              {view === 'dashboard' ? 'Recent Activity (Last 5)' : 'Full Audit Logs'}
            </h2>
            
            {/* Clear Button (Only in History View) */}
            {view === 'history' && history.length > 0 && (
              <button 
                onClick={clearHistory}
                style={{ backgroundColor: '#dc3545', fontSize: '0.9rem', padding: '8px 15px' }}
              >
                🗑️ Clear Logs
              </button>
            )}
          </div>

          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Target</th>
                <th>Status</th>
                <th>Time</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {displayedHistory.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '20px' }}>
                    No scans found. Launch a scan to begin.
                  </td>
                </tr>
              ) : (
                displayedHistory.map((scan) => (
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
                        <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                          <a 
                            href={`http://127.0.0.1:5000/api/download/${scan.pdf_path}`} 
                            className="download-link"
                            target="_blank" 
                            rel="noreferrer"
                          >
                            📄 Report
                          </a>
                          <a 
                            href={`http://127.0.0.1:5000/api/download/visual_report_${scan.id}.pdf`} 
                            className="download-link"
                            style={{ backgroundColor: '#28a745', borderColor: '#28a745' }}
                            target="_blank" 
                            rel="noreferrer"
                          >
                            📊 Visuals
                          </a>
                        </div>
                      ) : '---'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>

          {/* "View More" Link on Dashboard if there are more than 5 scans */}
          {view === 'dashboard' && history.length > 5 && (
            <div style={{ textAlign: 'center', marginTop: '15px' }}>
              <button 
                onClick={() => setView('history')}
                style={{ background: 'none', color: '#61dafb', border: '1px solid #61dafb', padding: '8px 20px', cursor: 'pointer' }}
              >
                View All Scans ({history.length}) →
              </button>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;