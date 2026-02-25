import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [target, setTarget] = useState('');
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [view, setView] = useState('dashboard'); 
  const [verificationResult, setVerificationResult] = useState(null); 

  // --- 🚀 FULLY DYNAMIC RISK ANALYTICS ---
  
  const totalScans = history.length;
  const highRiskScans = history.filter(scan => scan.risk_level === 'HIGH').length;
  const completedScans = history.filter(scan => scan.status === 'Completed').length;

  const uptimePercentage = totalScans > 0 
    ? ((completedScans / totalScans) * 100).toFixed(1) 
    : "100";

  // --- 🧠 DYNAMIC THREAT LOGIC (Majority + Single-Scan Handling) ---
  const getDominantThreat = () => {
    if (completedScans === 0) return "None Detected";

    // 1. Calculate the exact counts for each risk level
    const counts = history.reduce((acc, scan) => {
      if (scan.status === 'Completed') {
        const risk = scan.risk_level || "LOW";
        acc[risk] = (acc[risk] || 0) + 1;
      }
      return acc;
    }, {});

    const h = counts["HIGH"] || 0;
    const m = counts["MEDIUM"] || 0;
    const l = counts["LOW"] || 0;

    // 2. SINGLE-SCAN SCENARIO: If it's the only scan, just show its specific risk
    if (completedScans === 1) {
      const lastScan = history.find(scan => scan.status === 'Completed');
      const lastRisk = lastScan ? lastScan.risk_level : "LOW";
      
      if (lastRisk === "HIGH") return "Critical Vulnerabilities";
      if (lastRisk === "MEDIUM") return "Medium Risk Config";
      return "Low Risk Issues";
    }

    // 3. ABSOLUTE MAJORITY RULE: For 2+ scans, the most repeated risk wins
    if (m > h && m > l) return "Medium Risk Config";
    if (h > m && h > l) return "Critical Vulnerabilities";
    if (l > h && l > m) return "Low Risk Issues";

    // 4. TIE-BREAKER: If frequencies are exactly equal, prioritize the most dangerous
    if (h > 0 && h >= m && h >= l) return "Critical Vulnerabilities";
    if (m > 0 && m >= l) return "Medium Risk Config";
    
    return "Low Risk Issues";
  };

  const topThreat = getDominantThreat();

  const fetchHistory = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:5000/api/history');
      setHistory(response.data);
    } catch (error) {
      console.error("Error fetching history:", error);
    }
  };

  const verifyIntegrity = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const fileHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    const match = history.find(scan => scan.file_hash === fileHash);

    if (match) {
      setVerificationResult({ 
        status: 'success', 
        text: `✅ AUTHENTICITY VERIFIED: This report for ${match.target} matches our secure database records.` 
      });
    } else {
      setVerificationResult({ 
        status: 'error', 
        text: '❌ TAMPERING DETECTED: This file does not match any digital fingerprint in our database!' 
      });
    }
  };

  const clearHistory = async () => {
    if(!window.confirm("⚠️ Are you sure? This will permanently delete all scan logs.")) return;
    try {
      await axios.delete('http://127.0.0.1:5000/api/clear_history');
      setHistory([]); 
      setVerificationResult(null);
      alert("History Cleared!");
    } catch (error) {
      alert("Failed to clear history");
    }
  };

  useEffect(() => {
    fetchHistory();
    const intervalId = setInterval(fetchHistory, 5000);
    return () => clearInterval(intervalId);
  }, []);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!target) return alert("Please enter a target IP or Domain");
    setLoading(true);
    try {
      await axios.post('http://127.0.0.1:5000/api/scan', { target });
      setTarget('');
      fetchHistory();
      setView('dashboard'); 
    } catch (error) {
      alert("Scan failed. Check Backend.");
    }
    setLoading(false);
  };

  const displayedHistory = view === 'dashboard' ? history.slice(0, 5) : history;

  return (
    <div className="App">
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem 2rem' }}>
        <div>
          <h1>THREAT-FUSION SOAR</h1>
          <p style={{ margin: 0, opacity: 0.8 }}>Vulnerability Assessment & Automated Reporting</p>
        </div>
        <nav>
          <button onClick={() => setView('dashboard')} className={view === 'dashboard' ? 'nav-active' : ''} style={{ marginRight: '10px' }}>🏠 Dashboard</button>
          <button onClick={() => setView('history')} className={view === 'history' ? 'nav-active' : ''}>📜 Full History</button>
        </nav>
      </header>

      <main>
        <section className="analytics-dashboard" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '30px', padding: '0 2rem' }}>
          <div className="stat-card" style={{ background: '#1a1a1a', padding: '20px', borderRadius: '10px', borderLeft: '5px solid #61dafb' }}>
            <h4 style={{ margin: 0, opacity: 0.7, fontSize: '0.8rem' }}>TOTAL ASSESSMENTS</h4>
            <h2 style={{ margin: '10px 0 0 0', fontSize: '2rem' }}>{totalScans}</h2>
          </div>
          <div className="stat-card" style={{ background: '#1a1a1a', padding: '20px', borderRadius: '10px', borderLeft: '5px solid #e74c3c' }}>
            <h4 style={{ margin: 0, opacity: 0.7, fontSize: '0.8rem' }}>HIGH RISK DETECTED</h4>
            <h2 style={{ margin: '10px 0 0 0', fontSize: '2rem', color: '#e74c3c' }}>{highRiskScans}</h2>
          </div>
          <div className="stat-card" style={{ background: '#1a1a1a', padding: '20px', borderRadius: '10px', borderLeft: '5px solid #f1c40f' }}>
            <h4 style={{ margin: 0, opacity: 0.7, fontSize: '0.8rem' }}>NODE AVAILABILITY</h4>
            <h2 style={{ margin: '10px 0 0 0', fontSize: '2rem', color: '#f1c40f' }}>{uptimePercentage}%</h2>
          </div>
          <div className="stat-card" style={{ background: '#1a1a1a', padding: '20px', borderRadius: '10px', borderLeft: '5px solid #2ecc71' }}>
            <h4 style={{ margin: 0, opacity: 0.7, fontSize: '0.8rem' }}>DOMINANT THREAT</h4>
            <h2 style={{ margin: '10px 0 0 0', fontSize: '1.2rem', color: '#2ecc71' }}>{topThreat}</h2>
          </div>
        </section>

        {view === 'dashboard' && (
          <section className="scan-form">
            <h2>🚀 Launch New Assessment</h2>
            <form onSubmit={handleScan}>
              <input type="text" placeholder="Enter Target (e.g., scanme.nmap.org)" value={target} onChange={(e) => setTarget(e.target.value)} disabled={loading} />
              <button type="submit" disabled={loading}>{loading ? 'Initializing Scanner...' : 'Launch Scan'}</button>
            </form>
          </section>
        )}

        <section className="history-section">
          <section className="verify-tool" style={{ marginBottom: '30px', padding: '20px', border: '1px dashed #444', borderRadius: '12px', textAlign: 'center', backgroundColor: 'rgba(255,255,255,0.03)' }}>
            <h3 style={{ marginTop: 0 }}>🛡️ Report Integrity Verifier</h3>
            <p style={{ fontSize: '0.9rem', opacity: 0.7 }}>Upload a PDF report to verify its digital fingerprint against the secure SOAR database.</p>
            <input type="file" accept=".pdf" onChange={verifyIntegrity} style={{ color: '#aaa', margin: '10px 0' }} />
            {verificationResult && (
              <div style={{ marginTop: '15px', padding: '12px', borderRadius: '8px', backgroundColor: verificationResult.status === 'success' ? '#1b4721' : '#471b1b', color: 'white', fontWeight: 'bold', border: `1px solid ${verificationResult.status === 'success' ? '#2ecc71' : '#e74c3c'}` }}>
                {verificationResult.text}
              </div>
            )}
          </section>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2>{view === 'dashboard' ? 'Recent Activity (Last 5)' : 'Full Audit Logs'}</h2>
            {view === 'history' && history.length > 0 && (
              <button onClick={clearHistory} style={{ backgroundColor: '#dc3545', fontSize: '0.9rem', padding: '8px 15px' }}>🗑️ Clear Logs</button>
            )}
          </div>

          <table>
            <thead>
              <tr><th>ID</th><th>Target</th><th>Status</th><th>Time</th><th>Integrity Hash (SHA-256)</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {displayedHistory.length === 0 ? (
                <tr><td colSpan="6" style={{ textAlign: 'center', padding: '20px' }}>No scans found. Launch a scan to begin.</td></tr>
              ) : (
                displayedHistory.map((scan) => (
                  <tr key={scan.id}>
                    <td>{scan.id}</td><td>{scan.target}</td>
                    <td><span className={`status-${scan.status.toLowerCase()}`}>{scan.status}</span></td>
                    <td>{scan.created_at}</td>
                    <td style={{ fontSize: '11px', fontFamily: 'monospace', color: '#888' }}>
                      {scan.file_hash ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <span title={scan.file_hash}>{scan.file_hash.substring(0, 8)}...{scan.file_hash.substring(56)}</span>
                          <button onClick={() => alert(`Full Integrity Hash:\n${scan.file_hash}`)} style={{ padding: '2px 5px', fontSize: '9px', background: '#444', border: '1px solid #666', cursor: 'pointer' }}>View</button>
                        </div>
                      ) : (<span style={{ opacity: 0.5 }}>Pending...</span>)}
                    </td>
                    <td>
                      {scan.status === 'Completed' ? (
                        <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                          <a href={`http://127.0.0.1:5000/api/download/${scan.pdf_path}`} className="download-link" target="_blank" rel="noreferrer">📄 Report</a>
                          <a href={`http://127.0.0.1:5000/api/download/visual_report_${scan.id}.pdf`} className="download-link" style={{ backgroundColor: '#28a745', borderColor: '#28a745' }} target="_blank" rel="noreferrer">📊 Visuals</a>
                        </div>
                      ) : '---'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>

          {view === 'dashboard' && history.length > 5 && (
            <div style={{ textAlign: 'center', marginTop: '15px' }}>
              <button onClick={() => setView('history')} style={{ background: 'none', color: '#61dafb', border: '1px solid #61dafb', padding: '8px 20px', cursor: 'pointer' }}>View All Scans ({history.length}) →</button>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;