import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
    const [target, setTarget] = useState('');
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(false);
    const [view, setView] = useState('dashboard');
    const [verificationResult, setVerificationResult] = useState(null);

    const API_BASE_URL = 'http://127.0.0.1:5000/api';
    const apiUrl = (path) => `${API_BASE_URL}${path}`;

    // --- 🚀 FULLY DYNAMIC RISK ANALYTICS ---
    const totalScans = history.length;
    const highRiskScans = history.filter(scan => scan.risk_level === 'HIGH' || scan.risk_level === 'CRITICAL').length;
    const completedScans = history.filter(scan => scan.status === 'Completed').length;
    const uptimePercentage = totalScans > 0 ? ((completedScans / totalScans) * 100).toFixed(1) : "100";

    // --- 🧠 ENHANCED THREAT LOGIC ---
    const getDominantThreat = () => {
        if (completedScans === 0) return "None Detected";
        const counts = history.reduce((acc, scan) => {
            if (scan.status === 'Completed') {
                const risk = scan.risk_level || "LOW";
                acc[risk] = (acc[risk] || 0) + 1;
            }
            return acc;
        }, {});

        const c = counts["CRITICAL"] || 0;
        const h = counts["HIGH"] || 0;
        const m = counts["MEDIUM"] || 0;

        if (c > 0) return "Critical Vulnerabilities";
        if (h > 0) return "High Risk Detected";
        if (m > 0) return "Medium Risk Config";
        return "Low Risk Issues";
    };

    const topThreat = getDominantThreat();

    const fetchHistory = async () => {
        try {
            const response = await axios.get(apiUrl('/history'));
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
        if (!window.confirm("⚠️ Are you sure? This will permanently delete all scan logs.")) return;
        try {
            await axios.delete(apiUrl('/clear_history'));
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
            await axios.post(apiUrl('/scan'), { target });
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
            <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem 2rem', backgroundColor: '#0a0a0a', borderBottom: '1px solid #333' }}>
                <div>
                    <h1 style={{ margin: 0, color: '#61dafb' }}>THREAT-FUSION SOAR</h1>
                    <p style={{ margin: 0, opacity: 0.8, fontSize: '0.9rem' }}>Vulnerability Assessment & Automated Reporting</p>
                </div>
                <nav>
                    <button onClick={() => setView('dashboard')} className={view === 'dashboard' ? 'nav-active' : ''} style={{ marginRight: '10px', padding: '8px 15px', cursor: 'pointer' }}>🏠 Dashboard</button>
                    <button onClick={() => setView('history')} className={view === 'history' ? 'nav-active' : ''} style={{ padding: '8px 15px', cursor: 'pointer' }}>📜 Full History</button>
                </nav>
            </header>

            <main style={{ padding: '2rem' }}>
                <section className="analytics-dashboard" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '30px' }}>
                    <div className="stat-card" style={{ background: '#1a1a1a', padding: '20px', borderRadius: '10px', borderLeft: '5px solid #61dafb' }}>
                        <h4 style={{ margin: 0, opacity: 0.7, fontSize: '0.8rem' }}>TOTAL ASSESSMENTS</h4>
                        <h2 style={{ margin: '10px 0 0 0', fontSize: '2rem' }}>{totalScans}</h2>
                    </div>
                    <div className="stat-card" style={{ background: '#1a1a1a', padding: '20px', borderRadius: '10px', borderLeft: '5px solid #e74c3c' }}>
                        <h4 style={{ margin: 0, opacity: 0.7, fontSize: '0.8rem' }}>HIGH/CRITICAL RISK</h4>
                        <h2 style={{ margin: '10px 0 0 0', fontSize: '2rem', color: '#e74c3c' }}>{highRiskScans}</h2>
                    </div>
                    <div className="stat-card" style={{ background: '#1a1a1a', padding: '20px', borderRadius: '10px', borderLeft: '5px solid #f1c40f' }}>
                        <h4 style={{ margin: 0, opacity: 0.7, fontSize: '0.8rem' }}>SCAN SUCCESS RATE</h4>
                        <h2 style={{ margin: '10px 0 0 0', fontSize: '2rem', color: '#f1c40f' }}>{uptimePercentage}%</h2>
                    </div>
                    <div className="stat-card" style={{ background: '#1a1a1a', padding: '20px', borderRadius: '10px', borderLeft: '5px solid #2ecc71' }}>
                        <h4 style={{ margin: 0, opacity: 0.7, fontSize: '0.8rem' }}>DOMINANT THREAT</h4>
                        <h2 style={{ margin: '10px 0 0 0', fontSize: '1.2rem', color: '#2ecc71' }}>{topThreat}</h2>
                    </div>
                </section>

                {view === 'dashboard' && (
                    <section className="scan-form" style={{ marginBottom: '40px', textAlign: 'center' }}>
                        <h2 style={{ marginBottom: '20px' }}>🚀 Launch New Assessment</h2>
                        <form onSubmit={handleScan} style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                            <input
                                type="text"
                                placeholder="Enter Target (e.g., testphp.vulnweb.com)"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                disabled={loading}
                                style={{ padding: '12px', width: '350px', borderRadius: '5px', border: '1px solid #444', background: '#222', color: 'white' }}
                            />
                            <button type="submit" disabled={loading} style={{ padding: '12px 25px', borderRadius: '5px', background: '#61dafb', color: '#000', fontWeight: 'bold', border: 'none', cursor: 'pointer' }}>
                                {loading ? 'Initializing Scanner...' : 'Launch Scan'}
                            </button>
                        </form>
                    </section>
                )}

                <section className="history-section">
                    <section className="verify-tool" style={{ marginBottom: '30px', padding: '20px', border: '1px dashed #444', borderRadius: '12px', textAlign: 'center', backgroundColor: 'rgba(255,255,255,0.03)' }}>
                        <h3 style={{ marginTop: 0 }}>🛡️ Report Integrity Verifier</h3>
                        <p style={{ fontSize: '0.9rem', opacity: 0.7 }}>Upload a PDF report to verify its digital fingerprint against the secure database.</p>
                        <input type="file" accept=".pdf" onChange={verifyIntegrity} style={{ color: '#aaa', margin: '10px 0' }} />
                        {verificationResult && (
                            <div style={{
                                marginTop: '15px',
                                padding: '12px',
                                borderRadius: '8px',
                                backgroundColor: verificationResult.status === 'success' ? '#1b4721' : '#471b1b',
                                color: 'white',
                                fontWeight: 'bold',
                                border: `1px solid ${verificationResult.status === 'success' ? '#2ecc71' : '#e74c3c'}`
                            }}>
                                {verificationResult.text}
                            </div>
                        )}
                    </section>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                        <h2 style={{ margin: 0 }}>{view === 'dashboard' ? 'Recent Activity (Last 5)' : 'Full Audit Logs'}</h2>
                        {view === 'history' && history.length > 0 && (
                            <button onClick={clearHistory} style={{ backgroundColor: '#dc3545', color: 'white', border: 'none', borderRadius: '5px', fontSize: '0.9rem', padding: '8px 15px', cursor: 'pointer' }}>🗑️ Clear Logs</button>
                        )}
                    </div>

                    <table style={{ width: '100%', borderCollapse: 'collapse', backgroundColor: '#111', borderRadius: '10px', overflow: 'hidden' }}>
                        <thead>
                            <tr style={{ textAlign: 'left', borderBottom: '2px solid #333' }}>
                                <th style={{ padding: '15px' }}>ID</th>
                                <th>Target</th>
                                <th>Score</th>
                                <th>Level</th>
                                <th>Status</th>
                                <th>SHA-256 Hash</th>
                                <th style={{ textAlign: 'center' }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {displayedHistory.length === 0 ? (
                                <tr><td colSpan="7" style={{ textAlign: 'center', padding: '30px', opacity: 0.5 }}>No scans found. Launch an assessment to begin.</td></tr>
                            ) : (
                                displayedHistory.map((scan) => (
                                    <tr key={scan.id} style={{ borderBottom: '1px solid #222' }}>
                                        <td style={{ padding: '15px' }}>{scan.id}</td>
                                        <td style={{ fontWeight: 'bold' }}>{scan.target}</td>
                                        <td style={{ fontWeight: 'bold', color: scan.security_score < 50 ? '#ff4d4d' : (scan.security_score < 80 ? '#f1c40f' : '#2ecc71') }}>
                                            {scan.security_score !== null ? `${scan.security_score}/100` : '---'}
                                        </td>
                                        <td>
                                            <span style={{
                                                padding: '3px 8px',
                                                borderRadius: '4px',
                                                fontSize: '11px',
                                                fontWeight: 'bold',
                                                backgroundColor: scan.risk_level === 'CRITICAL' ? '#ff0000' : (scan.risk_level === 'HIGH' ? '#e74c3c' : (scan.risk_level === 'MEDIUM' ? '#f39c12' : '#27ae60')),
                                                color: 'white'
                                            }}>
                                                {scan.risk_level || 'WAITING'}
                                            </span>
                                        </td>
                                        <td><span style={{ fontSize: '0.9rem', color: scan.status === 'Completed' ? '#2ecc71' : '#f1c40f' }}>{scan.status}</span></td>
                                        <td style={{ fontSize: '11px', fontFamily: 'monospace', color: '#666' }}>
                                            {scan.file_hash ? (
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                    <span title={scan.file_hash}>
                                                        {scan.file_hash.substring(0, 8)}...{scan.file_hash.substring(58)}
                                                    </span>
                                                    <button 
                                                        onClick={() => alert(`Full Integrity Hash:\n${scan.file_hash}`)}
                                                        style={{ background: 'none', border: '1px solid #444', color: '#61dafb', fontSize: '9px', padding: '2px 5px', borderRadius: '3px', cursor: 'pointer' }}
                                                    >
                                                        VIEW
                                                    </button>
                                                </div>
                                            ) : 'Pending...'}
                                        </td>
                                        <td style={{ textAlign: 'center' }}>
                                            {scan.status === 'Completed' ? (
                                                <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
                                                    <a href={apiUrl(`/download/${scan.pdf_path}`)} style={{ textDecoration: 'none', color: '#61dafb', fontSize: '0.85rem', border: '1px solid #61dafb', padding: '4px 10px', borderRadius: '4px' }} target="_blank" rel="noreferrer">PDF</a>
                                                    <a href={apiUrl(`/download/visual_report_${scan.id}.pdf`)} style={{ textDecoration: 'none', color: '#2ecc71', fontSize: '0.85rem', border: '1px solid #2ecc71', padding: '4px 10px', borderRadius: '4px' }} target="_blank" rel="noreferrer">VISUAL</a>
                                                </div>
                                            ) : '---'}
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>

                    {view === 'dashboard' && history.length > 5 && (
                        <div style={{ textAlign: 'center', marginTop: '20px' }}>
                            <button onClick={() => setView('history')} style={{ background: 'none', color: '#61dafb', border: '1px solid #61dafb', padding: '10px 25px', borderRadius: '5px', cursor: 'pointer' }}>View All Audit Logs ({history.length}) →</button>
                        </div>
                    )}
                </section>
            </main>
        </div>
    );
}

export default App;