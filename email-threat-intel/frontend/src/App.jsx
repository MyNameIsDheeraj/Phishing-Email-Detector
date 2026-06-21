// src/App.jsx
import { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Upload, 
  Terminal, 
  Activity, 
  Trash2, 
  Download, 
  RefreshCw, 
  FileText, 
  Link, 
  Globe, 
  File, 
  Search, 
  Clock, 
  ChevronRight, 
  CheckCircle, 
  AlertTriangle, 
  XCircle, 
  Server,
  Database,
  BarChart2,
  Mail,
  AlertOctagon
} from 'lucide-react';
import { api } from './api';

function App() {
  // Navigation tab state: 'dashboard', 'analyze', 'history', 'details'
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedEmailId, setSelectedEmailId] = useState(null);
  
  // Dashboard & global data states
  const [stats, setStats] = useState({
    total_emails: 0,
    verdicts: {},
    avg_score: 0,
    iocs: { total_urls: 0, total_ips: 0, total_attachments: 0, total_events: 0 }
  });
  const [recentEmails, setRecentEmails] = useState([]);
  const [backendHealthy, setBackendHealthy] = useState(null);
  
  // History tab states
  const [historyEmails, setHistoryEmails] = useState([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historySkip, setHistorySkip] = useState(0);
  const [historyFilter, setHistoryFilter] = useState('ALL');
  const [historySearch, setHistorySearch] = useState('');
  
  // Detail view state
  const [emailDetails, setEmailDetails] = useState(null);
  const [activeDetailTab, setActiveDetailTab] = useState('iocs');
  const [activeIocTab, setActiveIocTab] = useState('urls');
  const [isEnriching, setIsEnriching] = useState(false);
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  
  // Uploader states
  const [dragActive, setDragActive] = useState(false);
  const [uploadFile, setUploadFile] = useState(null);
  const [rawEmailText, setRawEmailText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  
  // Global loading and toast notification states
  const [globalLoading, setGlobalLoading] = useState(false);
  const [toast, setToast] = useState(null);
  
  const fileInputRef = useRef(null);

  // Show status toasts
  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast(null);
    }, 4000);
  };

  // Initialize and check health
  useEffect(() => {
    checkHealthAndLoadStats();
    loadRecentEmails();
  }, []);

  // Check health and dashboard stats
  const checkHealthAndLoadStats = async () => {
    try {
      const health = await api.getDashboardStats(); // fallback to stats if /health has CORS
      setStats(health);
      
      // Hit actual health endpoint to confirm DB status
      const actualHealth = await fetch('http://localhost:8000/health').then(res => res.json()).catch(() => null);
      if (actualHealth && actualHealth.status === 'healthy') {
        setBackendHealthy(actualHealth.database === 'connected' ? 'connected' : 'warning');
      } else {
        setBackendHealthy('connected'); // Fallback if direct fetch is blocked but api works
      }
    } catch (err) {
      console.error(err);
      setBackendHealthy('disconnected');
      showToast('Cannot connect to backend service', 'error');
    }
  };

  // Load recent emails
  const loadRecentEmails = async () => {
    try {
      const data = await api.getRecentEmails();
      setRecentEmails(data.emails || []);
    } catch (err) {
      console.error(err);
    }
  };

  // Load paginated history
  const loadHistory = async (skip = 0, verdict = 'ALL') => {
    setGlobalLoading(true);
    try {
      const data = await api.getEmails(skip, 50, verdict);
      setHistoryEmails(data.emails || []);
      setHistoryTotal(data.total || 0);
      setHistorySkip(skip);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setGlobalLoading(false);
    }
  };

  // Trigger loading details
  const loadEmailDetails = async (id) => {
    setGlobalLoading(true);
    try {
      const data = await api.getEmailDetails(id);
      setEmailDetails(data);
      setSelectedEmailId(id);
      setActiveTab('details');
      setActiveDetailTab('iocs');
      setActiveIocTab('urls');
      setShowRawHeaders(false);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setGlobalLoading(false);
    }
  };

  // Handle direct file drag & drop
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const ext = file.name.split('.').pop().toLowerCase();
      if (ext === 'eml' || ext === 'txt') {
        setUploadFile(file);
        showToast(`Selected file: ${file.name}`);
      } else {
        showToast('Only .eml and .txt files are supported', 'error');
      }
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      setUploadFile(e.target.files[0]);
    }
  };

  // Submit EML file upload
  const handleFileUploadSubmit = async (e) => {
    e.preventDefault();
    if (!uploadFile) return;
    
    setIsAnalyzing(true);
    try {
      const result = await api.uploadEmailFile(uploadFile);
      showToast('Email parsed and analyzed successfully');
      setUploadFile(null);
      // Load details of new scan
      await loadEmailDetails(result.id);
      // Refresh dashboard info
      checkHealthAndLoadStats();
      loadRecentEmails();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Submit raw email text analysis
  const handleTextAnalyzeSubmit = async (e) => {
    e.preventDefault();
    if (!rawEmailText.trim()) return;
    
    setIsAnalyzing(true);
    try {
      const result = await api.analyzeEmailText(rawEmailText);
      showToast('Raw text analyzed successfully');
      setRawEmailText('');
      // Load details of new scan
      await loadEmailDetails(result.id);
      // Refresh dashboard info
      checkHealthAndLoadStats();
      loadRecentEmails();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Force synchronous threat intelligence enrichment
  const handleEnrich = async () => {
    if (!selectedEmailId) return;
    setIsEnriching(true);
    showToast('Enriching threat intel feed. VT & AbuseIPDB lookup in progress...');
    try {
      const result = await api.enrichEmail(selectedEmailId);
      showToast(`Enrichment complete! Score updated to ${result.threat_score}/100.`);
      // Reload details
      await loadEmailDetails(selectedEmailId);
      // Refresh dashboard stats
      checkHealthAndLoadStats();
      loadRecentEmails();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setIsEnriching(false);
    }
  };

  // Delete an email record
  const handleDeleteEmail = async (id, returnToDashboard = false) => {
    if (!window.confirm('Are you sure you want to delete this email forensic record? This action cannot be undone.')) {
      return;
    }
    try {
      await api.deleteEmail(id);
      showToast('Forensic analysis record deleted');
      
      checkHealthAndLoadStats();
      loadRecentEmails();
      
      if (returnToDashboard) {
        setActiveTab('dashboard');
        setSelectedEmailId(null);
        setEmailDetails(null);
      } else if (activeTab === 'history') {
        loadHistory(historySkip, historyFilter);
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  // Get color configurations based on verdict
  const getVerdictStyles = (verdict) => {
    const v = (verdict || '').toUpperCase();
    if (v === 'MALICIOUS') {
      return {
        badgeClass: 'malicious',
        scoreColorClass: 'malicious',
        textClass: 'color-malicious-text',
        icon: <ShieldAlert size={18} />
      };
    } else if (v === 'SUSPICIOUS') {
      return {
        badgeClass: 'suspicious',
        scoreColorClass: 'suspicious',
        textClass: 'color-suspicious-text',
        icon: <AlertOctagon size={18} />
      };
    } else {
      return {
        badgeClass: 'safe',
        scoreColorClass: 'safe',
        textClass: 'color-safe-text',
        icon: <ShieldCheck size={18} />
      };
    }
  };

  // Parse rule details from timeline
  const extractRuleTriggers = () => {
    if (!emailDetails || !emailDetails.timeline) return [];
    const ruleDetailsEvent = emailDetails.timeline.find(
      (ev) => ev.event_type === 'RULE_DETAILS'
    );
    if (!ruleDetailsEvent) return [];
    const desc = ruleDetailsEvent.description;
    if (desc.startsWith("Rule triggers: ")) {
      return desc.substring(15).split(',').map(s => s.trim()).filter(Boolean);
    }
    return [];
  };

  // Format date values
  const formatDate = (isoString) => {
    if (!isoString) return 'N/A';
    const date = new Date(isoString);
    return date.toLocaleString();
  };

  const activeVerdictInfo = getVerdictStyles(emailDetails?.verdict);
  const ruleTriggers = extractRuleTriggers();

  // Search filter for History Tab
  const filteredHistory = historyEmails.filter(email => {
    if (!historySearch) return true;
    const searchLower = historySearch.toLowerCase();
    return (
      (email.subject || '').toLowerCase().includes(searchLower) ||
      (email.sender || '').toLowerCase().includes(searchLower)
    );
  });

  return (
    <div className="app-container">
      {/* Toast Notification */}
      {toast && (
        <div className={`toast-bar ${toast.type === 'error' ? 'error' : toast.type === 'success' ? 'success' : ''}`}>
          {toast.type === 'error' ? <AlertTriangle size={18} /> : <CheckCircle size={18} />}
          <span>{toast.message}</span>
        </div>
      )}

      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <Shield size={32} />
          </div>
          <h1 className="sidebar-title">
            ThreatIntel
            <span>Email Phishing Forensics</span>
          </h1>
        </div>
        
        <nav className="sidebar-nav">
          <button 
            className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => { setActiveTab('dashboard'); setSelectedEmailId(null); }}
          >
            <BarChart2 size={18} />
            <span>Dashboard</span>
          </button>
          
          <button 
            className={`nav-item ${activeTab === 'analyze' ? 'active' : ''}`}
            onClick={() => { setActiveTab('analyze'); setSelectedEmailId(null); }}
          >
            <Upload size={18} />
            <span>Analyze Email</span>
          </button>
          
          <button 
            className={`nav-item ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => { setActiveTab('history'); loadHistory(0, 'ALL'); setSelectedEmailId(null); }}
          >
            <Activity size={18} />
            <span>Forensic Logs</span>
          </button>

          {selectedEmailId && (
            <button 
              className={`nav-item ${activeTab === 'details' ? 'active' : ''}`}
              onClick={() => setActiveTab('details')}
            >
              <FileText size={18} />
              <span>Forensic Report</span>
            </button>
          )}
        </nav>

        {/* <div className="sidebar-footer">
          <div>SOC Console v2.0.0</div>
          <div>Database Connected</div>
        </div> */}
      </aside>

      {/* Main Panel Area */}
      <div className="main-wrapper">
        <header className="main-header">
          <div className="page-title-area">
            <h2>
              {activeTab === 'dashboard' && 'Security Operations Overview'}
              {activeTab === 'analyze' && 'Threat Analysis Entry'}
              {activeTab === 'history' && 'Forensic Log Database'}
              {activeTab === 'details' && 'Incident forensic Investigation'}
            </h2>
          </div>
          
          <div className="header-status">
            {backendHealthy === 'connected' && (
              <div className="db-badge">
                <Server size={14} />
                <span>Backend Online</span>
              </div>
            )}
            {backendHealthy === 'warning' && (
              <div className="db-badge disconnected">
                <AlertTriangle size={14} />
                <span>DB Error</span>
              </div>
            )}
            {backendHealthy === 'disconnected' && (
              <div className="db-badge disconnected">
                <XCircle size={14} />
                <span>Backend Offline</span>
              </div>
            )}
          </div>
        </header>

        <main className="main-content">
          {globalLoading && (
            <div className="loading-overlay">
              <div className="spinner"></div>
              <p>Fetching Threat Intel Records...</p>
            </div>
          )}

          {/* DASHBOARD TAB */}
          {!globalLoading && activeTab === 'dashboard' && (
            <div>
              {/* Statistics Cards */}
              <div className="dashboard-grid">
                <div className="stat-card">
                  <div className="stat-info">
                    <h3>Scanned Emails</h3>
                    <div className="stat-val">{stats.total_emails}</div>
                  </div>
                  <div className="stat-icon blue">
                    <Mail size={24} />
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-info">
                    <h3>Avg Threat Score</h3>
                    <div className="stat-val">{stats.avg_score || 0}%</div>
                  </div>
                  <div className="stat-icon red">
                    <ShieldAlert size={24} />
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-info">
                    <h3>Malicious Detected</h3>
                    <div className="stat-val">{stats.verdicts?.MALICIOUS || 0}</div>
                  </div>
                  <div className="stat-icon red">
                    <ShieldAlert size={24} />
                  </div>
                </div>

                <div className="stat-card">
                  <div className="stat-info">
                    <h3>Verified Safe</h3>
                    <div className="stat-val">{stats.verdicts?.SAFE || 0}</div>
                  </div>
                  <div className="stat-icon green">
                    <ShieldCheck size={24} />
                  </div>
                </div>
              </div>

              {/* Middle Breakdown Rows */}
              <div className="dashboard-rows">
                {/* Left panel: Recent scans */}
                <div className="card-panel">
                  <div className="panel-header">
                    <h3>Recent Analysis History</h3>
                    <button className="btn btn-secondary btn-icon" onClick={loadRecentEmails}>
                      <RefreshCw size={14} />
                    </button>
                  </div>
                  <div className="panel-body">
                    {recentEmails.length === 0 ? (
                      <div className="empty-state">
                        <h4>No Scanned Emails</h4>
                        <p>Upload an EML file or paste raw text to run threat intelligence forensics.</p>
                        <button className="btn btn-primary margin-top-md" onClick={() => setActiveTab('analyze')}>
                          Scan Suspicious Email
                        </button>
                      </div>
                    ) : (
                      <div className="scans-table-container">
                        <table className="scans-table">
                          <thead>
                            <tr>
                              <th>Sender</th>
                              <th>Subject</th>
                              <th>Score</th>
                              <th>Verdict</th>
                              <th>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {recentEmails.map((email) => {
                              const vInfo = getVerdictStyles(email.verdict);
                              return (
                                <tr key={email.id}>
                                  <td className="sender-cell">{email.sender || 'Unknown Sender'}</td>
                                  <td className="subject-cell">{email.subject || 'No Subject'}</td>
                                  <td>
                                    <span className={`threat-score-badge ${vInfo.badgeClass}`}>
                                      {email.threat_score}%
                                    </span>
                                  </td>
                                  <td>
                                    <span className={`verdict-badge ${vInfo.badgeClass}`}>
                                      {vInfo.icon}
                                      {email.verdict}
                                    </span>
                                  </td>
                                  <td className="actions-cell">
                                    <button 
                                      className="btn btn-outline-info btn-icon" 
                                      onClick={() => loadEmailDetails(email.id)}
                                      title="Forensic details"
                                    >
                                      <ChevronRight size={14} />
                                    </button>
                                    <button 
                                      className="btn btn-danger btn-icon" 
                                      onClick={() => handleDeleteEmail(email.id)}
                                      title="Delete"
                                    >
                                      <Trash2 size={14} />
                                    </button>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </div>

                {/* Right Panel: IOC Breakdown */}
                <div className="card-panel">
                  <div className="panel-header">
                    <h3>Verdict & IOC Breakdown</h3>
                  </div>
                  <div className="panel-body">
                    {/* Verdict Progress bars */}
                    <div className="verdict-breakdown-list margin-bottom-lg">
                      <div className="verdict-row">
                        <div className="verdict-row-info">
                          <span className="verdict-row-label">
                            <span className="verdict-dot malicious"></span>
                            <span>Malicious</span>
                          </span>
                          <span>
                            {stats.verdicts?.MALICIOUS || 0} (
                            {stats.total_emails > 0 
                              ? Math.round(((stats.verdicts?.MALICIOUS || 0) / stats.total_emails) * 100) 
                              : 0}%
                            )
                          </span>
                        </div>
                        <div className="verdict-progress-bg">
                          <div 
                            className="verdict-progress-fill malicious" 
                            style={{ width: `${stats.total_emails > 0 ? ((stats.verdicts?.MALICIOUS || 0) / stats.total_emails) * 100 : 0}%` }}
                          ></div>
                        </div>
                      </div>

                      <div className="verdict-row">
                        <div className="verdict-row-info">
                          <span className="verdict-row-label">
                            <span className="verdict-dot suspicious"></span>
                            <span>Suspicious</span>
                          </span>
                          <span>
                            {stats.verdicts?.SUSPICIOUS || 0} (
                            {stats.total_emails > 0 
                              ? Math.round(((stats.verdicts?.SUSPICIOUS || 0) / stats.total_emails) * 100) 
                              : 0}%
                            )
                          </span>
                        </div>
                        <div className="verdict-progress-bg">
                          <div 
                            className="verdict-progress-fill suspicious" 
                            style={{ width: `${stats.total_emails > 0 ? ((stats.verdicts?.SUSPICIOUS || 0) / stats.total_emails) * 100 : 0}%` }}
                          ></div>
                        </div>
                      </div>

                      <div className="verdict-row">
                        <div className="verdict-row-info">
                          <span className="verdict-row-label">
                            <span className="verdict-dot safe"></span>
                            <span>Safe</span>
                          </span>
                          <span>
                            {stats.verdicts?.SAFE || 0} (
                            {stats.total_emails > 0 
                              ? Math.round(((stats.verdicts?.SAFE || 0) / stats.total_emails) * 100) 
                              : 0}%
                            )
                          </span>
                        </div>
                        <div className="verdict-progress-bg">
                          <div 
                            className="verdict-progress-fill safe" 
                            style={{ width: `${stats.total_emails > 0 ? ((stats.verdicts?.SAFE || 0) / stats.total_emails) * 100 : 0}%` }}
                          ></div>
                        </div>
                      </div>
                    </div>

                    {/* IOC Stats Table */}
                    <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
                      <h4 className="margin-bottom-md" style={{ fontFamily: 'var(--font-display)', fontSize: '0.95rem' }}>
                        Extracted IOC Totals
                      </h4>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                        <div style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>URLs Analyzed</div>
                          <div style={{ fontSize: '1.4rem', fontWeight: '700', color: 'var(--accent-neon)' }}>{stats.iocs?.total_urls || 0}</div>
                        </div>
                        <div style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>IPs Checked</div>
                          <div style={{ fontSize: '1.4rem', fontWeight: '700', color: 'var(--accent-neon)' }}>{stats.iocs?.total_ips || 0}</div>
                        </div>
                        <div style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>File Hashes</div>
                          <div style={{ fontSize: '1.4rem', fontWeight: '700', color: 'var(--accent-neon)' }}>{stats.iocs?.total_attachments || 0}</div>
                        </div>
                        <div style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                          <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textTransform: 'uppercase' }}>Forensic Events</div>
                          <div style={{ fontSize: '1.4rem', fontWeight: '700', color: 'var(--accent-neon)' }}>{stats.iocs?.total_events || 0}</div>
                        </div>
                      </div>
                    </div>

                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ANALYZE EMAIL TAB */}
          {!globalLoading && activeTab === 'analyze' && (
            <div className="upload-container">
              {/* Left Panel: File Upload */}
              <div className="card-panel panel-flex">
                <div className="panel-header">
                  <h3>Upload Email File (.eml / .txt)</h3>
                </div>
                <div className="panel-body">
                  <form onSubmit={handleFileUploadSubmit} style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '16px' }}>
                    <div 
                      className={`upload-drag-area ${dragActive ? 'dragging' : ''}`}
                      onDragEnter={handleDrag}
                      onDragOver={handleDrag}
                      onDragLeave={handleDrag}
                      onDrop={handleDrop}
                      onClick={() => fileInputRef.current.click()}
                    >
                      <input 
                        ref={fileInputRef}
                        type="file" 
                        className="file-input"
                        accept=".eml,.txt"
                        onChange={handleFileSelect}
                      />
                      <Upload size={48} style={{ color: uploadFile ? 'var(--accent-neon)' : 'var(--text-muted)' }} />
                      {uploadFile ? (
                        <div className="text-center">
                          <p style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{uploadFile.name}</p>
                          <p style={{ fontSize: '0.8rem', marginTop: '4px' }}>{(uploadFile.size / 1024).toFixed(2)} KB</p>
                        </div>
                      ) : (
                        <p>
                          Drag & drop EML or TXT email file here, or <span style={{ color: 'var(--accent-neon)', textDecoration: 'underline' }}>browse files</span>.
                        </p>
                      )}
                    </div>
                    
                    <button 
                      type="submit" 
                      className="btn btn-primary"
                      disabled={!uploadFile || isAnalyzing}
                      style={{ width: '100%', padding: '14px' }}
                    >
                      {isAnalyzing ? (
                        <>
                          <div className="spinner" style={{ width: '16px', height: '16px', borderTopColor: '#fff', borderLeftColor: 'transparent' }}></div>
                          <span>Parsing forensic indicators...</span>
                        </>
                      ) : (
                        <>
                          <Shield size={18} />
                          <span>Run Forensic Scan</span>
                        </>
                      )}
                    </button>
                  </form>
                </div>
              </div>

              {/* Right Panel: Paste Raw Text */}
              <div className="card-panel panel-flex">
                <div className="panel-header">
                  <h3>Paste Raw Email Content</h3>
                </div>
                <div className="panel-body">
                  <form onSubmit={handleTextAnalyzeSubmit} className="text-analyzer-form">
                    <textarea
                      className="raw-textarea"
                      placeholder="Paste raw email headers, metadata and body here (standard RFC 822 format)..."
                      value={rawEmailText}
                      onChange={(e) => setRawEmailText(e.target.value)}
                    ></textarea>
                    
                    <button 
                      type="submit" 
                      className="btn btn-primary"
                      disabled={!rawEmailText.trim() || isAnalyzing}
                      style={{ padding: '14px' }}
                    >
                      {isAnalyzing ? (
                        <>
                          <div className="spinner" style={{ width: '16px', height: '16px', borderTopColor: '#fff', borderLeftColor: 'transparent' }}></div>
                          <span>Analyzing raw content...</span>
                        </>
                      ) : (
                        <>
                          <Terminal size={18} />
                          <span>Scan Email Text</span>
                        </>
                      )}
                    </button>
                  </form>
                </div>
              </div>
            </div>
          )}

          {/* HISTORY FORENSIC LOG TAB */}
          {!globalLoading && activeTab === 'history' && (
            <div className="card-panel">
              <div className="panel-header">
                <h3>Forensic Log Database</h3>
                <div style={{ display: 'flex', gap: '12px' }}>
                  <div style={{ position: 'relative' }}>
                    <Search size={14} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                    <input 
                      type="text" 
                      placeholder="Search sender/subject..."
                      value={historySearch}
                      onChange={(e) => setHistorySearch(e.target.value)}
                      style={{
                        padding: '8px 12px 8px 32px',
                        background: 'rgba(0,0,0,0.2)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '6px',
                        color: 'var(--text-primary)',
                        fontSize: '0.85rem'
                      }}
                    />
                  </div>
                  <button className="btn btn-secondary btn-icon" onClick={() => loadHistory(historySkip, historyFilter)}>
                    <RefreshCw size={14} />
                  </button>
                </div>
              </div>
              <div className="panel-body">
                {/* Filter Selector */}
                <div className="history-filters">
                  {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'SAFE'].map(v => (
                    <button
                      key={v}
                      className={`filter-btn ${historyFilter === v ? `active ${v.toLowerCase()}` : ''}`}
                      onClick={() => {
                        setHistoryFilter(v);
                        loadHistory(0, v);
                      }}
                    >
                      {v}
                    </button>
                  ))}
                </div>

                {filteredHistory.length === 0 ? (
                  <div className="empty-state">
                    <h4>No Threat Logs Found</h4>
                    <p>No records match your query filters. Scan new files to build your database.</p>
                  </div>
                ) : (
                  <div>
                    <div className="scans-table-container">
                      <table className="scans-table">
                        <thead>
                          <tr>
                            <th>ID</th>
                            <th>Received At</th>
                            <th>Sender</th>
                            <th>Subject</th>
                            <th>Score</th>
                            <th>Verdict</th>
                            <th>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredHistory.map((email) => {
                            const vInfo = getVerdictStyles(email.verdict);
                            return (
                              <tr key={email.id}>
                                <td style={{ color: 'var(--accent-neon)', fontWeight: '600', fontFamily: 'var(--font-mono)' }}>#{email.id}</td>
                                <td className="date-cell">{formatDate(email.received_at)}</td>
                                <td className="sender-cell">{email.sender || 'Unknown Sender'}</td>
                                <td className="subject-cell">{email.subject || 'No Subject'}</td>
                                <td>
                                  <span className={`threat-score-badge ${vInfo.badgeClass}`}>
                                    {email.threat_score}%
                                  </span>
                                </td>
                                <td>
                                  <span className={`verdict-badge ${vInfo.badgeClass}`}>
                                    {vInfo.icon}
                                    {email.verdict}
                                  </span>
                                </td>
                                <td className="actions-cell">
                                  <button 
                                    className="btn btn-outline-info btn-icon" 
                                    onClick={() => loadEmailDetails(email.id)}
                                    title="View Forensic Details"
                                  >
                                    <ChevronRight size={14} />
                                  </button>
                                  <a 
                                    href={api.getReportDownloadUrl(email.id)}
                                    className="btn btn-secondary btn-icon" 
                                    title="Download PDF report"
                                    download
                                  >
                                    <Download size={14} />
                                  </a>
                                  <button 
                                    className="btn btn-danger btn-icon" 
                                    onClick={() => handleDeleteEmail(email.id)}
                                    title="Delete"
                                  >
                                    <Trash2 size={14} />
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>

                    {/* Simple Pagination Footer */}
                    <div className="flex-between margin-top-md" style={{ borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
                      <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                        Showing {filteredHistory.length} of {historyTotal} records
                      </span>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          className="btn btn-secondary"
                          disabled={historySkip === 0}
                          onClick={() => loadHistory(Math.max(0, historySkip - 50), historyFilter)}
                          style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                        >
                          Previous
                        </button>
                        <button
                          className="btn btn-secondary"
                          disabled={historySkip + 50 >= historyTotal}
                          onClick={() => loadHistory(historySkip + 50, historyFilter)}
                          style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* EMAIL FORENSIC DETAIL VIEW */}
          {!globalLoading && activeTab === 'details' && emailDetails && (
            <div className="forensic-layout">
              {/* Back / Top bar */}
              <div className="flex-between">
                <button className="btn btn-secondary" onClick={() => setActiveTab('dashboard')}>
                  &larr; Back to Dashboard
                </button>
                <div style={{ display: 'flex', gap: '12px' }}>
                  <button 
                    className="btn btn-secondary" 
                    onClick={handleEnrich} 
                    disabled={isEnriching}
                  >
                    <RefreshCw size={16} className={isEnriching ? 'spinner' : ''} />
                    <span>{isEnriching ? 'Syncing Intel...' : 'Force Intel Enrichment'}</span>
                  </button>
                  
                  <a 
                    href={api.getReportDownloadUrl(emailDetails.id)} 
                    className="btn btn-primary"
                    download
                  >
                    <Download size={16} />
                    <span>Download PDF Report</span>
                  </a>

                  <button 
                    className="btn btn-danger"
                    onClick={() => handleDeleteEmail(emailDetails.id, true)}
                  >
                    <Trash2 size={16} />
                    <span>Delete Record</span>
                  </button>
                </div>
              </div>

              {/* Main Summary Header */}
              <div className="forensic-header-bar">
                <div className="email-meta-summary">
                  <div className="meta-subject">{emailDetails.subject || '(No Subject)'}</div>
                  <div className="meta-row" style={{ marginTop: '8px' }}>
                    <div><strong>From:</strong> {emailDetails.sender}</div>
                    <div><strong>Domain:</strong> {emailDetails.sender_domain || 'N/A'}</div>
                    <div><strong>Analyzed At:</strong> {formatDate(emailDetails.analyzed_at || emailDetails.received_at)}</div>
                  </div>
                </div>

                <div className="header-verdict-card">
                  <div className="score-title">Threat Verdict</div>
                  <div className={`score-number ${activeVerdictInfo.scoreColorClass}`}>
                    {emailDetails.threat_score}%
                  </div>
                  <span className={`verdict-badge ${activeVerdictInfo.badgeClass}`}>
                    {activeVerdictInfo.icon}
                    {emailDetails.verdict}
                  </span>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '8px' }}>
                    Confidence: <strong>{emailDetails.confidence}</strong>
                  </div>
                </div>
              </div>

              {/* Two Column details structure */}
              <div className="forensic-grid">
                {/* Left Column: Security Auth Checklist & Rules */}
                <div className="left-panel">
                  {/* Security Checks */}
                  <div className="card-panel">
                    <div className="panel-header">
                      <h3>Security Authentication Checklist</h3>
                    </div>
                    <div className="panel-body">
                      <div className="auth-checklist">
                        <div className="auth-item">
                          <div className="auth-item-info">
                            <ShieldCheck size={16} style={{ color: emailDetails.spf_status === 'PASS' ? 'var(--color-safe)' : 'var(--color-malicious)' }} />
                            <strong>SPF Validation</strong>
                          </div>
                          <span className={`auth-badge ${emailDetails.spf_status?.toLowerCase() || 'none'}`}>
                            {emailDetails.spf_status || 'NONE'}
                          </span>
                        </div>

                        <div className="auth-item">
                          <div className="auth-item-info">
                            <ShieldCheck size={16} style={{ color: emailDetails.dkim_status === 'PASS' ? 'var(--color-safe)' : 'var(--color-malicious)' }} />
                            <strong>DKIM Verification</strong>
                          </div>
                          <span className={`auth-badge ${emailDetails.dkim_status?.toLowerCase() || 'none'}`}>
                            {emailDetails.dkim_status || 'NONE'}
                          </span>
                        </div>

                        <div className="auth-item">
                          <div className="auth-item-info">
                            <ShieldCheck size={16} style={{ color: emailDetails.dmarc_status === 'PASS' ? 'var(--color-safe)' : 'var(--color-malicious)' }} />
                            <strong>DMARC Alignment</strong>
                          </div>
                          <span className={`auth-badge ${emailDetails.dmarc_status?.toLowerCase() || 'none'}`}>
                            {emailDetails.dmarc_status || 'NONE'}
                          </span>
                        </div>

                        {/* Spamhaus check (extract from timeline or IP list) */}
                        <div className="auth-item">
                          <div className="auth-item-info">
                            <Database size={16} style={{ color: emailDetails.iocs?.ips?.some(ip => ip.spamhaus_flagged) ? 'var(--color-malicious)' : 'var(--color-safe)' }} />
                            <strong>Spamhaus Blacklist</strong>
                          </div>
                          {emailDetails.iocs?.ips?.some(ip => ip.spamhaus_flagged) ? (
                            <span className="auth-badge fail">FLAGGED</span>
                          ) : (
                            <span className="auth-badge pass">CLEAN</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Rule Triggers */}
                  <div className="card-panel">
                    <div className="panel-header">
                      <h3>Rule Detections ({ruleTriggers.length})</h3>
                    </div>
                    <div className="panel-body">
                      <div className="rule-triggers-list">
                        {ruleTriggers.length === 0 ? (
                          <div className="rule-trigger-item none">
                            <span>No suspicious rules triggered. Email heuristics look standard.</span>
                          </div>
                        ) : (
                          ruleTriggers.map((rule, idx) => (
                            <div className="rule-trigger-item" key={idx}>
                              <AlertTriangle size={14} style={{ color: 'var(--color-suspicious)', marginTop: '2px', flexShrink: 0 }} />
                              <span>{rule}</span>
                            </div>
                          ))
                        )}
                      </div>
                      <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        <span>Heuristic Base Score:</span>
                        <strong style={{ color: 'var(--text-primary)' }}>{emailDetails.rule_score}/100</strong>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Right Column: IOC Tabs / Body Content */}
                <div className="right-panel">
                  <div className="card-panel">
                    <div className="tabs-header">
                      <button 
                        className={`tab-btn ${activeDetailTab === 'iocs' ? 'active' : ''}`}
                        onClick={() => setActiveDetailTab('iocs')}
                      >
                        Threat Intelligence IOCs
                      </button>
                      <button 
                        className={`tab-btn ${activeDetailTab === 'timeline' ? 'active' : ''}`}
                        onClick={() => setActiveDetailTab('timeline')}
                      >
                        Forensic Timeline
                      </button>
                      <button 
                        className={`tab-btn ${activeDetailTab === 'body' ? 'active' : ''}`}
                        onClick={() => setActiveDetailTab('body')}
                      >
                        Email Inspector
                      </button>
                    </div>

                    {/* IOC SUB-TABS PANEL */}
                    {activeDetailTab === 'iocs' && (
                      <div className="tab-body">
                        {/* Sub tab selectors */}
                        <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', paddingBottom: '12px' }}>
                          <button
                            className={`filter-btn ${activeIocTab === 'urls' ? 'active' : ''}`}
                            onClick={() => setActiveIocTab('urls')}
                            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                          >
                            <Link size={12} />
                            <span>URLs ({emailDetails.iocs?.urls?.length || 0})</span>
                          </button>
                          <button
                            className={`filter-btn ${activeIocTab === 'ips' ? 'active' : ''}`}
                            onClick={() => setActiveIocTab('ips')}
                            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                          >
                            <Globe size={12} />
                            <span>IP Addresses ({emailDetails.iocs?.ips?.length || 0})</span>
                          </button>
                          <button
                            className={`filter-btn ${activeIocTab === 'attachments' ? 'active' : ''}`}
                            onClick={() => setActiveIocTab('attachments')}
                            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                          >
                            <File size={12} />
                            <span>Attachments ({emailDetails.iocs?.attachments?.length || 0})</span>
                          </button>
                        </div>

                        {/* URLs List */}
                        {activeIocTab === 'urls' && (
                          <div>
                            {(!emailDetails.iocs?.urls || emailDetails.iocs.urls.length === 0) ? (
                              <div className="empty-state">
                                <p>No URLs extracted from this email.</p>
                              </div>
                            ) : (
                              <div className="scans-table-container">
                                <table className="scans-table" style={{ fontSize: '0.85rem' }}>
                                  <thead>
                                    <tr>
                                      <th>URL Link</th>
                                      <th>Domain</th>
                                      <th>VirusTotal Score</th>
                                      <th>Verdict</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {emailDetails.iocs.urls.map((url, idx) => (
                                      <tr key={idx}>
                                        <td style={{ wordBreak: 'break-all', maxWidth: '240px', color: 'var(--accent-neon)', fontFamily: 'var(--font-mono)' }}>
                                          {url.url}
                                        </td>
                                        <td>{url.domain}</td>
                                        <td style={{ fontFamily: 'var(--font-mono)' }}>
                                          {url.vt_score !== null ? `${url.vt_score} detections` : 'Pending scan'}
                                        </td>
                                        <td>
                                          {url.is_phishing ? (
                                            <span className="threat-score-badge malicious">PHISHING</span>
                                          ) : (
                                            <span className="threat-score-badge safe">CLEAN / UNCHECKED</span>
                                          )}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}
                          </div>
                        )}

                        {/* IPs List */}
                        {activeIocTab === 'ips' && (
                          <div>
                            {(!emailDetails.iocs?.ips || emailDetails.iocs.ips.length === 0) ? (
                              <div className="empty-state">
                                <p>No IP addresses extracted from this email.</p>
                              </div>
                            ) : (
                              <div className="scans-table-container">
                                <table className="scans-table" style={{ fontSize: '0.85rem' }}>
                                  <thead>
                                    <tr>
                                      <th>IP Address</th>
                                      <th>AbuseIPDB Score</th>
                                      <th>Country</th>
                                      <th>ISP Owner</th>
                                      <th>Spamhaus</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {emailDetails.iocs.ips.map((ip, idx) => (
                                      <tr key={idx}>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: '600' }}>{ip.ip}</td>
                                        <td>
                                          {ip.abuse_score !== null ? (
                                            <span className={`threat-score-badge ${ip.abuse_score > 50 ? 'malicious' : ip.abuse_score > 20 ? 'suspicious' : 'safe'}`}>
                                              {ip.abuse_score}%
                                            </span>
                                          ) : (
                                            <span style={{ color: 'var(--text-muted)' }}>Pending scan</span>
                                          )}
                                        </td>
                                        <td>{ip.country || 'Unknown'}</td>
                                        <td style={{ maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ip.isp}>
                                          {ip.isp || 'N/A'}
                                        </td>
                                        <td>
                                          {ip.spamhaus_flagged ? (
                                            <span className="threat-score-badge malicious">BLACKLISTED</span>
                                          ) : (
                                            <span className="threat-score-badge safe">CLEAN</span>
                                          )}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}
                          </div>
                        )}

                        {/* Attachments List */}
                        {activeIocTab === 'attachments' && (
                          <div>
                            {(!emailDetails.iocs?.attachments || emailDetails.iocs.attachments.length === 0) ? (
                              <div className="empty-state">
                                <p>No file attachments detected in this email.</p>
                              </div>
                            ) : (
                              <div className="scans-table-container">
                                <table className="scans-table" style={{ fontSize: '0.85rem' }}>
                                  <thead>
                                    <tr>
                                      <th>Filename</th>
                                      <th>SHA256 File Hash</th>
                                      <th>VirusTotal Verdict</th>
                                      <th>Scan Time</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {emailDetails.iocs.attachments.map((att, idx) => (
                                      <tr key={idx}>
                                        <td style={{ fontWeight: '500' }}>
                                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <File size={14} style={{ color: 'var(--text-muted)' }} />
                                            <span>{att.file_name}</span>
                                          </div>
                                        </td>
                                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', wordBreak: 'break-all', maxWidth: '200px' }}>
                                          {att.sha256}
                                        </td>
                                        <td>
                                          {att.vt_score !== null ? (
                                            <span className={`threat-score-badge ${att.vt_score > 0 ? 'malicious' : 'safe'}`}>
                                              {att.vt_score > 0 ? `${att.vt_score} engines flagged` : 'CLEAN'}
                                            </span>
                                          ) : (
                                            <span style={{ color: 'var(--text-muted)' }}>Pending VT scan</span>
                                          )}
                                        </td>
                                        <td className="date-cell">{att.checked_at ? formatDate(att.checked_at) : 'Not scan enriched'}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* FORENSIC TIMELINE PANEL */}
                    {activeDetailTab === 'timeline' && (
                      <div className="tab-body">
                        {!emailDetails.timeline || emailDetails.timeline.length === 0 ? (
                          <div className="empty-state">
                            <p>No timeline events available for this analysis.</p>
                          </div>
                        ) : (
                          <div className="timeline-list">
                            {emailDetails.timeline.map((event, idx) => (
                              <div className="timeline-item" key={idx}>
                                <div className={`timeline-dot ${event.severity.toLowerCase()}`}></div>
                                <div className="timeline-meta">
                                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: 'var(--accent-neon)', fontSize: '0.75rem' }}>
                                    {event.event_type}
                                  </span>
                                  <span>{formatDate(event.timestamp)}</span>
                                </div>
                                <div className="timeline-desc">
                                  {event.description}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* EMAIL BODY INSPECTOR */}
                    {activeDetailTab === 'body' && (
                      <div className="tab-body">
                        <div className="flex-between margin-bottom-md">
                          <h4>Analyzed Email Content</h4>
                          <button 
                            className="btn btn-secondary" 
                            style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                            onClick={() => setShowRawHeaders(!showRawHeaders)}
                          >
                            {showRawHeaders ? 'Show Parsed Body' : 'View Headers'}
                          </button>
                        </div>

                        {showRawHeaders ? (
                          <div className="email-body-preview raw">
                            {emailDetails.headers || 'No SMTP Headers captured.'}
                          </div>
                        ) : (
                          <div className="email-body-preview">
                            {emailDetails.body || '(Empty email body content)'}
                          </div>
                        )}
                      </div>
                    )}

                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
