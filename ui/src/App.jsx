import { useState, useEffect, useRef } from 'react'
import { Shield, Cloud, Settings, Sun, Moon, Info, Send, RotateCcw, Download } from 'lucide-react'
import DastAnalyzer from './DastAnalyzer'
import AdminDashboard from './AdminDashboard'
import Welcome from './Welcome'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000/api'

function App() {
  const [activeTab, setActiveTab] = useState('welcome')
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark')
  const [apiKey, setApiKey] = useState(localStorage.getItem('CloudSecurityApp_api_key') || '')
  const [showKeyInput, setShowKeyInput] = useState(false)

  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [sessionId, setSessionId] = useState(null)
  const [progress, setProgress] = useState(0)
  const chatEndRef = useRef(null)

  useEffect(() => {
    localStorage.setItem('theme', theme)
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  useEffect(() => {
    if (activeTab === 'waf' && !sessionId) {
      startSession()
    }
  }, [activeTab])

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const toggleTheme = () => setTheme(prev => prev === 'dark' ? 'light' : 'dark')

  const saveApiKey = (key) => {
    setApiKey(key)
    localStorage.setItem('CloudSecurityApp_api_key', key)
    setShowKeyInput(false)
  }

  const startSession = async () => {
    setLoading(true)
    try {
      const response = await fetch(`${API_BASE}/chat/start`, { method: 'POST' })
      const data = await response.json()
      setSessionId(data.session_id)
      setMessages([{ role: 'bot', text: data.response }])
      setProgress(data.progress ?? 0)
    } catch (e) {
      setMessages([{ role: 'bot', text: `Connection Error: ${e.message}. Ensure backend is running.` }])
    }
    setLoading(false)
  }

  const sendMessage = async () => {
    if (!input.trim() || loading || !sessionId) return
    const userMessage = input.trim()
    setInput('')
    setMessages(prev => [...prev, { role: 'user', text: userMessage }])
    setLoading(true)

    try {
      const response = await fetch(`${API_BASE}/chat/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId, message: userMessage })
      })
      const data = await response.json()
      setMessages(prev => [...prev, { role: 'bot', text: data.response }])
      setProgress(data.progress ?? 0)
    } catch (e) {
      setMessages(prev => [...prev, { role: 'bot', text: 'Error communicating with AI.' }])
    }
    setLoading(false)
  }

  const handleDownload = () => {
    window.open(`${API_BASE}/report/pdf?session_id=${sessionId}`, '_blank')
  }

  return (
    <div className="app-container">
      <nav className="top-nav">
        <div className="logo" onClick={() => setActiveTab('welcome')}>
          <Shield className="logo-icon" size={24} />
          <span>Secure Cloud Architecture Assessment Engine</span>
        </div>
        <div className="nav-links">
          <button className={activeTab === 'welcome' ? 'active' : ''} onClick={() => setActiveTab('welcome')}>
            <Info size={18} /> Overview
          </button>
          <button className={activeTab === 'waf' ? 'active' : ''} onClick={() => setActiveTab('waf')}>
            <Shield size={18} /> WAF Assessment
          </button>
          <button className={activeTab === 'dast' ? 'active' : ''} onClick={() => setActiveTab('dast')}>
            <Cloud size={18} /> Pentesting
          </button>
          <button className={activeTab === 'admin' ? 'active' : ''} onClick={() => setActiveTab('admin')}>
            <Settings size={18} /> Admin
          </button>
          <div className="divider"></div>
          <button
            className={`nav-key-btn ${apiKey ? 'has-key' : ''}`}
            onClick={() => setShowKeyInput(!showKeyInput)}
            title={apiKey ? "Engine Key Active" : "Set Engine Key"}
          >
            <RotateCcw size={18} className={apiKey ? 'pulse-green' : ''} />
            <span>{apiKey ? 'API Active' : 'Set Key'}</span>
          </button>
          <button className="theme-toggle" onClick={toggleTheme} title="Toggle Theme">
            {theme === 'dark' ? <Sun size={20} /> : <Moon size={20} />}
          </button>
        </div>
        {showKeyInput && (
          <div className="global-key-overlay">
            <div className="key-modal glass-panel">
              <h3>Engine Access Credentials</h3>
              <p>Enter your CloudSecurityApp API key to unlock Pentesting and Admin capabilities.</p>
              <div className="modal-input-group">
                <input
                  type="password"
                  defaultValue={apiKey}
                  placeholder="ag_..."
                  id="global-api-key-input"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') saveApiKey(e.target.value)
                  }}
                />
                <button onClick={() => saveApiKey(document.getElementById('global-api-key-input').value)}>
                  Apply Key
                </button>
              </div>
              <button className="close-btn" onClick={() => setShowKeyInput(false)}>Close</button>
            </div>
          </div>
        )}
      </nav>

      <main className="content-area">
        {activeTab === 'welcome' && (
          <Welcome
            onStartAssessment={() => setActiveTab('waf')}
            onStartPentesting={() => setActiveTab('dast')}
          />
        )}

        {activeTab === 'waf' && (
          <div className="waf-panel glass-panel">
            <header className="panel-header">
              <div className="header-info">
                <h2>AWS Well-Architected Framework Assessment</h2>
                <div className="progress-container">
                  <div className="progress-bar" style={{ width: `${progress}%` }}></div>
                  <span className="progress-label">{progress}% Complete</span>
                </div>
              </div>
              <button
                className="btn-ghost"
                onClick={() => { setSessionId(null); setMessages([]); startSession(); }}
                title="Restart Session"
              >
                <RotateCcw size={18} />
              </button>
            </header>

            <div className="chat-area">
              {messages.map((msg, i) => (
                <div key={i} className={`message ${msg.role}`}>
                  <div className="bubble">
                    {msg.text}
                  </div>
                </div>
              ))}
              {loading && <div className="message bot"><div className="bubble typing">AI is analyzing...</div></div>}
              <div ref={chatEndRef} />
            </div>

            <div className="input-area">
              <div className="input-controls">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Describe your architecture or answer the question..."
                  onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
                  rows={2}
                />
                <button onClick={sendMessage} disabled={loading || !input.trim()}>
                  <Send size={18} />
                </button>
              </div>
              {progress >= 100 && (
                <div className="completion-panel">
                  <button className="download-btn" onClick={handleDownload}>
                    <Download size={18} /> Download Assessment Report
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
        {activeTab === 'dast' && <DastAnalyzer />}
        {activeTab === 'admin' && <AdminDashboard apiKey={apiKey} />}
      </main>
    </div>
  )
}

export default App
