import { useState, useRef, useEffect } from 'react'
import {
    Upload, RefreshCw, BarChart3, HelpCircle, Wrench,
    Terminal, ShieldAlert, FileSearch, CheckCircle2, AlertCircle,
    Lock, Send
} from 'lucide-react'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000/api'

function DastAnalyzer() {
    const [file, setFile] = useState(null)
    const [scannerType, setScannerType] = useState('OWASP_ZAP')
    const [environment, setEnvironment] = useState('production')
    const [uploading, setUploading] = useState(false)
    const [vulns, setVulns] = useState([])
    const [selectedVuln, setSelectedVuln] = useState(null)
    const [loadingVulns, setLoadingVulns] = useState(false)
    const [error, setError] = useState(null)

    const [chatMessages, setChatMessages] = useState([])
    const [aiThinking, setAiThinking] = useState(false)
    const [userInput, setUserInput] = useState('')
    const chatEndRef = useRef(null)
    const chatInputRef = useRef(null)

    // Initial Fetch
    useEffect(() => {
        fetchVulns()
    }, [])

    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [chatMessages])

    const handleFileChange = (e) => {
        if (e.target.files) {
            setFile(e.target.files[0])
            setError(null)
        }
    }

    const handleUpload = async () => {
        if (!file) return
        setUploading(true)
        setError(null)

        const formData = new FormData()
        formData.append('file', file)
        formData.append('scanner_source', scannerType)
        formData.append('environment', environment)

        try {
            const res = await fetch(`${API_BASE}/v1/scans/ingest`, {
                method: 'POST',
                body: formData
            })
            const data = await res.json()

            if (res.ok) {
                addChatMessage('bot', `Successfully ingested ${data.findings_count} findings from ${file.name}.`)
                await fetchVulns()
            } else {
                setError(data.detail || "Upload failed")
            }
        } catch (e) {
            setError("Network error during upload.")
        }
        setUploading(false)
    }

    const fetchVulns = async () => {
        setLoadingVulns(true)
        try {
            const res = await fetch(`${API_BASE}/v1/vulnerabilities`)
            if (!res.ok) throw new Error("Failed to load findings")
            const data = await res.json()
            setVulns(data)
        } catch (e) {
            setError("Authentication failed or backend unreachable.")
        }
        setLoadingVulns(false)
    }

    const addChatMessage = (role, text) => {
        setChatMessages(prev => [...prev, { role, text }])
    }

    const handleSummarize = async () => {
        if (vulns.length === 0) return
        setAiThinking(true)
        addChatMessage('user', "Please summarize these findings.")
        try {
            const res = await fetch(`${API_BASE}/v1/analysis/summarize`, {
                method: 'POST'
            })
            const data = await res.json()
            addChatMessage('bot', data.summary)
        } catch (e) {
            addChatMessage('bot', "Error generating summary.")
        }
        setAiThinking(false)
    }

    const handleClarify = async () => {
        if (vulns.length === 0) return
        setAiThinking(true)
        addChatMessage('user', "What clarifying questions do you have?")
        try {
            const res = await fetch(`${API_BASE}/v1/context/clarify`, {
                method: 'POST'
            })
            const data = await res.json()
            addChatMessage('bot', data.questions)
        } catch (e) {
            addChatMessage('bot', "Error generating questions.")
        }
        setAiThinking(false)
    }

    const handleRemediation = async (vuln) => {
        if (!vuln) return
        setAiThinking(true)
        addChatMessage('user', `How do I fix: ${vuln.title}?`)
        try {
            const res = await fetch(`${API_BASE}/v1/analysis/remediation?vulnerability_id=${vuln.id}`, {
                method: 'POST'
            })
            const data = await res.json()
            addChatMessage('bot', data.remediation)
        } catch (e) {
            addChatMessage('bot', "Error generating remediation.")
        }
        setAiThinking(false)
    }

    const handleChat = async (e) => {
        e?.preventDefault()
        if (!userInput.trim() || aiThinking) return

        const message = userInput.trim()
        setUserInput('')
        addChatMessage('user', message)
        setAiThinking(true)

        try {
            const res = await fetch(`${API_BASE}/v1/analysis/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: message,
                    history: chatMessages.slice(-10).map(m => ({ role: m.role, content: m.text }))
                })
            })
            const data = await res.json()
            if (res.ok) {
                addChatMessage('bot', data.response)
            } else {
                addChatMessage('bot', "I'm having trouble connecting to the engine.")
            }
        } catch (e) {
            addChatMessage('bot', "Network error. Please check backend status.")
        }
        setAiThinking(false)
    }

    return (
        <div className="dast-container">
            <div className="left-panel">
                <header className="panel-header">
                    <div className="title-with-icon">
                        <Terminal size={20} className="accent-icon" />
                        <h2>Cloud Pentesting Orchestrator</h2>
                    </div>
                </header>

                <div className="control-card upload-card">
                    <div className="form-group">
                        <label>Scanner Source</label>
                        <select value={scannerType} onChange={(e) => setScannerType(e.target.value)}>
                            <optgroup label="Cloud & Infrastructure">
                                <option value="ScoutSuite">ScoutSuite</option>
                                <option value="Prowler">Prowler</option>
                                <option value="CloudSploit">CloudSploit</option>
                                <option value="Amazon_Inspector">Amazon Inspector</option>
                                <option value="Qualys_Cloud_Platform">Qualys Cloud</option>
                            </optgroup>
                            <optgroup label="Web & API">
                                <option value="OWASP_ZAP">OWASP ZAP</option>
                                <option value="Burp_Suite">Burp Suite</option>
                                <option value="Nuclei">Nuclei</option>
                                <option value="StackHawk">StackHawk</option>
                            </optgroup>
                            <optgroup label="Containers & K8s">
                                <option value="Trivy">Trivy</option>
                                <option value="Kube_hunter">Kube-hunter</option>
                                <option value="Kubescape">Kubescape</option>
                            </optgroup>
                        </select>
                    </div>

                    <div className="form-group">
                        <label>Environment</label>
                        <select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
                            <option value="production">Production</option>
                            <option value="staging">Staging</option>
                            <option value="dev">Development</option>
                        </select>
                    </div>

                    <div className="form-group file-field">
                        <input type="file" id="file-upload" onChange={handleFileChange} accept=".json,.xml" className="hidden-file" style={{ display: 'none' }} />
                        <label htmlFor="file-upload" className="btn-ghost" style={{ cursor: 'pointer' }}>
                            <Upload size={16} />
                            {file ? file.name : 'Choose Scan File'}
                        </label>
                    </div>

                    <button className="primary-btn" onClick={handleUpload} disabled={uploading || !file}>
                        {uploading ? <RefreshCw className="spin" size={18} /> : <CheckCircle2 size={18} />}
                        <span>{uploading ? 'Processing...' : 'Ingest Scan'}</span>
                    </button>
                </div>

                {error && <div className="error-banner"><AlertCircle size={16} /> {error}</div>}

                <div className="findings-list">
                    <div className="section-header">
                        <h3>Vulnerability Findings ({vulns.length})</h3>
                        <button onClick={fetchVulns} disabled={loadingVulns} className="btn-ghost">
                            <RefreshCw size={16} className={loadingVulns ? 'spin' : ''} />
                            <span>Sync</span>
                        </button>
                    </div>

                    <div className="triage-tools">
                        <button onClick={handleSummarize} className="tool-btn" disabled={vulns.length === 0}>
                            <BarChart3 size={16} /> Summarize Results
                        </button>
                        <button onClick={handleClarify} className="tool-btn" disabled={vulns.length === 0}>
                            <HelpCircle size={16} /> Gap Analysis
                        </button>
                    </div>

                    <div className="vuln-table-container">
                        <table className="vuln-table">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Finding Details</th>
                                    <th>Score</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {vulns.length === 0 ? (
                                    <tr>
                                        <td colSpan="4">
                                            <div className="empty-state">
                                                {loadingVulns ? <RefreshCw className="spin" size={32} /> : <FileSearch size={32} />}
                                                <p>{loadingVulns ? 'Accessing records...' : 'No findings detected in the current environment.'}</p>
                                            </div>
                                        </td>
                                    </tr>
                                ) : (
                                    vulns.map((v) => (
                                        <tr key={v.id} onClick={() => setSelectedVuln(v)} className={selectedVuln?.id === v.id ? 'selected' : ''}>
                                            <td><span className={`severity-tag ${v.severity}`}>{v.severity}</span></td>
                                            <td className="vuln-title">{v.title}</td>
                                            <td><span className="priority-value">{v.priority_score?.toFixed(0) || 0}</span></td>
                                            <td>
                                                <button className="icon-btn" onClick={(e) => { e.stopPropagation(); handleRemediation(v); }} title="Analyze with AI">
                                                    <ShieldAlert size={16} />
                                                </button>
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div className="right-panel">
                <header className="panel-header">
                    <div className="title-with-icon">
                        <ShieldAlert size={20} className="accent-icon" />
                        <h2>AI Security Analyst</h2>
                    </div>
                </header>
                <div className="chat-window">
                    {chatMessages.length === 0 && (
                        <div className="empty-chat">
                            <FileSearch size={48} />
                            <p>Awaiting scan ingestion to begin automated analysis.</p>
                        </div>
                    )}
                    {chatMessages.map((msg, i) => (
                        <div key={i} className={`chat-msg ${msg.role}`}>
                            <div className="msg-content">
                                {msg.text ? (
                                    msg.text.split('\n').map((line, idx) => <p key={idx}>{line}</p>)
                                ) : (
                                    <p>...</p>
                                )}
                            </div>
                        </div>
                    ))}
                    {aiThinking && <div className="chat-msg bot"><div className="msg-content"><i>Synthesizing countermeasures...</i></div></div>}
                    <div ref={chatEndRef} />
                </div>
                <form className="chat-input-area" onSubmit={handleChat}>
                    <input
                        type="text"
                        placeholder="Ask the security assistant..."
                        value={userInput}
                        onChange={(e) => setUserInput(e.target.value)}
                        disabled={aiThinking}
                    />
                    <button type="submit" className="send-btn" disabled={aiThinking || !userInput.trim()}>
                        <Send size={18} />
                    </button>
                </form>
            </div>
        </div>
    )
}

export default DastAnalyzer
