import { useState, useEffect } from 'react'
import {
    Database, Upload, Trash2, FileText, Lock,
    Plus, AlertCircle, RefreshCw, FileType, CheckCircle
} from 'lucide-react'

const API_BASE = import.meta.env.VITE_API_BASE ? `${import.meta.env.VITE_API_BASE}/v1` : 'http://localhost:8000/api/v1'

function AdminDashboard({ apiKey }) {
    const [documents, setDocuments] = useState([])
    const [uploading, setUploading] = useState(false)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState('')

    useEffect(() => {
        if (apiKey) {
            fetchDocuments()
        }
    }, [apiKey])

    const fetchDocuments = async () => {
        setLoading(true)
        setError('')
        try {
            const response = await fetch(`${API_BASE}/rag/documents`, {
                headers: { 'x-api-key': apiKey }
            })
            if (!response.ok) throw new Error('Failed to fetch documents')
            const data = await response.json()
            setDocuments(data)
        } catch (err) {
            setError(err.message)
        }
        setLoading(false)
    }

    const handleFileUpload = async (e) => {
        const file = e.target.files[0]
        if (!file) return
        if (file.type !== 'application/pdf') {
            setError('Only PDF documents are supported for RAG ingestion.')
            return
        }

        setUploading(true)
        setError('')

        const formData = new FormData()
        formData.append('file', file)

        try {
            const response = await fetch(`${API_BASE}/rag/upload`, {
                method: 'POST',
                headers: { 'x-api-key': apiKey },
                body: formData
            })

            const data = await response.json()
            if (!response.ok) throw new Error(data.detail || 'Upload failed')

            await fetchDocuments()
        } catch (err) {
            setError(`Upload error: ${err.message}`)
        }
        setUploading(false)
        e.target.value = null
    }

    const handleDelete = async (docId) => {
        if (!window.confirm('Are you sure you want to remove this document from the knowledge base?')) return

        try {
            const response = await fetch(`${API_BASE}/rag/documents/${docId}`, {
                method: 'DELETE',
                headers: { 'x-api-key': apiKey }
            })
            if (!response.ok) throw new Error('Delete failed')
            await fetchDocuments()
        } catch (err) {
            setError(`Delete error: ${err.message}`)
        }
    }

    if (!apiKey) {
        return (
            <div className="auth-fallback glass-panel">
                <Lock size={48} className="lock-icon" />
                <h2>Knowledge Base Access Restricted</h2>
                <p>Unlock the engine with your API key using the "Set Key" button in the navigation bar.</p>
            </div>
        )
    }

    return (
        <div className="admin-dashboard">
            <div className="glass-panel main-settings">
                <header className="panel-header">
                    <div className="title-with-icon">
                        <Database size={20} className="accent-icon" />
                        <h2>RAG Knowledge Base</h2>
                    </div>
                    <button onClick={fetchDocuments} disabled={loading} className="btn-ghost">
                        <RefreshCw size={18} className={loading ? 'spin' : ''} />
                    </button>
                </header>

                <p className="description">
                    Populate the engine with reference architecture, compliance frameworks, and technical evidence.
                    The AI uses these documents for multi-layered WAF analysis.
                </p>

                {error && <div className="error-banner"><AlertCircle size={16} /> {error}</div>}

                <div className="upload-dropzone">
                    <input
                        type="file"
                        accept=".pdf"
                        onChange={handleFileUpload}
                        style={{ display: 'none' }}
                        id="rag-file-upload"
                        disabled={uploading}
                    />
                    <label htmlFor="rag-file-upload" className="upload-trigger">
                        {uploading ? <RefreshCw className="spin" size={24} /> : <Upload size={24} />}
                        <span>{uploading ? 'Processing Document...' : 'Select PDF to Ingest'}</span>
                        <p>Immediate vector embedding conversion</p>
                    </label>
                </div>
            </div>

            <div className="glass-panel doc-list-section">
                <div className="section-header">
                    <h3>Knowledge Assets ({documents.length})</h3>
                </div>

                {loading ? (
                    <div className="loading-state">
                        <RefreshCw size={32} className="spin" />
                        <p>Accessing knowledge repository...</p>
                    </div>
                ) : documents.length === 0 ? (
                    <div className="empty-state">
                        <FileType size={48} />
                        <p>No knowledge assets present. Upload architecture docs to enhance the AI assistant.</p>
                    </div>
                ) : (
                    <div className="doc-grid">
                        {documents.map((doc) => (
                            <div key={doc.id} className="doc-item">
                                <div className="doc-info">
                                    <div className="doc-icon">
                                        <FileText size={20} />
                                    </div>
                                    <div className="doc-meta">
                                        <span className="doc-name">{doc.filename}</span>
                                        <span className="doc-id">Reference ID: {doc.id.substring(0, 8)}</span>
                                    </div>
                                </div>
                                <div className="doc-actions">
                                    <div className="status-badge">
                                        <CheckCircle size={14} /> Indexed
                                    </div>
                                    <button
                                        onClick={() => handleDelete(doc.id)}
                                        className="delete-btn"
                                        title="Remove from KB"
                                    >
                                        <Trash2 size={16} />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    )
}

export default AdminDashboard
