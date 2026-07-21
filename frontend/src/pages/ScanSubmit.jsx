import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, FileText, AlertCircle, X, Shield, Zap, RefreshCw, CheckCircle2 } from 'lucide-react'
import { api } from '../api/client'

export default function ScanSubmit() {
  const [file, setFile] = useState(null)
  const [scanType, setScanType] = useState('deep')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const [scanId, setScanId] = useState(null)
  const [pollStatus, setPollStatus] = useState(null)
  const [isDragging, setIsDragging] = useState(false)
  const pollRef = useRef(null)
  const navigate = useNavigate()

  const validateAndSetFile = (f) => {
    if (!f) return
    if (f.name.toLowerCase().endsWith('.apk')) {
      setFile(f)
      setError(null)
    } else {
      setError('Invalid file type. Only Android Package (.apk) files are supported.')
      setFile(null)
    }
  }

  const handleFileChange = (e) => {
    const f = e.target.files[0]
    validateAndSetFile(f)
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSetFile(e.dataTransfer.files[0])
    }
  }

  const startPolling = (id) => {
    setPollStatus('pending')
    pollRef.current = setInterval(async () => {
      try {
        const res = await api.getScanStatus(id)
        const status = res.data.data.status
        setPollStatus(status)
        if (status === 'complete' || status === 'failed') {
          clearInterval(pollRef.current)
          if (status === 'complete') {
            navigate(`/scan/${id}`)
          }
        }
      } catch {
        clearInterval(pollRef.current)
        setError('Polling failed. Check your backend server connection.')
      }
    }, 4000)
  }

  const handleSubmit = async () => {
    if (!file) return
    setSubmitting(true)
    setError(null)

    const formData = new FormData()
    formData.append('file', file)
    formData.append('scan_type', scanType)

    try {
      const res = await api.submitScan(formData)
      const id = res.data.data.scan_id
      setScanId(id)
      startPolling(id)
    } catch (err) {
      setError(
        err.response?.data?.message || 
        'Submission failed. Make sure the backend API server is running.'
      )
      setSubmitting(false)
    }
  }

  useEffect(() => {
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
      }
    }
  }, [])

  const STATUS_LABELS = {
    pending: 'Queued — waiting for worker thread...',
    processing: 'Decompiling APK & running static/dynamic ML models...',
    complete: 'Analysis complete — redirecting to report...',
    failed: 'Analysis failed — please check worker logs.',
  }

  return (
    <div style={{ maxWidth: '680px', margin: '0' }}>

      {/* Upload zone */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '24px',
        marginBottom: '20px',
      }}>
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.32px',
          textTransform: 'uppercase',
          fontWeight: 600,
          marginBottom: '14px',
        }}>
          1. Select APK Package
        </div>

        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          style={{
            border: isDragging ? '2px dashed var(--action-blue)' : '1px dashed var(--border)',
            padding: '36px 24px',
            textAlign: 'center',
            background: isDragging ? 'var(--bg-elevated)' : 'var(--bg-primary)',
            transition: 'all 0.15s ease',
            cursor: 'pointer',
            position: 'relative',
          }}
        >
          <input
            type="file"
            accept=".apk"
            onChange={handleFileChange}
            disabled={submitting}
            style={{
              position: 'absolute',
              top: 0, left: 0, width: '100%', height: '100%',
              opacity: 0, cursor: submitting ? 'not-allowed' : 'pointer',
            }}
          />
          
          {file ? (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '12px',
              position: 'relative',
              zIndex: 2,
            }}>
              <FileText size={24} color='var(--action-blue)' />
              <div style={{ textAlign: 'left' }}>
                <div className="mono" style={{
                  fontSize: '14px',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                }}>
                  {file.name}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Size: {(file.size / 1024 / 1024).toFixed(2)} MB · Format: Android Application Package
                </div>
              </div>
              
              {!submitting && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation()
                    setFile(null)
                  }}
                  style={{
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-secondary)',
                    padding: '4px',
                    cursor: 'pointer',
                    marginLeft: '12px',
                  }}
                >
                  <X size={16} />
                </button>
              )}
            </div>
          ) : (
            <div>
              <Upload
                size={28}
                color={isDragging ? 'var(--action-blue)' : 'var(--text-placeholder)'}
                style={{ margin: '0 auto 12px' }}
              />
              <div style={{
                fontSize: '14px',
                fontWeight: 600,
                color: 'var(--text-primary)',
              }}>
                {isDragging ? 'Drop .apk file here' : 'Drag & drop your .apk file here, or click to browse'}
              </div>
              <div style={{
                fontSize: '12px',
                color: 'var(--text-placeholder)',
                marginTop: '6px',
              }}>
                Accepts standalone APK binaries up to 50 MB
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Scan type selector */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '24px',
        marginBottom: '20px',
      }}>
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.32px',
          textTransform: 'uppercase',
          fontWeight: 600,
          marginBottom: '14px',
        }}>
          2. Choose Pipeline Profile
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <div
            onClick={() => !submitting && setScanType('quick')}
            style={{
              padding: '16px',
              border: scanType === 'quick' ? '2px solid var(--action-blue)' : '1px solid var(--border)',
              background: scanType === 'quick' ? 'var(--bg-elevated)' : 'var(--bg-primary)',
              cursor: submitting ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <Zap size={18} color={scanType === 'quick' ? 'var(--action-blue)' : 'var(--text-secondary)'} />
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>Quick Scan</span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
              Decompilation + DEX string extraction + Static ML model classification. Fast (< 5s).
            </div>
          </div>

          <div
            onClick={() => !submitting && setScanType('deep')}
            style={{
              padding: '16px',
              border: scanType === 'deep' ? '2px solid var(--action-blue)' : '1px solid var(--border)',
              background: scanType === 'deep' ? 'var(--bg-elevated)' : 'var(--bg-primary)',
              cursor: submitting ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <Shield size={18} color={scanType === 'deep' ? 'var(--action-blue)' : 'var(--text-secondary)'} />
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>Deep Scan</span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
              Full pipeline: Static ML + Dynamic ML + VirusTotal lookup + MITRE technique mapping.
            </div>
          </div>
        </div>
      </div>

      {/* Error display */}
      {error && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '14px 16px',
          background: 'var(--danger-bg)',
          border: '1px solid var(--danger)',
          marginBottom: '20px',
          color: 'var(--danger)',
          fontSize: '13px',
        }}>
          <AlertCircle size={18} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      {/* Submit button */}
      {!scanId && (
        <button
          className="btn-carbon"
          onClick={handleSubmit}
          disabled={!file || submitting}
          style={{
            width: '100%',
            justifyContent: 'center',
            padding: '14px',
            fontSize: '14px',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
            opacity: (!file || submitting) ? 0.6 : 1,
            cursor: (!file || submitting) ? 'not-allowed' : 'pointer',
          }}
        >
          {submitting ? (
            <>
              <RefreshCw size={16} className="animate-spin" />
              Submitting Package to Analysis Queue...
            </>
          ) : (
            'Launch Automated Scan'
          )}
        </button>
      )}

      {/* Live Polling Status */}
      {scanId && (
        <div style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--action-blue)',
          padding: '20px',
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '12px',
          }}>
            <div style={{
              fontSize: '12px',
              color: 'var(--action-blue)',
              letterSpacing: '0.32px',
              textTransform: 'uppercase',
              fontWeight: 600,
            }}>
              Analysis Task Running
            </div>
            <span className="pulse-dot" />
          </div>
          
          <div className="mono" style={{
            fontSize: '12px',
            color: 'var(--text-secondary)',
            marginBottom: '12px',
            background: 'var(--bg-primary)',
            padding: '6px 10px',
            border: '1px solid var(--border-subtle)',
          }}>
            Task ID: {scanId}
          </div>

          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontSize: '14px',
            color: pollStatus === 'failed' ? 'var(--danger)' : 'var(--text-primary)',
            fontWeight: 500,
          }}>
            {pollStatus === 'processing' || pollStatus === 'pending' ? (
              <RefreshCw size={16} className="animate-spin" color="var(--action-blue)" />
            ) : pollStatus === 'complete' ? (
              <CheckCircle2 size={16} color="var(--success)" />
            ) : null}
            {STATUS_LABELS[pollStatus] || pollStatus}
          </div>
        </div>
      )}
    </div>
  )
}
