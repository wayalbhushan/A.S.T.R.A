import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, FileText, AlertCircle } from 'lucide-react'
import { api } from '../api/client'

export default function ScanSubmit() {
  const [file, setFile] = useState(null)
  const [scanType, setScanType] = useState('deep')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const [scanId, setScanId] = useState(null)
  const [pollStatus, setPollStatus] = useState(null)
  const pollRef = useRef(null)
  const navigate = useNavigate()

  const handleFileChange = (e) => {
    const f = e.target.files[0]
    if (f) {
      if (f.name.toLowerCase().endsWith('.apk')) {
        setFile(f)
        setError(null)
      } else {
        setError('Only .apk files are accepted')
        setFile(null)
      }
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
        setError('Polling failed. Check your API server connection.')
      }
    }, 3000)
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
        'Submission failed. Make sure the backend server is running.'
      )
      setSubmitting(false)
    }
  }

  // Clear polling interval on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
      }
    }
  }, [])

  const STATUS_LABELS = {
    pending: 'Queued — waiting for worker',
    processing: 'Analyzing APK...',
    complete: 'Complete — redirecting...',
    failed: 'Analysis failed',
  }

  return (
    <div style={{ maxWidth: '600px', margin: '0' }}>

      {/* Upload zone */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '32px',
        marginBottom: '16px',
      }}>
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.32px',
          textTransform: 'uppercase',
          fontWeight: 600,
          marginBottom: '16px',
        }}>
          APK File
        </div>

        <label style={{
          display: 'block',
          border: '1px dashed var(--border)',
          padding: '24px',
          textAlign: 'center',
          cursor: 'pointer',
          background: 'var(--bg-primary)',
        }}>
          <input
            type="file"
            accept=".apk"
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
          {file ? (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
            }}>
              <FileText
                size={16}
                color='var(--action-blue)'
              />
              <span style={{
                fontFamily: 'IBM Plex Mono, monospace',
                fontSize: '13px',
                color: 'var(--text-primary)',
              }}>
                {file.name}
              </span>
              <span style={{
                fontSize: '12px',
                color: 'var(--text-secondary)',
              }}>
                ({(file.size / 1024 / 1024).toFixed(1)} MB)
              </span>
            </div>
          ) : (
            <div>
              <Upload
                size={20}
                color='var(--text-placeholder)'
                style={{ margin: '0 auto 8px' }}
              />
              <div style={{
                fontSize: '14px',
                color: 'var(--text-secondary)',
              }}>
                Click to select .apk file
              </div>
              <div style={{
                fontSize: '12px',
                color: 'var(--text-placeholder)',
                marginTop: '4px',
              }}>
                Maximum 50 MB
              </div>
            </div>
          )}
        </label>
      </div>

      {/* Scan type selector */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '16px',
        marginBottom: '16px',
      }}>
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.32px',
          textTransform: 'uppercase',
          fontWeight: 600,
          marginBottom: '12px',
        }}>
          Scan Type
        </div>
        <div style={{ display: 'flex', gap: '1px' }}>
          {['quick', 'deep'].map(type => (
            <button
              key={type}
              onClick={() => setScanType(type)}
              disabled={submitting}
              style={{
                flex: 1,
                padding: '10px',
                background: scanType === type
                  ? 'var(--action-blue)'
                  : 'var(--bg-elevated)',
                color: 'var(--text-primary)',
                border: 'none',
                cursor: submitting ? 'not-allowed' : 'pointer',
                fontSize: '13px',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.16px',
                fontFamily: 'IBM Plex Sans, sans-serif',
                borderRadius: '0px',
              }}
            >
              {type === 'quick' ? 'Quick Scan' : 'Deep Scan'}
            </button>
          ))}
        </div>
        <div style={{
          marginTop: '8px',
          fontSize: '12px',
          color: 'var(--text-placeholder)',
        }}>
          {scanType === 'quick'
            ? 'Static analysis + ML classification only'
            : 'Full pipeline: static + ML + VT sandbox + MITRE mapping'
          }
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '12px',
          background: 'rgba(218, 30, 40, 0.1)',
          border: '1px solid var(--danger)',
          marginBottom: '16px',
          color: 'var(--danger)',
          fontSize: '13px',
        }}>
          <AlertCircle size={14} />
          {error}
        </div>
      )}

      {/* Submit button */}
      {!scanId && (
        <button
          onClick={handleSubmit}
          disabled={!file || submitting}
          style={{
            width: '100%',
            padding: '12px',
            background: (!file || submitting)
              ? 'var(--bg-elevated)'
              : 'var(--action-blue)',
            color: (!file || submitting)
              ? 'var(--text-placeholder)'
              : '#fff',
            border: 'none',
            cursor: (!file || submitting) ? 'not-allowed' : 'pointer',
            fontSize: '14px',
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.16px',
            fontFamily: 'IBM Plex Sans, sans-serif',
            borderRadius: '0px',
          }}
        >
          {submitting ? 'Submitting...' : 'Submit for Analysis'}
        </button>
      )}

      {/* Poll status */}
      {scanId && (
        <div style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          padding: '16px',
        }}>
          <div style={{
            fontSize: '12px',
            color: 'var(--text-secondary)',
            letterSpacing: '0.32px',
            textTransform: 'uppercase',
            fontWeight: 600,
            marginBottom: '8px',
          }}>
            Scan Status
          </div>
          <div style={{
            fontFamily: 'IBM Plex Mono, monospace',
            fontSize: '12px',
            color: 'var(--text-placeholder)',
            marginBottom: '8px',
          }}>
            ID: {scanId}
          </div>
          <div style={{
            fontSize: '14px',
            color: pollStatus === 'failed'
              ? 'var(--danger)'
              : 'var(--text-primary)',
          }}>
            {STATUS_LABELS[pollStatus] || pollStatus}
          </div>
        </div>
      )}
    </div>
  )
}
