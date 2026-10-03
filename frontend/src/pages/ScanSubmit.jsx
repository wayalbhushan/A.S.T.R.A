import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, FileText, AlertCircle, X, Shield, Zap, RefreshCw, CheckCircle2 } from 'lucide-react'
import { api } from '../api/client'

const MAX_UPLOAD_MB = Number(import.meta.env.VITE_MAX_UPLOAD_MB) || 150

export default function ScanSubmit() {
  const [file, setFile] = useState(null)
  const [scanType, setScanType] = useState('deep')
  const [forceRescan, setForceRescan] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)
  const [errorCode, setErrorCode] = useState(null)
  const [scanId, setScanId] = useState(null)
  const [pollStatus, setPollStatus] = useState(null)
  const [isDragging, setIsDragging] = useState(false)
  const pollRef = useRef(null)
  const startTimeRef = useRef(null)
  const navigate = useNavigate()

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  const resetForm = () => {
    stopPolling()
    setFile(null)
    setSubmitting(false)
    setError(null)
    setErrorCode(null)
    setScanId(null)
    setPollStatus(null)
    setForceRescan(false)
  }

  const validateAndSetFile = (f) => {
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.apk')) {
      setError('Invalid file type. Only Android Package (.apk) files are supported.')
      setErrorCode(null)
      setFile(null)
      return
    }
    const maxBytes = MAX_UPLOAD_MB * 1024 * 1024
    if (f.size > maxBytes) {
      const mb = (f.size / (1024 * 1024)).toFixed(1)
      setError(`This file is ${mb} MB. The maximum is ${MAX_UPLOAD_MB} MB.`)
      setErrorCode(null)
      setFile(null)
      return
    }
    setFile(f)
    setError(null)
    setErrorCode(null)
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
    stopPolling()
    setPollStatus('pending')
    startTimeRef.current = Date.now()

    pollRef.current = setInterval(async () => {
      // Stop polling after 6 minutes (360,000 ms)
      if (Date.now() - startTimeRef.current > 360000) {
        stopPolling()
        setSubmitting(false)
        setError('This is taking longer than expected. You can leave this page and open the scan from the dashboard.')
        return
      }

      try {
        const res = await api.getScanStatus(id)
        const data = res.data.data
        const status = data?.status
        setPollStatus(status)

        if (status === 'complete') {
          stopPolling()
          navigate(`/scan/${id}`)
        } else if (status === 'failed') {
          stopPolling()
          setSubmitting(false)
          setError(data?.error_message || 'Analysis failed.')
        }
      } catch (err) {
        stopPolling()
        setSubmitting(false)
        setError(err.friendlyMessage || 'Polling failed. Check your backend server connection.')
      }
    }, 5000)
  }

  const handleSubmit = async () => {
    if (!file) return
    setSubmitting(true)
    setError(null)

    const formData = new FormData()
    formData.append('file', file)
    formData.append('scan_type', scanType)
    if (forceRescan) {
      formData.append('force', 'true')
    }

    try {
      const res = await api.submitScan(formData)
      const data = res.data.data
      if (data?.cached === true) {
        navigate(`/scan/${data.scan_id}`)
        return
      }
      const id = data.scan_id
      setScanId(id)
      startPolling(id)
    } catch (err) {
      const status = err.response?.status
      let msg = ''
      if (err.friendlyMessage) {
        msg = err.friendlyMessage
      } else if (err.response?.data?.message) {
        msg = err.response.data.message
      } else if (status === 413) {
        msg = `File is too large. The maximum upload size is ${MAX_UPLOAD_MB} MB.`
      } else if (status === 429) {
        msg = 'Too many requests. Please wait and try again.'
      } else if (!err.response) {
        msg = 'Could not reach the server, or the upload was cut off. If the file is large, check its size and try again.'
      } else {
        msg = `Upload failed (HTTP ${status}).`
      }
      setError(msg)
      setErrorCode(status || null)
      setSubmitting(false)
    }
  }

  useEffect(() => {
    return () => {
      stopPolling()
    }
  }, [])

  const STATUS_LABELS = {
    pending: 'Queued - waiting for worker thread...',
    processing: 'Decompiling APK & running static/dynamic ML models...',
    complete: 'Analysis complete - redirecting to report...',
    failed: 'Analysis failed - please check worker logs.',
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
                Accepts standalone APK binaries up to {MAX_UPLOAD_MB} MB
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
              Static analysis, bank certificate check, indicator extraction, ML model and VirusTotal reputation. Usually under a minute.
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
              Everything in Quick plus the VirusTotal sandbox behaviour report. Usually under a minute if VirusTotal is available.
            </div>
          </div>
        </div>

        {/* Re-scan checkbox */}
        <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <input
            type="checkbox"
            id="force-rescan"
            checked={forceRescan}
            onChange={(e) => setForceRescan(e.target.checked)}
            disabled={submitting}
            style={{
              cursor: submitting ? 'not-allowed' : 'pointer',
              accentColor: 'var(--action-blue)',
            }}
          />
          <label
            htmlFor="force-rescan"
            style={{
              fontSize: '13px',
              color: 'var(--text-secondary)',
              cursor: submitting ? 'not-allowed' : 'pointer',
              userSelect: 'none',
            }}
          >
            Re-scan even if this file was analyzed before
          </label>
        </div>
      </div>

      {/* Error display */}
      {error && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '12px',
          padding: '14px 16px',
          background: 'var(--danger-bg)',
          border: '1px solid var(--danger)',
          marginBottom: '20px',
          color: 'var(--danger)',
          fontSize: '13px',
          flexWrap: 'wrap',
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
            <AlertCircle size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <span>{error}</span>
              {errorCode && (
                <div className="mono" style={{ fontSize: '11px', color: 'var(--text-placeholder)', marginTop: '4px' }}>
                  HTTP {errorCode}
                </div>
              )}
            </div>
          </div>
          {pollStatus === 'failed' && (
            <button
              type="button"
              className="btn-carbon-secondary"
              onClick={resetForm}
              style={{
                fontSize: '12px',
                padding: '4px 12px',
                border: '1px solid var(--danger)',
                color: 'var(--danger)',
                background: 'transparent',
                cursor: 'pointer',
              }}
            >
              Try another file
            </button>
          )}
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
