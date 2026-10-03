import { useState } from 'react'
import { Download, Copy, Check, AlertCircle, FileText, ChevronRight } from 'lucide-react'
import { api } from '../api/client'

export default function TakedownPanel({ result }) {
  const isEligible =
    result?.verdict === 'MALICIOUS' ||
    result?.verdict === 'SUSPICIOUS' ||
    result?.impersonation?.verdict === 'IMPERSONATION'

  if (!isEligible) return null

  const [takedownData, setTakedownData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState(null)
  const [copiedKey, setCopiedKey] = useState(null)
  const [copyErrorKey, setCopyErrorKey] = useState(null)

  const scanId = result?.id || result?.scan_id

  const handlePreparePack = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.getTakedown(scanId)
      setTakedownData(res.data?.data)
    } catch (err) {
      setError(err.friendlyMessage || err.message || 'Failed to prepare takedown pack.')
    } finally {
      setLoading(false)
    }
  }

  const handleDownloadPdf = async () => {
    setDownloading(true)
    setError(null)
    try {
      const res = await api.downloadTakedownPdf(scanId)
      const blob = new Blob([res.data], { type: 'application/pdf' })
      const url = window.URL.createObjectURL(blob)
      const shortId = String(scanId || '').slice(0, 8) || 'scan'
      const link = document.createElement('a')
      link.href = url
      link.download = `astra-takedown-${shortId}.pdf`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch (err) {
      setError(err.friendlyMessage || err.message || 'Failed to download takedown PDF.')
    } finally {
      setDownloading(false)
    }
  }

  const handleCopyNotice = async (notice) => {
    try {
      const textToCopy = `${notice.subject || ''}\n\n${notice.body || ''}`
      await navigator.clipboard.writeText(textToCopy)
      setCopiedKey(notice.key)
      setTimeout(() => setCopiedKey(null), 2000)
    } catch {
      setCopyErrorKey(notice.key)
      setTimeout(() => setCopyErrorKey(null), 3000)
    }
  }

  const counts = takedownData?.indicators?.counts || {}
  const tgCount = counts.telegram_bots ?? 0
  const dcCount = counts.discord_webhooks ?? 0
  const fbCount = counts.firebase_projects ?? 0
  const strength = takedownData?.evidence_strength || 'PARTIAL'

  return (
    <div
      style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '16px',
        marginBottom: '16px',
      }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          marginBottom: '10px',
        }}
      >
        <div>
          <div
            style={{
              fontSize: '12px',
              textTransform: 'uppercase',
              fontWeight: 600,
              letterSpacing: '0.32px',
              color: 'var(--text-primary)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <FileText size={14} />
            TAKEDOWN EVIDENCE PACK
          </div>
          <div
            style={{
              fontSize: '12px',
              color: 'var(--text-secondary)',
              marginTop: '4px',
              lineHeight: '1.4',
            }}
          >
            Report texts and a PDF built from this scan. Review everything before sending. Contact channels are unverified until you confirm them.
          </div>
        </div>

        {!takedownData && (
          <button
            className="btn-carbon"
            onClick={handlePreparePack}
            disabled={loading}
            style={{
              fontSize: '13px',
              padding: '8px 16px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              borderRadius: '0px',
            }}
          >
            {loading ? 'Preparing...' : 'Prepare pack'}
          </button>
        )}
      </div>

      {/* Error Message Area */}
      {error && (
        <div
          style={{
            background: 'var(--danger-bg, #2d0709)',
            border: '1px solid var(--danger)',
            color: 'var(--danger)',
            padding: '10px 14px',
            fontSize: '12px',
            marginBottom: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <AlertCircle size={14} />
          {error}
        </div>
      )}

      {/* Loaded Pack Content */}
      {takedownData && (
        <div>
          {/* Summary and Download Bar */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
              padding: '10px 12px',
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border)',
              marginBottom: '14px',
            }}
          >
            <div style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
              <span
                style={{
                  fontWeight: 600,
                  color: strength === 'STRONG' ? 'var(--danger)' : 'var(--warning)',
                  marginRight: '8px',
                }}
              >
                {strength}
              </span>
              <span style={{ color: 'var(--text-secondary)' }}>
                Indicators found: {tgCount} Telegram bots, {dcCount} Discord webhooks, {fbCount} Firebase projects
              </span>
            </div>

            <button
              className="btn-carbon-secondary"
              onClick={handleDownloadPdf}
              disabled={downloading}
              style={{
                fontSize: '12px',
                padding: '6px 12px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                borderRadius: '0px',
              }}
            >
              <Download size={13} />
              {downloading ? 'Downloading...' : 'Download PDF'}
            </button>
          </div>

          {/* Notices Section */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {(takedownData.notices || []).map((notice) => (
              <details
                key={notice.key}
                style={{
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border)',
                  padding: '10px 12px',
                }}
              >
                <summary
                  style={{
                    cursor: 'pointer',
                    fontSize: '13px',
                    fontWeight: 600,
                    color: 'var(--text-primary)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    userSelect: 'none',
                  }}
                >
                  <span>{notice.label || notice.key}</span>
                  {!notice.verified && (
                    <span
                      style={{
                        background: 'var(--bg-primary)',
                        border: '1px solid var(--border)',
                        color: 'var(--text-secondary)',
                        fontSize: '10px',
                        fontWeight: 600,
                        padding: '2px 6px',
                        letterSpacing: '0.4px',
                        borderRadius: '0px',
                        textTransform: 'uppercase',
                      }}
                    >
                      UNVERIFIED CONTACT
                    </span>
                  )}
                </summary>

                <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div
                    style={{
                      fontFamily: 'IBM Plex Mono, monospace',
                      fontSize: '12px',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    Channel: {notice.channel}
                  </div>

                  <div
                    style={{
                      fontSize: '13px',
                      fontWeight: 600,
                      color: 'var(--text-primary)',
                    }}
                  >
                    Subject: {notice.subject}
                  </div>

                  <pre
                    style={{
                      fontFamily: 'IBM Plex Mono, monospace',
                      fontSize: '12px',
                      whiteSpace: 'pre-wrap',
                      color: 'var(--text-primary)',
                      background: 'var(--bg-primary)',
                      border: '1px solid var(--border)',
                      padding: '12px',
                      margin: '4px 0',
                      borderRadius: '0px',
                      lineHeight: '1.5',
                      overflowX: 'auto',
                    }}
                  >
                    {notice.body}
                  </pre>

                  <div>
                    <button
                      className="btn-carbon-secondary"
                      onClick={() => handleCopyNotice(notice)}
                      style={{
                        fontSize: '11px',
                        padding: '4px 10px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        borderRadius: '0px',
                      }}
                    >
                      {copiedKey === notice.key ? (
                        <>
                          <Check size={12} color="var(--success)" />
                          <span style={{ color: 'var(--success)' }}>Copied</span>
                        </>
                      ) : copyErrorKey === notice.key ? (
                        <span>Copy failed, select the text manually</span>
                      ) : (
                        <>
                          <Copy size={12} />
                          <span>Copy text</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </details>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
