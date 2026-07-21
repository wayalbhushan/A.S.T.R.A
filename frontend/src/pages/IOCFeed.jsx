import { useEffect, useState } from 'react'
import { RefreshCw, Radio, Search, Copy, Check, Download } from 'lucide-react'
import { api } from '../api/client'

export default function IOCFeed() {
  const [feed, setFeed] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [copiedId, setCopiedId] = useState(null)

  const fetchFeed = () => {
    setLoading(true)
    setError(null)
    api.getIOCFeed(100)
      .then(res => setFeed(res.data.data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchFeed()
  }, [])

  const indicators = feed?.objects || []

  const filteredIndicators = indicators.filter(ind => {
    const q = searchQuery.toLowerCase()
    return (
      (ind.id || '').toLowerCase().includes(q) ||
      (ind.name || '').toLowerCase().includes(q) ||
      (ind.pattern || '').toLowerCase().includes(q) ||
      (ind.labels || []).some(l => l.toLowerCase().includes(q))
    )
  })

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const exportJSON = () => {
    if (!feed) return
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(feed, null, 2))
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute("href", dataStr)
    downloadAnchor.setAttribute("download", `astra_stix_ioc_feed_${Date.now()}.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  const truncate = (str, len = 24) => {
    if (!str) return '—'
    if (str.length <= len) return str
    return str.substring(0, len) + '...'
  }

  return (
    <div>
      {/* Header bar row */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '20px',
        flexWrap: 'wrap',
        gap: '12px',
      }}>
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.32px',
          textTransform: 'uppercase',
          fontWeight: 600,
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
        }}>
          <Radio size={16} color="var(--action-blue)" />
          STIX 2.1 Threat Intel · {loading ? '—' : `${filteredIndicators.length} Indicators`}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Search bar */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            padding: '4px 10px',
            gap: '6px',
            width: '240px',
          }}>
            <Search size={14} color="var(--text-placeholder)" />
            <input
              type="text"
              placeholder="Search IOCs or patterns..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: 'var(--text-primary)',
                fontSize: '12px',
                width: '100%',
                fontFamily: 'IBM Plex Sans, sans-serif',
              }}
            />
          </div>

          {/* Export STIX JSON */}
          <button
            className="btn-carbon-secondary"
            onClick={exportJSON}
            disabled={!feed || indicators.length === 0}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <Download size={13} />
            Export STIX JSON
          </button>

          {/* Refresh Feed */}
          <button
            className="btn-carbon-secondary"
            onClick={fetchFeed}
            disabled={loading}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Loading & Error States */}
      {loading && (
        <div style={{
          color: 'var(--text-secondary)',
          fontSize: '14px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '24px 0',
        }}>
          <RefreshCw size={16} className="animate-spin" color="var(--action-blue)" />
          Fetching STIX 2.1 threat feed...
        </div>
      )}

      {!loading && error && (
        <div style={{
          padding: '14px 16px',
          background: 'var(--danger-bg)',
          border: '1px solid var(--danger)',
          color: 'var(--danger)',
          fontSize: '13px',
          marginBottom: '24px',
        }}>
          Error loading threat feed: {error}
        </div>
      )}

      {/* Feed table */}
      {!loading && !error && (
        <div style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
        }}>
          <table className="carbon-table" style={{
            width: '100%',
            borderCollapse: 'collapse',
          }}>
            <thead>
              <tr>
                {['Indicator ID', 'File Name', 'SHA-256 Pattern', 'Labels', 'Created Date', 'Action'].map(h => (
                  <th key={h} style={{
                    padding: '10px 16px',
                    textAlign: 'left',
                    fontSize: '11px',
                    color: 'var(--text-secondary)',
                    letterSpacing: '0.32px',
                    textTransform: 'uppercase',
                    fontWeight: 600,
                    background: 'var(--bg-elevated)',
                    borderBottom: '1px solid var(--border)',
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredIndicators.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{
                    padding: '32px 16px',
                    color: 'var(--text-placeholder)',
                    textAlign: 'center',
                    fontSize: '13px',
                  }}>
                    {indicators.length === 0
                      ? 'No malicious indicators yet. Submit APKs to generate STIX 2.1 threat intelligence data.'
                      : 'No STIX indicators match your current search query.'}
                  </td>
                </tr>
              ) : (
                filteredIndicators.map(ind => (
                  <tr
                    key={ind.id}
                    style={{ borderBottom: '1px solid var(--border-subtle)' }}
                  >
                    <td className="mono" style={{
                      padding: '10px 16px',
                      fontSize: '11px',
                      color: 'var(--action-blue)',
                    }}>
                      {truncate(ind.id, 24)}
                    </td>
                    <td style={{
                      padding: '10px 16px',
                      fontSize: '13px',
                      color: 'var(--text-primary)',
                      fontWeight: 500,
                    }}>
                      {truncate(ind.name || 'Unknown APK', 24)}
                    </td>
                    <td className="mono" style={{
                      padding: '10px 16px',
                      fontSize: '11px',
                      color: 'var(--text-secondary)',
                    }}>
                      {truncate(ind.pattern, 36)}
                    </td>
                    <td style={{ padding: '10px 16px' }}>
                      <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                        {(ind.labels || []).map((label, idx) => (
                          <span
                            key={idx}
                            style={{
                              background: 'var(--tag-bg)',
                              color: 'var(--text-secondary)',
                              padding: '2px 6px',
                              fontSize: '10px',
                              fontWeight: 600,
                              textTransform: 'uppercase',
                              border: '1px solid var(--border-subtle)',
                              fontFamily: 'IBM Plex Sans, sans-serif'
                            }}
                          >
                            {label}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td style={{
                      padding: '10px 16px',
                      color: 'var(--text-secondary)',
                      fontSize: '12px',
                    }}>
                      {new Date(ind.created).toLocaleString()}
                    </td>
                    <td style={{ padding: '10px 16px' }}>
                      <button
                        className="btn-carbon-ghost"
                        onClick={() => copyToClipboard(ind.pattern, ind.id)}
                        title="Copy pattern to clipboard"
                        style={{ padding: '4px 8px' }}
                      >
                        {copiedId === ind.id ? (
                          <>
                            <Check size={12} color="var(--success)" />
                            <span style={{ color: 'var(--success)', fontSize: '11px' }}>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy size={12} />
                            <span style={{ fontSize: '11px' }}>Copy</span>
                          </>
                        )}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
