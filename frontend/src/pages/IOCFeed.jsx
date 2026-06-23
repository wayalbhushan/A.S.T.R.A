import { useEffect, useState } from 'react'
import { RefreshCw, Radio } from 'lucide-react'
import { api } from '../api/client'

export default function IOCFeed() {
  const [feed, setFeed] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

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

  // Truncation Helper
  const truncate = (str, len = 20) => {
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
          <Radio size={16} />
          STIX 2.1 Format · {loading ? '—' : indicators.length} Indicators
        </div>
        <button
          onClick={fetchFeed}
          disabled={loading}
          style={{
            background: 'transparent',
            border: '1px solid var(--border)',
            color: 'var(--text-primary)',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            borderRadius: '0px',
          }}
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          Refresh Feed
        </button>
      </div>

      {/* Loading & Error States */}
      {loading && (
        <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
          Loading threat intelligence indicators...
        </div>
      )}

      {!loading && error && (
        <div style={{
          padding: '12px',
          background: 'rgba(218, 30, 40, 0.1)',
          border: '1px solid var(--danger)',
          color: 'var(--danger)',
          fontSize: '13px',
          marginBottom: '24px',
        }}>
          Error: {error}
        </div>
      )}

      {/* Feed table */}
      {!loading && !error && (
        <div style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
        }}>
          <table style={{
            width: '100%',
            borderCollapse: 'collapse',
          }}>
            <thead>
              <tr>
                {['Indicator ID', 'File Name', 'SHA-256 Pattern', 'Labels', 'Created Date'].map(h => (
                  <th key={h} style={{
                    padding: '10px 16px',
                    textAlign: 'left',
                    fontSize: '12px',
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
              {indicators.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{
                    padding: '24px 16px',
                    color: 'var(--text-placeholder)',
                    textAlign: 'center',
                  }}>
                    No malicious indicators yet. Submit APKs to generate threat intelligence data.
                  </td>
                </tr>
              ) : (
                indicators.map(ind => (
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
                    }}>
                      {truncate(ind.name || 'Unknown APK', 24)}
                    </td>
                    <td className="mono" style={{
                      padding: '10px 16px',
                      fontSize: '11px',
                      color: 'var(--text-secondary)',
                    }}>
                      {truncate(ind.pattern, 40)}
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
                              borderRadius: '0px',
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
