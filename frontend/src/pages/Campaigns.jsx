import { useState } from 'react'
import { Search, Link, AlertTriangle, ShieldAlert } from 'lucide-react'
import { api } from '../api/client'
import VerdictBadge from '../components/VerdictBadge'
import StatCard from '../components/StatCard'

export default function Campaigns() {
  const [certHash, setCertHash] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleSearch = async () => {
    if (!certHash.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await api.getCertPivot(certHash.trim())
      setResult(res.data.data)
    } catch (err) {
      setError(
        err.response?.data?.message ||
        'Lookup failed. Ensure the search value is a valid SHA-256 certificate hash.'
      )
    } finally {
      setLoading(false)
    }
  }

  const getConfidenceColor = (conf) => {
    switch (conf) {
      case 'HIGH': return 'var(--danger)'
      case 'MEDIUM': return 'var(--warning)'
      case 'LOW': return 'var(--success)'
      default: return 'var(--text-placeholder)'
    }
  }

  return (
    <div style={{ maxWidth: '900px' }}>
      {/* Header explanation */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '16px',
        marginBottom: '24px',
        fontSize: '13px',
        color: 'var(--text-secondary)',
        lineHeight: 1.5,
      }}>
        This tool pivots the dataset to find all APK applications sharing the same signing certificate hash.
        Tracking shared signatures helps analysts identify common threat actors, reused build environments, and distributed malware campaigns.
      </div>

      {/* Search input */}
      <div style={{
        display: 'flex',
        gap: '1px',
        marginBottom: '24px',
        background: 'var(--border)',
        padding: '1px'
      }}>
        <input
          type="text"
          value={certHash}
          onChange={e => setCertHash(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
          placeholder="Enter certificate SHA-256 hash..."
          style={{
            flex: 1,
            background: 'var(--bg-elevated)',
            border: 'none',
            borderRadius: '0px',
            padding: '10px 12px',
            color: 'var(--text-primary)',
            fontFamily: 'IBM Plex Mono, monospace',
            fontSize: '13px',
            outline: 'none',
          }}
        />
        <button
          onClick={handleSearch}
          disabled={loading}
          style={{
            padding: '10px 16px',
            background: 'var(--action-blue)',
            color: '#fff',
            border: 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '14px',
            fontWeight: 600,
            borderRadius: '0px',
          }}
        >
          <Search size={16} color="#fff" />
          {loading ? 'Searching...' : 'Search'}
        </button>
      </div>

      {/* Loading & Error States */}
      {loading && (
        <div style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '24px' }}>
          Searching certificate records...
        </div>
      )}

      {error && (
        <div style={{
          padding: '12px',
          background: 'rgba(218, 30, 40, 0.1)',
          border: '1px solid var(--danger)',
          color: 'var(--danger)',
          fontSize: '13px',
          marginBottom: '24px',
        }}>
          {error}
        </div>
      )}

      {/* Results details */}
      {result && (
        <div>
          {result.total_apks_scanned === 0 ? (
            <div style={{
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              padding: '24px',
              textAlign: 'center',
              color: 'var(--text-placeholder)',
            }}>
              No results for this certificate hash
            </div>
          ) : (
            <div>
              {/* Stat panels */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '1px',
                marginBottom: '24px',
                background: 'var(--border)',
              }}>
                <StatCard
                  label="Total APKs"
                  value={result.total_apks_scanned}
                  icon={Link}
                />
                <StatCard
                  label="Malicious Count"
                  value={result.malicious_count}
                  icon={AlertTriangle}
                  accent="var(--danger)"
                />
                <StatCard
                  label="Campaign Confidence"
                  value={result.campaign_confidence || 'NO DATA'}
                  icon={ShieldAlert}
                  accent={getConfidenceColor(result.campaign_confidence)}
                />
              </div>

              {/* Connected apps table */}
              <div style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
              }}>
                <div style={{
                  padding: '12px 16px',
                  borderBottom: '1px solid var(--border)',
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  letterSpacing: '0.32px',
                  textTransform: 'uppercase',
                  fontWeight: 600,
                }}>
                  Associated Scans
                </div>

                <table style={{
                  width: '100%',
                  borderCollapse: 'collapse',
                }}>
                  <thead>
                    <tr>
                      {['File Name', 'Package', 'Verdict', 'Risk Score', 'Scanned Date'].map(h => (
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
                    {result.apks.map(apk => (
                      <tr
                        key={apk.scan_id}
                        style={{ borderBottom: '1px solid var(--border-subtle)' }}
                      >
                        <td className="mono" style={{
                          padding: '10px 16px',
                          fontSize: '13px',
                          color: 'var(--text-primary)',
                        }}>
                          {apk.file_name || '—'}
                        </td>
                        <td style={{
                          padding: '10px 16px',
                          color: 'var(--text-secondary)',
                          fontSize: '13px',
                        }}>
                          {apk.package_name || '—'}
                        </td>
                        <td style={{ padding: '10px 16px' }}>
                          <VerdictBadge verdict={apk.verdict} />
                        </td>
                        <td className="mono" style={{
                          padding: '10px 16px',
                          fontSize: '13px',
                          color: 'var(--text-primary)',
                        }}>
                          {apk.risk_score ?? '—'}
                        </td>
                        <td style={{
                          padding: '10px 16px',
                          color: 'var(--text-secondary)',
                          fontSize: '12px',
                        }}>
                          {new Date(apk.scanned_at).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
