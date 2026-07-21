import { useState } from 'react'
import { Search, Link, AlertTriangle, ShieldAlert, Copy, Check, Filter } from 'lucide-react'
import { api } from '../api/client'
import VerdictBadge from '../components/VerdictBadge'
import StatCard from '../components/StatCard'

export default function Campaigns() {
  const [certHash, setCertHash] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [copiedHash, setCopiedHash] = useState(false)

  const handleSearch = async (hashToSearch) => {
    const targetHash = (hashToSearch || certHash).trim()
    if (!targetHash) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await api.getCertPivot(targetHash)
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

  const handleCopyHash = (text) => {
    navigator.clipboard.writeText(text)
    setCopiedHash(true)
    setTimeout(() => setCopiedHash(false), 2000)
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
    <div style={{ maxWidth: '960px' }}>
      {/* Header explanation */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '18px 20px',
        marginBottom: '24px',
        fontSize: '13px',
        color: 'var(--text-secondary)',
        lineHeight: 1.5,
      }}>
        <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
          Certificate-Based Campaign Threat Pivoting
        </div>
        This tool pivots the dataset to find all APK applications sharing the exact same signing certificate hash.
        Tracking shared developer signatures helps threat analysts identify common adversary campaigns, reused Android build infrastructure, and malware clusters.
      </div>

      {/* Search input */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '20px',
        marginBottom: '24px',
      }}>
        <div style={{
          fontSize: '11px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.4px',
          textTransform: 'uppercase',
          fontWeight: 600,
          marginBottom: '10px',
        }}>
          Search Certificate Signature (SHA-256)
        </div>

        <div style={{
          display: 'flex',
          gap: '8px',
        }}>
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', background: 'var(--bg-primary)', border: '1px solid var(--border)' }}>
            <input
              type="text"
              value={certHash}
              onChange={e => setCertHash(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSearch()}
              placeholder="e.g. 61ed377e85d386a8dfee6b864bd85b0baf55b124ac10a28c3e872ad9237e24a8..."
              style={{
                flex: 1,
                background: 'transparent',
                border: 'none',
                padding: '10px 14px',
                color: 'var(--text-primary)',
                fontFamily: 'IBM Plex Mono, monospace',
                fontSize: '12px',
                outline: 'none',
              }}
            />
          </div>

          <button
            className="btn-carbon"
            onClick={() => handleSearch()}
            disabled={loading || !certHash.trim()}
            style={{ padding: '10px 20px' }}
          >
            <Search size={16} />
            {loading ? 'Pivoting...' : 'Pivot Signature'}
          </button>
        </div>
      </div>

      {/* Loading & Error States */}
      {loading && (
        <div style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '24px', padding: '16px 0' }}>
          Querying certificate relationship graph...
        </div>
      )}

      {error && (
        <div style={{
          padding: '14px 16px',
          background: 'var(--danger-bg)',
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
              padding: '32px',
              textAlign: 'center',
              color: 'var(--text-placeholder)',
              fontSize: '14px',
            }}>
              No APK records found matching certificate signature <span className="mono">{certHash}</span>.
            </div>
          ) : (
            <div>
              {/* Stat panels */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '16px',
                marginBottom: '24px',
              }}>
                <StatCard
                  label="Associated APKs"
                  value={result.total_apks_scanned}
                  icon={Link}
                  subtitle="Applications sharing signature"
                />
                <StatCard
                  label="Malicious Artifacts"
                  value={result.malicious_count}
                  icon={AlertTriangle}
                  accent="var(--danger)"
                  subtitle="Flagged malicious apps"
                />
                <StatCard
                  label="Campaign Risk Level"
                  value={result.campaign_confidence || 'UNKNOWN'}
                  icon={ShieldAlert}
                  accent={getConfidenceColor(result.campaign_confidence)}
                  subtitle="Calculated threat actor pivot rating"
                />
              </div>

              {/* Connected apps table */}
              <div style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
              }}>
                <div style={{
                  padding: '14px 16px',
                  borderBottom: '1px solid var(--border)',
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  letterSpacing: '0.32px',
                  textTransform: 'uppercase',
                  fontWeight: 600,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}>
                  <span>Associated APK Scans ({result.apks.length})</span>

                  <button
                    className="btn-carbon-ghost"
                    onClick={() => handleCopyHash(certHash)}
                    style={{ fontSize: '11px' }}
                  >
                    {copiedHash ? (
                      <>
                        <Check size={12} color="var(--success)" />
                        <span style={{ color: 'var(--success)' }}>Cert Hash Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy size={12} />
                        <span>Copy Cert Hash</span>
                      </>
                    )}
                  </button>
                </div>

                <table className="carbon-table" style={{
                  width: '100%',
                  borderCollapse: 'collapse',
                }}>
                  <thead>
                    <tr>
                      {['File Name', 'Package Name', 'Verdict', 'Risk Score', 'Scanned Date'].map(h => (
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
                    {result.apks.map(apk => (
                      <tr
                        key={apk.scan_id}
                        style={{ borderBottom: '1px solid var(--border-subtle)' }}
                      >
                        <td className="mono" style={{
                          padding: '12px 16px',
                          fontSize: '13px',
                          fontWeight: 500,
                          color: 'var(--text-primary)',
                        }}>
                          {apk.file_name || '—'}
                        </td>
                        <td className="mono" style={{
                          padding: '12px 16px',
                          color: 'var(--text-secondary)',
                          fontSize: '12px',
                        }}>
                          {apk.package_name || '—'}
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <VerdictBadge verdict={apk.verdict} />
                        </td>
                        <td className="mono" style={{
                          padding: '12px 16px',
                          fontSize: '13px',
                          fontWeight: 600,
                          color: (apk.risk_score || 0) >= 70 ? 'var(--danger)' : (apk.risk_score || 0) >= 40 ? 'var(--warning)' : 'var(--success)',
                        }}>
                          {apk.risk_score ?? '—'}
                        </td>
                        <td style={{
                          padding: '12px 16px',
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
