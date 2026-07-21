import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Activity, Database, Shield, Search, Plus, Filter, RefreshCw
} from 'lucide-react'
import { api } from '../api/client'
import StatCard from '../components/StatCard'
import VerdictBadge from '../components/VerdictBadge'

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [verdictFilter, setVerdictFilter] = useState('ALL')
  const navigate = useNavigate()

  const fetchStats = () => {
    setLoading(true)
    api.getStats()
      .then(res => setStats(res.data.data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchStats()
  }, [])

  if (loading && !stats) return (
    <div style={{
      color: 'var(--text-secondary)',
      fontSize: '14px',
      padding: '24px 0',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
    }}>
      <RefreshCw size={16} className="animate-spin" />
      Loading Security Dashboard Metrics...
    </div>
  )

  if (error) return (
    <div style={{
      background: 'var(--danger-bg)',
      border: '1px solid var(--danger)',
      padding: '16px',
      color: 'var(--danger)',
      fontSize: '14px',
    }}>
      Error loading dashboard: {error}
    </div>
  )

  const recentScans = stats?.recent_scans || []
  
  const filteredScans = recentScans.filter(scan => {
    const matchesSearch = 
      (scan.file_name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (scan.package_name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (scan.scan_id || '').toLowerCase().includes(searchQuery.toLowerCase())
    
    if (verdictFilter === 'ALL') return matchesSearch
    return matchesSearch && String(scan.verdict).toUpperCase() === verdictFilter
  })

  return (
    <div>
      {/* Stat cards grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '16px',
        marginBottom: '24px',
      }}>
        <StatCard
          label="Total Scans Processed"
          value={stats?.total_scans}
          icon={Activity}
          subtitle="Lifetime static & dynamic scans"
        />
        <StatCard
          label="Malicious APKs"
          value={stats?.malicious_count}
          icon={AlertTriangle}
          accent='var(--danger)'
          subtitle="Flagged by ML & threat signals"
        />
        <StatCard
          label="Detection Accuracy Rate"
          value={`${stats?.detection_rate_percent}%`}
          icon={Shield}
          accent='var(--warning)'
          subtitle="Combined signal confidence"
        />
        <StatCard
          label="Tracked Signature Certs"
          value={stats?.certificates_tracked}
          icon={Database}
          subtitle="Known developer signatures"
        />
      </div>

      {/* Recent scans section */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
      }}>
        {/* Section Action Bar */}
        <div style={{
          padding: '12px 16px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          background: 'var(--bg-secondary)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{
              fontSize: '12px',
              color: 'var(--text-secondary)',
              letterSpacing: '0.32px',
              textTransform: 'uppercase',
              fontWeight: 600,
            }}>
              Recent Analysis Activity
            </span>
            <span style={{
              fontSize: '11px',
              fontFamily: 'IBM Plex Mono, monospace',
              color: 'var(--text-placeholder)',
              background: 'var(--bg-elevated)',
              padding: '2px 6px',
            }}>
              {filteredScans.length} of {recentScans.length}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {/* Search Input */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              background: 'var(--bg-primary)',
              border: '1px solid var(--border)',
              padding: '4px 10px',
              gap: '6px',
              width: '220px',
            }}>
              <Search size={14} color="var(--text-placeholder)" />
              <input
                type="text"
                placeholder="Filter by file or package..."
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

            {/* Verdict Filter Pills */}
            <div style={{ display: 'flex', gap: '2px', background: 'var(--bg-primary)', padding: '2px', border: '1px solid var(--border-subtle)' }}>
              {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'CLEAN'].map(v => (
                <button
                  key={v}
                  onClick={() => setVerdictFilter(v)}
                  style={{
                    padding: '3px 8px',
                    fontSize: '11px',
                    fontFamily: 'IBM Plex Sans, sans-serif',
                    background: verdictFilter === v ? 'var(--action-blue)' : 'transparent',
                    color: verdictFilter === v ? '#ffffff' : 'var(--text-secondary)',
                    border: 'none',
                    cursor: 'pointer',
                    fontWeight: verdictFilter === v ? 600 : 400,
                  }}
                >
                  {v}
                </button>
              ))}
            </div>

            {/* Submit New Scan Button */}
            <button
              className="btn-carbon"
              onClick={() => navigate('/scan')}
              style={{ fontSize: '12px', padding: '6px 12px' }}
            >
              <Plus size={14} />
              Submit APK
            </button>
          </div>
        </div>

        {/* Table */}
        <table className="carbon-table" style={{
          width: '100%',
          borderCollapse: 'collapse',
        }}>
          <thead>
            <tr>
              {['File Name', 'Package Name', 'Verdict', 'Risk Score', 'Scanned At'].map(h => (
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
            {filteredScans.length === 0 ? (
              <tr>
                <td colSpan={5} style={{
                  padding: '32px 16px',
                  color: 'var(--text-placeholder)',
                  textAlign: 'center',
                  fontSize: '13px',
                }}>
                  {recentScans.length === 0
                    ? 'No scans processed yet. Submit an APK to launch static and dynamic analysis.'
                    : 'No scans match your current filter criteria.'}
                </td>
              </tr>
            ) : (
              filteredScans.map(scan => (
                <tr
                  key={scan.scan_id}
                  onClick={() => navigate(`/scan/${scan.scan_id}`)}
                  style={{ cursor: 'pointer', borderBottom: '1px solid var(--border-subtle)' }}
                >
                  <td className="mono" style={{
                    padding: '12px 16px',
                    fontSize: '13px',
                    fontWeight: 500,
                    color: 'var(--text-primary)',
                  }}>
                    {scan.file_name || '—'}
                  </td>
                  <td className="mono" style={{
                    padding: '12px 16px',
                    color: 'var(--text-secondary)',
                    fontSize: '12px',
                  }}>
                    {scan.package_name || '—'}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <VerdictBadge verdict={scan.verdict} />
                  </td>
                  <td className="mono" style={{
                    padding: '12px 16px',
                    fontSize: '13px',
                    fontWeight: 600,
                    color: (scan.risk_score || 0) >= 70 ? 'var(--danger)' : (scan.risk_score || 0) >= 40 ? 'var(--warning)' : 'var(--success)',
                  }}>
                    {scan.risk_score ?? '—'}
                  </td>
                  <td style={{
                    padding: '12px 16px',
                    color: 'var(--text-secondary)',
                    fontSize: '12px',
                  }}>
                    {new Date(scan.scanned_at).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
