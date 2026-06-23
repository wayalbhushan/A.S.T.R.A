import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Activity, Database, Shield
} from 'lucide-react'
import { api } from '../api/client'
import StatCard from '../components/StatCard'
import VerdictBadge from '../components/VerdictBadge'

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    api.getStats()
      .then(res => setStats(res.data.data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div style={{
      color: 'var(--text-secondary)',
      fontSize: '14px'
    }}>
      Loading...
    </div>
  )

  if (error) return (
    <div style={{ color: 'var(--danger)', fontSize: '14px' }}>
      Error: {error}
    </div>
  )

  return (
    <div>
      {/* Stat cards grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '1px',
        marginBottom: '24px',
        background: 'var(--border)',
      }}>
        <StatCard
          label="Total Scans"
          value={stats.total_scans}
          icon={Activity}
        />
        <StatCard
          label="Malicious"
          value={stats.malicious_count}
          icon={AlertTriangle}
          accent='var(--danger)'
        />
        <StatCard
          label="Detection Rate"
          value={`${stats.detection_rate_percent}%`}
          icon={Shield}
          accent='var(--warning)'
        />
        <StatCard
          label="Certs Tracked"
          value={stats.certificates_tracked}
          icon={Database}
        />
      </div>

      {/* Recent scans table */}
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
          Recent Scans
        </div>

        <table style={{
          width: '100%',
          borderCollapse: 'collapse',
        }}>
          <thead>
            <tr>
              {['File Name', 'Package', 'Verdict', 'Risk Score', 'Scanned At'].map(h => (
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
            {stats.recent_scans.length === 0 ? (
              <tr>
                <td colSpan={5} style={{
                  padding: '24px 16px',
                  color: 'var(--text-placeholder)',
                  textAlign: 'center',
                }}>
                  No scans yet. Submit an APK to begin analysis.
                </td>
              </tr>
            ) : (
              stats.recent_scans.map(scan => (
                <tr
                  key={scan.scan_id}
                  onClick={() => navigate(`/scan/${scan.scan_id}`)}
                  style={{ cursor: 'pointer' }}
                  onMouseEnter={e => {
                    e.currentTarget.style.background = 'var(--bg-elevated)'
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.background = 'transparent'
                  }}
                >
                  <td style={{
                    padding: '10px 16px',
                    borderBottom: '1px solid var(--border-subtle)',
                    fontFamily: 'IBM Plex Mono, monospace',
                    fontSize: '13px',
                  }}>
                    {scan.file_name || '—'}
                  </td>
                  <td style={{
                    padding: '10px 16px',
                    borderBottom: '1px solid var(--border-subtle)',
                    color: 'var(--text-secondary)',
                    fontSize: '13px',
                  }}>
                    {scan.package_name || '—'}
                  </td>
                  <td style={{
                    padding: '10px 16px',
                    borderBottom: '1px solid var(--border-subtle)',
                  }}>
                    <VerdictBadge verdict={scan.verdict} />
                  </td>
                  <td style={{
                    padding: '10px 16px',
                    borderBottom: '1px solid var(--border-subtle)',
                    fontFamily: 'IBM Plex Mono, monospace',
                    fontSize: '13px',
                  }}>
                    {scan.risk_score ?? '—'}
                  </td>
                  <td style={{
                    padding: '10px 16px',
                    borderBottom: '1px solid var(--border-subtle)',
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
