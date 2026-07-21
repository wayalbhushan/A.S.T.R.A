import { ShieldAlert, AlertTriangle, CheckCircle2, Info } from 'lucide-react'

const VERDICT_CONFIG = {
  'MALICIOUS':  { bg: '#da1e28', color: '#fff', icon: ShieldAlert },
  'SUSPICIOUS': { bg: '#f1c21b', color: '#161616', icon: AlertTriangle },
  'LOW RISK':   { bg: '#009d9a', color: '#fff', icon: Info },
  'CLEAN':      { bg: '#24a148', color: '#fff', icon: CheckCircle2 },
}

export default function VerdictBadge({ verdict }) {
  if (!verdict) return null
  const config = VERDICT_CONFIG[verdict] || { bg: '#525252', color: '#fff', icon: Info }
  const Icon = config.icon

  return (
    <span style={{
      background: config.bg,
      color: config.color,
      padding: '3px 8px',
      fontSize: '11px',
      fontWeight: 600,
      letterSpacing: '0.4px',
      textTransform: 'uppercase',
      borderRadius: '0px',
      fontFamily: 'IBM Plex Sans, sans-serif',
      display: 'inline-flex',
      alignItems: 'center',
      gap: '5px',
      userSelect: 'none',
    }}>
      <Icon size={12} style={{ flexShrink: 0 }} />
      <span>{verdict}</span>
    </span>
  )
}
