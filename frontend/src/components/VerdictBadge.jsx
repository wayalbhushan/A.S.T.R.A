const VERDICT_STYLES = {
  'MALICIOUS':  { bg: '#da1e28', color: '#fff' },
  'SUSPICIOUS': { bg: '#f1c21b', color: '#161616' },
  'LOW RISK':   { bg: '#009d9a', color: '#fff' },
  'CLEAN':      { bg: '#24a148', color: '#fff' },
}

export default function VerdictBadge({ verdict }) {
  if (!verdict) return null
  const style = VERDICT_STYLES[verdict] || 
    { bg: '#525252', color: '#fff' }
  return (
    <span style={{
      background: style.bg,
      color: style.color,
      padding: '2px 8px',
      fontSize: '11px',
      fontWeight: 600,
      letterSpacing: '0.32px',
      textTransform: 'uppercase',
      borderRadius: '0px',
      fontFamily: 'IBM Plex Sans, sans-serif',
      display: 'inline-block',
    }}>
      {verdict}
    </span>
  )
}
