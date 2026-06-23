export default function RiskScore({ score }) {
  if (score === null || score === undefined) return null
  
  const getColor = (s) => {
    if (s >= 70) return '#da1e28'
    if (s >= 40) return '#f1c21b'
    if (s >= 20) return '#009d9a'
    return '#24a148'
  }

  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{
        fontFamily: 'IBM Plex Mono, monospace',
        fontSize: '48px',
        fontWeight: 600,
        color: getColor(score),
        lineHeight: 1,
      }}>
        {score}
      </div>
      <div style={{
        fontSize: '11px',
        color: 'var(--text-secondary)',
        letterSpacing: '0.32px',
        textTransform: 'uppercase',
        marginTop: '4px',
      }}>
        / 100
      </div>
    </div>
  )
}
