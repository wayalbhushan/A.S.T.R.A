export default function RiskScore({ score }) {
  if (score === null || score === undefined) return null
  
  const getColor = (s) => {
    if (s >= 70) return '#da1e28'
    if (s >= 40) return '#f1c21b'
    if (s >= 20) return '#009d9a'
    return '#24a148'
  }

  const getRiskLabel = (s) => {
    if (s >= 70) return 'HIGH SEVERITY RISK'
    if (s >= 40) return 'SUSPICIOUS RISK'
    if (s >= 20) return 'LOW RISK'
    return 'MINIMAL RISK'
  }

  const color = getColor(score)

  return (
    <div style={{ textAlign: 'center', width: '100%' }}>
      <div style={{
        fontFamily: 'IBM Plex Mono, monospace',
        fontSize: '44px',
        fontWeight: 600,
        color: color,
        lineHeight: 1,
      }}>
        {score}
      </div>
      <div style={{
        fontSize: '10px',
        color: 'var(--text-placeholder)',
        letterSpacing: '0.5px',
        textTransform: 'uppercase',
        marginTop: '2px',
        fontFamily: 'IBM Plex Mono, monospace',
      }}>
        SCORE / 100
      </div>

      {/* Progress score bar */}
      <div style={{
        height: '4px',
        background: 'var(--bg-elevated)',
        marginTop: '10px',
        width: '100%',
        position: 'relative',
      }}>
        <div style={{
          height: '100%',
          width: `${Math.min(Math.max(score, 4), 100)}%`,
          background: color,
          transition: 'width 0.3s ease',
        }} />
      </div>

      <div style={{
        fontSize: '10px',
        fontWeight: 600,
        color: color,
        letterSpacing: '0.4px',
        textTransform: 'uppercase',
        marginTop: '6px',
      }}>
        {getRiskLabel(score)}
      </div>
    </div>
  )
}
