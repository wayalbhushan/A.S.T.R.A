export default function StatCard({
  label, value, icon: Icon, accent
}) {
  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: '1px solid var(--border)',
      padding: '16px',
      borderRadius: '0px',
    }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: '12px',
      }}>
        <span style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.32px',
          textTransform: 'uppercase',
          fontWeight: 600,
        }}>
          {label}
        </span>
        {Icon && (
          <Icon
            size={16}
            color={accent || 'var(--text-secondary)'}
          />
        )}
      </div>
      <div style={{
        fontSize: '28px',
        fontWeight: 600,
        fontFamily: 'IBM Plex Mono, monospace',
        color: accent || 'var(--text-primary)',
      }}>
        {value ?? '—'}
      </div>
    </div>
  )
}
