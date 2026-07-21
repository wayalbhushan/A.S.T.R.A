export default function StatCard({
  label, value, icon: Icon, accent, subtitle
}) {
  return (
    <div
      style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '18px 20px',
        borderRadius: '0px',
        transition: 'background-color 0.15s ease, border-color 0.15s ease',
        cursor: 'default',
        position: 'relative',
        overflow: 'hidden',
      }}
      onMouseEnter={e => {
        e.currentTarget.style.background = 'var(--bg-elevated)'
        e.currentTarget.style.borderColor = accent || 'var(--action-blue)'
      }}
      onMouseLeave={e => {
        e.currentTarget.style.background = 'var(--bg-secondary)'
        e.currentTarget.style.borderColor = 'var(--border)'
      }}
    >
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '10px',
      }}>
        <span style={{
          fontSize: '11px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.4px',
          textTransform: 'uppercase',
          fontWeight: 600,
        }}>
          {label}
        </span>
        {Icon && (
          <Icon
            size={18}
            color={accent || 'var(--action-blue)'}
            style={{ opacity: 0.9 }}
          />
        )}
      </div>
      
      <div style={{
        fontSize: '28px',
        fontWeight: 600,
        fontFamily: 'IBM Plex Mono, monospace',
        color: accent || 'var(--text-primary)',
        lineHeight: '1.2',
      }}>
        {value ?? '—'}
      </div>

      {subtitle && (
        <div style={{
          fontSize: '11px',
          color: 'var(--text-placeholder)',
          marginTop: '6px',
        }}>
          {subtitle}
        </div>
      )}
    </div>
  )
}
