export default function Header({ title }) {
  return (
    <header style={{
      height: '48px',
      display: 'flex',
      alignItems: 'center',
      padding: '0 24px',
      borderBottom: '1px solid var(--border)',
      background: 'var(--bg-primary)',
    }}>
      <span style={{
        fontSize: '14px',
        fontWeight: 600,
        color: 'var(--text-primary)',
        letterSpacing: '0.16px',
      }}>
        {title}
      </span>
    </header>
  )
}
