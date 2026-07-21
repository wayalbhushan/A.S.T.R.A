import { Activity, Terminal } from 'lucide-react'

export default function Header({ title }) {
  return (
    <header style={{
      height: '48px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      borderBottom: '1px solid var(--border)',
      background: 'var(--bg-primary)',
      userSelect: 'none',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <span style={{
          fontSize: '14px',
          fontWeight: 600,
          color: 'var(--text-primary)',
          letterSpacing: '0.16px',
        }}>
          {title}
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {/* Environment Tag */}
        <div style={{
          fontSize: '10px',
          fontFamily: 'IBM Plex Mono, monospace',
          color: 'var(--text-secondary)',
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          padding: '2px 8px',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
        }}>
          <Terminal size={12} color="var(--text-placeholder)" />
          ENV: DEV
        </div>

        {/* Live Engine Status Indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '11px',
          color: 'var(--text-secondary)',
          background: 'var(--bg-secondary)',
          padding: '4px 10px',
          border: '1px solid var(--border-subtle)',
        }}>
          <span className="pulse-dot" />
          <span style={{ fontWeight: 500 }}>SYSTEM OPERATIONAL</span>
        </div>
      </div>
    </header>
  )
}
