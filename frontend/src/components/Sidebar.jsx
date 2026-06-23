import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Upload, Shield,
  Link, Radio
} from 'lucide-react'

const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard,
    label: 'Dashboard' },
  { to: '/scan', icon: Upload,
    label: 'Submit APK' },
  { to: '/campaigns', icon: Link,
    label: 'Campaign Tracker' },
  { to: '/feed', icon: Radio,
    label: 'IOC Feed' },
]

export default function Sidebar() {
  return (
    <aside style={{
      position: 'fixed',
      top: 0, left: 0,
      width: '240px',
      height: '100vh',
      background: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 100,
    }}>
      {/* Logo area */}
      <div style={{
        height: '48px',
        display: 'flex',
        alignItems: 'center',
        padding: '0 16px',
        borderBottom: '1px solid var(--border)',
        gap: '8px',
      }}>
        <Shield size={16} color='var(--action-blue)' />
        <span style={{
          fontFamily: 'IBM Plex Mono, monospace',
          fontSize: '13px',
          fontWeight: 600,
          color: 'var(--text-primary)',
          letterSpacing: '0.08em',
        }}>
          ASTRA
        </span>
        <span style={{
          fontSize: '11px',
          color: 'var(--text-placeholder)',
          marginLeft: '4px',
        }}>
          v1.0
        </span>
      </div>

      {/* Section label */}
      <div style={{
        padding: '16px 16px 8px',
        fontSize: '11px',
        color: 'var(--text-placeholder)',
        letterSpacing: '0.32px',
        textTransform: 'uppercase',
        fontWeight: 600,
      }}>
        Navigation
      </div>

      {/* Nav links */}
      <nav style={{ flex: 1 }}>
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '10px 16px',
              color: isActive
                ? 'var(--text-primary)'
                : 'var(--text-secondary)',
              background: isActive
                ? 'var(--bg-elevated)'
                : 'transparent',
              borderLeft: isActive
                ? '2px solid var(--action-blue)'
                : '2px solid transparent',
              textDecoration: 'none',
              fontSize: '14px',
              fontWeight: isActive ? 600 : 400,
              transition: 'none',
            })}
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div style={{
        padding: '12px 16px',
        borderTop: '1px solid var(--border)',
        fontSize: '11px',
        color: 'var(--text-placeholder)',
      }}>
        CICMalDroid 2020 · 94.27% accuracy
      </div>
    </aside>
  )
}
