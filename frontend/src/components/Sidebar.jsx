import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Upload, Shield,
  Link, Radio, Cpu, Layers
} from 'lucide-react'

const NAV_SECTIONS = [
  {
    title: 'ANALYTICS & SCANNING',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/scan', icon: Upload, label: 'Submit APK' },
    ]
  },
  {
    title: 'THREAT INTELLIGENCE',
    items: [
      { to: '/campaigns', icon: Link, label: 'Campaign Tracker' },
      { to: '/feed', icon: Radio, label: 'IOC Feed' },
    ]
  }
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
      userSelect: 'none',
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
        <Shield size={18} color='var(--action-blue)' />
        <span style={{
          fontFamily: 'IBM Plex Mono, monospace',
          fontSize: '14px',
          fontWeight: 600,
          color: 'var(--text-primary)',
          letterSpacing: '0.1em',
        }}>
          ASTRA
        </span>
        <span style={{
          fontSize: '10px',
          color: 'var(--text-placeholder)',
          fontFamily: 'IBM Plex Mono, monospace',
          background: 'var(--bg-elevated)',
          padding: '1px 5px',
          border: '1px solid var(--border-subtle)',
          marginLeft: 'auto',
        }}>
          v1.0
        </span>
      </div>

      {/* Nav sections */}
      <nav style={{ flex: 1, padding: '12px 0', overflowY: 'auto' }}>
        {NAV_SECTIONS.map((section, idx) => (
          <div key={section.title} style={{ marginBottom: idx < NAV_SECTIONS.length - 1 ? '16px' : '0' }}>
            <div style={{
              padding: '8px 16px 6px',
              fontSize: '10px',
              color: 'var(--text-placeholder)',
              letterSpacing: '0.4px',
              textTransform: 'uppercase',
              fontWeight: 600,
            }}>
              {section.title}
            </div>
            {section.items.map(({ to, icon: Icon, label }) => (
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
                    ? '3px solid var(--action-blue)'
                    : '3px solid transparent',
                  textDecoration: 'none',
                  fontSize: '13px',
                  fontWeight: isActive ? 600 : 400,
                  transition: 'background-color 0.12s ease',
                })}
              >
                <Icon size={16} style={{ flexShrink: 0 }} />
                <span>{label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Engine Status Footer */}
      <div style={{
        padding: '14px 16px',
        borderTop: '1px solid var(--border)',
        fontSize: '11px',
        background: 'var(--bg-primary)',
        color: 'var(--text-secondary)',
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontWeight: 600,
          color: 'var(--text-primary)',
          marginBottom: '4px',
        }}>
          <Cpu size={13} color="var(--info)" />
          ML Engine Model
        </div>
        <div style={{ fontSize: '10px', color: 'var(--text-placeholder)', lineHeight: '1.4' }}>
          CICMalDroid 2020 Dataset
        </div>
        <div style={{
          fontSize: '10px',
          color: 'var(--success)',
          fontWeight: 600,
          marginTop: '2px',
          display: 'flex',
          alignItems: 'center',
          gap: '4px',
        }}>
          <Layers size={10} /> 94.27% Accuracy Verified
        </div>
      </div>
    </aside>
  )
}
