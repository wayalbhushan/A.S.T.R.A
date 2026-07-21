import Sidebar from './Sidebar'
import Header from './Header'
import { Outlet, useLocation, Link } from 'react-router-dom'
import { ChevronRight, Home } from 'lucide-react'

const PAGE_TITLES = {
  '/': 'Dashboard Overview',
  '/scan': 'Submit APK for Analysis',
  '/campaigns': 'Campaign Tracker',
  '/feed': 'IOC Threat Intelligence Feed',
}

export default function Layout() {
  const location = useLocation()
  const title = PAGE_TITLES[location.pathname] || 'Scan Result'
  const isHome = location.pathname === '/'

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      <Sidebar />
      <div style={{
        marginLeft: '240px',
        flex: 1,
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--bg-primary)',
      }}>
        <Header title={title} />
        
        {/* Subtle Breadcrumb Bar */}
        <div style={{
          padding: '8px 24px',
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '11px',
          color: 'var(--text-secondary)',
        }}>
          <Link to="/" style={{ color: 'var(--text-secondary)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Home size={12} />
            <span>ASTRA</span>
          </Link>
          {!isHome && (
            <>
              <ChevronRight size={12} color="var(--text-placeholder)" />
              <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{title}</span>
            </>
          )}
        </div>

        <main style={{ padding: '24px', flex: 1 }}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
