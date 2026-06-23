import Sidebar from './Sidebar'
import Header from './Header'
import { Outlet, useLocation } from 'react-router-dom'

const PAGE_TITLES = {
  '/': 'Dashboard',
  '/scan': 'Submit APK for Analysis',
  '/campaigns': 'Campaign Tracker',
  '/feed': 'IOC Threat Feed',
}

export default function Layout() {
  const location = useLocation()
  const title = PAGE_TITLES[location.pathname]
    || 'Scan Result'

  return (
    <div style={{ display: 'flex' }}>
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
        <main style={{ padding: '24px', flex: 1 }}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
