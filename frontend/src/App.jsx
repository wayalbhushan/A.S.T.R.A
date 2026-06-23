import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ScanSubmit from './pages/ScanSubmit'
import ScanResult from './pages/ScanResult'
import Campaigns from './pages/Campaigns'
import IOCFeed from './pages/IOCFeed'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="scan" element={<ScanSubmit />} />
          <Route path="scan/:scanId" element={<ScanResult />} />
          <Route path="campaigns" element={<Campaigns />} />
          <Route path="feed" element={<IOCFeed />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
