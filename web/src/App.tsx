import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { ThemeProvider } from './components/ui'
import { LangProvider } from './lib/lang'
import { Shell } from './components/Shell'
import { Login, Mfa } from './pages/Login'
import { Setup } from './pages/Setup'
import { Dashboard } from './pages/Dashboard'
import { Targets } from './pages/Targets'
import { Users } from './pages/Users'
import { Activity, Enroll } from './pages/Activity'
import { Settings } from './pages/Settings'

/** Auth screens fill the viewport; everything else lives inside the shell. */
function Layout() {
  const { pathname } = useLocation()
  const bare = pathname === '/login' || pathname === '/mfa' || pathname === '/setup'

  const routes = (
    <Routes>
      <Route path="/setup" element={<Setup />} />
      <Route path="/login" element={<Login />} />
      <Route path="/mfa" element={<Mfa />} />
      <Route path="/" element={<Dashboard />} />
      <Route path="/targets" element={<Targets />} />
      <Route path="/users" element={<Users />} />
      <Route path="/activity" element={<Activity />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="/enroll" element={<Enroll />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )

  return bare ? routes : <Shell>{routes}</Shell>
}

/** Sends a fresh install straight into the wizard, wherever they landed. */
function SetupGate({ children }: { children: React.ReactNode }) {
  const [checked, setChecked] = useState(false)
  const nav = useNavigate()
  const { pathname } = useLocation()

  useEffect(() => {
    fetch('/api/setup/status')
      .then((r) => r.json())
      .then((s) => {
        if (s.setup_required && pathname !== '/setup') nav('/setup', { replace: true })
      })
      .catch(() => {})
      .finally(() => setChecked(true))
    // Only on first mount: re-checking on every navigation would be a request
    // per click for something that changes once in the lifetime of a gateway.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return checked ? <>{children}</> : null
}

export default function App() {
  return (
    <ThemeProvider>
      <LangProvider>
        <BrowserRouter>
          <SetupGate>
            <Layout />
          </SetupGate>
        </BrowserRouter>
      </LangProvider>
    </ThemeProvider>
  )
}
