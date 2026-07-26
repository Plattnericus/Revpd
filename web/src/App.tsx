import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { ThemeProvider } from './components/ui'
import { LangProvider } from './lib/lang'
import { Guard, SessionProvider } from './lib/session'
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

export default function App() {
  return (
    <ThemeProvider>
      <LangProvider>
        <BrowserRouter>
          {/*
            Guard sits inside the router because it navigates, and outside the
            layout because nothing behind the login should render even for a
            frame. A fresh gateway goes to the wizard, a signed-out one to the
            login, and a signed-in one never sees either.
          */}
          <SessionProvider>
            <Guard>
              <Layout />
            </Guard>
          </SessionProvider>
        </BrowserRouter>
      </LangProvider>
    </ThemeProvider>
  )
}
