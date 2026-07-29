import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { api, onUnauthorized } from './api'

/*
  Who is looking at this, and where are they allowed to be.

  Two things decide it, and they are asked in that order: a gateway with no
  accounts yet needs the wizard before anything else, and after that a page
  behind the login needs a full session — password *and* second factor.

  The check is deliberately not repeated on every click. It runs once, again
  whenever an authentication step completes, and again when the tab comes back
  to the foreground. In between, the API client itself is the safety net: any
  request that comes back 401 means the session is gone, and that lands here
  immediately rather than as a broken page.
*/

export type SessionStatus =
  | 'checking' // the first answer has not arrived yet
  | 'setup' // no accounts exist; the wizard is the only place to be
  | 'onboarding' // an account exists and is signed in, but never finished the wizard
  | 'out' // nobody is signed in
  | 'in' // signed in, second factor included

export interface SessionUser {
  username: string
  displayName: string
  role: 'admin' | 'user'
}

interface Session {
  status: SessionStatus
  user: SessionUser | null
  /** Re-asks the server. Call after any step that changes who is signed in. */
  refresh: () => Promise<void>
  /** Marks the session gone without a round trip, as sign-out does. */
  forget: () => void
}

const SessionCtx = createContext<Session>({
  status: 'checking',
  user: null,
  refresh: async () => {},
  forget: () => {},
})

export const useSession = () => useContext(SessionCtx)

export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SessionStatus>('checking')
  const [user, setUser] = useState<SessionUser | null>(null)

  // Guards against two checks racing: the slower answer must not overwrite
  // the newer one, or a sign-out can be undone by a reply already in flight.
  const generation = useRef(0)

  const refresh = useCallback(async () => {
    const mine = ++generation.current

    let setupComplete = true
    try {
      const setup = await api.setupStatus()
      if (mine !== generation.current) return

      if (setup.setup_required) {
        setStatus('setup')
        setUser(null)
        return
      }
      setupComplete = setup.setup_complete
    } catch {
      // The status endpoint is public and always answers. If it did not, the
      // gateway is unreachable rather than the session invalid — treat it as
      // signed out so the login screen can report the real error.
      if (mine !== generation.current) return
      setStatus('out')
      setUser(null)
      return
    }

    try {
      const me = await api.me()
      if (mine !== generation.current) return

      setUser({ username: me.username, displayName: me.display_name, role: me.role })
      // Signed in, but the wizard was never walked to its last screen —
      // a refresh belongs back there, not on a dashboard nobody has set up
      // yet, with nothing left to say so.
      setStatus(setupComplete ? 'in' : 'onboarding')
    } catch {
      if (mine !== generation.current) return

      // 401 is the ordinary "not signed in"; anything else means the request
      // failed outright. Either way the login screen is the honest place to
      // be, because no page behind it can load its data. An unfinished
      // wizard changes nothing here — signing in is still the first step,
      // and doing that again lands back in this same check with a session.
      setUser(null)
      setStatus('out')
    }
  }, [])

  const forget = useCallback(() => {
    generation.current++
    setUser(null)
    setStatus('out')
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  // The API client reports any 401 here, so a session that expired while the
  // page was open sends the user to the login instead of showing an error on
  // a screen they cannot use.
  useEffect(() => {
    onUnauthorized(() => forget())
    return () => onUnauthorized(null)
  }, [forget])

  // A tab left open overnight has an expired session. Re-check when it comes
  // back rather than waiting for the first click to fail.
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === 'visible') refresh()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => document.removeEventListener('visibilitychange', onVisible)
  }, [refresh])

  return <SessionCtx.Provider value={{ status, user, refresh, forget }}>{children}</SessionCtx.Provider>
}

/* ---------------------------------------------------------------- guard --- */

/** The wizard. Reachable only while the gateway has no accounts. */
const SETUP_PATH = '/setup'

/**
 * Where someone who is not signed in may still be.
 *
 * /mfa is on the list on purpose: between the password and the second factor
 * the session is real but not yet full, so /api/me refuses it. Treating that
 * as signed out and bouncing to /login would make it impossible to ever
 * finish signing in.
 */
const ANONYMOUS_PATHS = ['/login', '/mfa']

/**
 * destination decides where a given visitor belongs. Null means "where they
 * already are".
 *
 * Kept separate from the component so the rules can be read — and tested — on
 * their own, rather than being inferred from what the app happens to do.
 */
export function destination(status: SessionStatus, pathname: string): string | null {
  // Nothing is known yet, so nothing is decided.
  if (status === 'checking') return null

  // A gateway with no accounts has exactly one useful page — and so does one
  // whose only account has never finished the wizard. The difference between
  // the two is invisible here on purpose: both send everything to /setup,
  // which is what tells them apart once it loads.
  if (status === 'setup' || status === 'onboarding') {
    return pathname === SETUP_PATH ? null : SETUP_PATH
  }

  if (status === 'out') {
    if (ANONYMOUS_PATHS.includes(pathname)) return null

    // Remember where they were going, so signing in lands them there rather
    // than dumping everyone on the overview.
    return pathname === '/' ? '/login' : `/login?next=${encodeURIComponent(pathname)}`
  }

  // Signed in. The login and the wizard have nothing left to offer.
  if (ANONYMOUS_PATHS.includes(pathname) || pathname === SETUP_PATH) return '/'
  return null
}

/**
 * Guard sends people where they belong before rendering anything.
 *
 * It renders nothing at all while the first check is outstanding. Showing the
 * dashboard's frame and then yanking it away is worse than a blank moment,
 * and the check is one request against the local server.
 */
export function Guard({ children }: { children: ReactNode }) {
  const { status } = useSession()
  const { pathname } = useLocation()

  if (status === 'checking') return null

  const to = destination(status, pathname)
  return to ? <Navigate to={to} replace /> : <>{children}</>
}

/** Where to go after signing in, honouring the page that was asked for. */
export function nextAfterLogin(search: string): string {
  const next = new URLSearchParams(search).get('next')

  // Only same-site paths. An open redirect on a login page is worth taking
  // seriously even when the value can only come from our own guard.
  if (next && next.startsWith('/') && !next.startsWith('//')) return next
  return '/'
}
