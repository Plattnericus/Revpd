import { useCallback, useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { ArrowUpCircle, Check, RefreshCw, TriangleAlert } from 'lucide-react'
import { Badge, Button, Card, spring } from './ui'
import { api, type ApiUpdate } from '../lib/api'
import { useT } from '../lib/lang'

/*
  The update panel.

  Two shapes, deliberately: on the dashboard it only appears when there is
  something to say, so a gateway that is current stays a page about machines.
  In Settings it is always there, with the automatic-update switch.

  Downloading happens on the server, so the browser is not holding anything —
  it polls while work is in flight and stops when it is not.
*/

/** How often to re-read the status while something is happening. */
const BUSY_POLL_MS = 1500

export function useUpdateStatus() {
  const [status, setStatus] = useState<ApiUpdate | null>(null)
  const [isAdmin, setIsAdmin] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      setStatus(await api.updateStatus())
    } catch {
      // A failed poll is not worth a message: the next one is a second away,
      // and the button's own errors are the ones that matter.
    }
  }, [])

  useEffect(() => {
    load()
    // Everyone may see that an update exists; only an administrator gets the
    // buttons, so ask once who is looking rather than offering a control the
    // server would refuse.
    api
      .me()
      .then((me) => setIsAdmin(me.role === 'admin'))
      .catch(() => setIsAdmin(false))
  }, [load])

  // Poll only while the server is mid-flight. An idle gateway is polled once.
  const phase = status?.phase
  const inFlight = phase === 'checking' || phase === 'downloading' || phase === 'verifying' || phase === 'applying'

  const timer = useRef<number | undefined>(undefined)
  useEffect(() => {
    if (!inFlight) return
    timer.current = window.setInterval(load, BUSY_POLL_MS)
    return () => window.clearInterval(timer.current)
  }, [inFlight, load])

  const run = useCallback(
    async (action: () => Promise<ApiUpdate>) => {
      setBusy(true)
      setError('')
      try {
        setStatus(await action())
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e))
      } finally {
        setBusy(false)
      }
    },
    [],
  )

  return {
    status,
    isAdmin,
    busy: busy || inFlight,
    error,
    reload: load,
    check: () => run(() => api.updateCheck()),
    install: (version?: string) => run(() => api.updateInstall(version)),
    setAuto: (on: boolean) => run(() => api.updateAuto(on)),
  }
}

type Controller = ReturnType<typeof useUpdateStatus>

/** The dashboard banner: silent unless there is something to act on. */
export function UpdateBanner({ ctl }: { ctl: Controller }) {
  const t = useT()
  const { status: s, isAdmin } = ctl

  if (!s?.supported) return null

  const busyPhase = s.phase === 'downloading' || s.phase === 'verifying' || s.phase === 'applying'
  const failed = s.last_result && !s.last_result.ok
  const succeeded = s.last_result?.ok

  if (!s.available && !busyPhase && !failed && !succeeded) return null

  return (
    <AnimatePresence initial={false}>
      <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} transition={spring}>
        <Card padded={false}>
          <div className="flex items-center gap-3.5 p-4">
            <StatusIcon status={s} />

            <div className="min-w-0 flex-1">
              <h3 className="flex items-center gap-2 text-[15px] font-semibold tracking-[-0.015em]">
                {headline(s, t)}
                {s.available && !busyPhase && (
                  <span className="font-mono text-[13px] font-medium" style={{ color: 'var(--accent)' }}>
                    {s.available.version}
                  </span>
                )}
              </h3>
              <p className="mt-0.5 text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                {detail(s, t)}
              </p>
            </div>

            {s.available && !busyPhase && isAdmin && s.can_install !== false && (
              <Button
                variant="primary"
                icon={<ArrowUpCircle size={15} strokeWidth={2} />}
                onClick={() => ctl.install()}
                disabled={ctl.busy}
              >
                {t('update.install')}
              </Button>
            )}
          </div>

          {s.progress && s.progress.total > 0 && <ProgressBar {...s.progress} />}

          {s.available && s.can_install === false && (
            <Note tone="orange">{t('update.noApplier')}</Note>
          )}
          {s.available && isAdmin && s.can_install !== false && !busyPhase && (
            <Note tone="muted">{t('update.restartWarning')}</Note>
          )}
          {ctl.error && <Note tone="red">{ctl.error}</Note>}
        </Card>
      </motion.div>
    </AnimatePresence>
  )
}

/** The Settings panel: always visible, with the automatic-update switch. */
export function UpdatePanel({ ctl }: { ctl: Controller }) {
  const t = useT()
  const { status: s, isAdmin } = ctl

  if (!s) return <Card><div className="h-16" /></Card>

  if (!s.supported) {
    return (
      <Card>
        <div className="mb-1 flex items-center gap-2">
          <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{t('update.title')}</h2>
          <Badge tone="grey">{s.current}</Badge>
        </div>
        <p className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
          {s.reason ?? t('update.unsupported')}
        </p>
      </Card>
    )
  }

  const busyPhase = s.phase === 'downloading' || s.phase === 'verifying' || s.phase === 'applying'

  return (
    <Card padded={false}>
      <div className="flex items-center gap-3 px-5 py-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{t('update.title')}</h2>
            <Badge tone={s.available ? 'accent' : 'green'}>
              {s.available ? s.available.version : t('update.upToDate')}
            </Badge>
          </div>
          <p className="mt-0.5 text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
            {t('update.current')} <span className="font-mono">{s.current}</span>
            {' · '}
            {t('update.lastCheck')} {s.last_check ? relative(s.last_check) : t('update.never')}
          </p>
        </div>

        {isAdmin && (
          <div className="flex shrink-0 gap-2">
            <Button
              size="sm"
              icon={<RefreshCw size={13} strokeWidth={2} className={ctl.busy ? 'animate-spin' : undefined} />}
              onClick={ctl.check}
              disabled={ctl.busy}
            >
              {t('update.check')}
            </Button>
            {s.available && !busyPhase && s.can_install !== false && (
              <Button size="sm" variant="primary" onClick={() => ctl.install()} disabled={ctl.busy}>
                {t('update.install')}
              </Button>
            )}
          </div>
        )}
      </div>

      {s.progress && s.progress.total > 0 && <ProgressBar {...s.progress} />}

      {busyPhase && <Note tone="muted">{phaseLabel(s.phase, t)}</Note>}
      {s.error && <Note tone="orange">{s.error}</Note>}
      {ctl.error && <Note tone="red">{ctl.error}</Note>}
      {s.last_result && (
        <Note tone={s.last_result.ok ? 'green' : 'red'}>
          {s.last_result.message}
          {s.last_result.rolled_back && ' ' + t('update.rolledBack')}
        </Note>
      )}
      {s.available?.notes && (
        <div className="border-t px-5 py-3" style={{ background: 'var(--surface-sunken)' }}>
          <p className="mb-1 text-[12px] font-medium" style={{ color: 'var(--text-secondary)' }}>
            {t('update.notes')}
          </p>
          <pre className="max-h-40 overflow-y-auto whitespace-pre-wrap text-[12.5px] leading-relaxed">
            {s.available.notes}
          </pre>
        </div>
      )}

      {isAdmin && (
        <div className="border-t px-5 py-1">
          <AutoToggle
            checked={s.auto_install === true}
            disabled={ctl.busy || s.can_install === false}
            onChange={ctl.setAuto}
            label={t('update.auto')}
            hint={s.can_install === false ? t('update.noApplier') : t('update.autoHint')}
          />
        </div>
      )}
    </Card>
  )
}

/* ------------------------------------------------------------- pieces --- */

function AutoToggle({
  checked,
  disabled,
  onChange,
  label,
  hint,
}: {
  checked: boolean
  disabled?: boolean
  onChange: (v: boolean) => void
  label: string
  hint: string
}) {
  return (
    <div className="flex items-start justify-between gap-6 py-2.5">
      <div className="min-w-0">
        <div className="text-[14px] font-medium">{label}</div>
        <p className="mt-0.5 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
          {hint}
        </p>
      </div>
      <button
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className="relative h-[31px] w-[51px] shrink-0 rounded-full transition-colors disabled:opacity-40"
        style={{ background: checked ? 'var(--green)' : 'var(--fill-hover)' }}
      >
        <motion.span
          layout
          transition={spring}
          className="absolute top-[2px] h-[27px] w-[27px] rounded-full bg-white"
          style={{ left: checked ? 22 : 2, boxShadow: '0 2px 5px rgba(0,0,0,.25)' }}
        />
      </button>
    </div>
  )
}

function ProgressBar({ downloaded, total }: { downloaded: number; total: number }) {
  const pct = Math.min(100, Math.round((downloaded / Math.max(total, 1)) * 100))
  return (
    <div className="border-t px-5 py-3" style={{ background: 'var(--surface-sunken)' }}>
      <div className="h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'var(--fill)' }}>
        <motion.div
          className="h-full rounded-full"
          style={{ background: 'var(--accent)' }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
        />
      </div>
      <p className="tnum mt-1.5 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
        {pct}% · {mb(downloaded)} / {mb(total)}
      </p>
    </div>
  )
}

function Note({ tone, children }: { tone: 'red' | 'orange' | 'green' | 'muted'; children: React.ReactNode }) {
  const colors = {
    red: { background: 'var(--red-soft)', color: 'var(--red)' },
    orange: { background: 'var(--orange-soft)', color: 'var(--orange)' },
    green: { background: 'var(--green-soft)', color: 'var(--green)' },
    muted: { background: 'var(--surface-sunken)', color: 'var(--text-secondary)' },
  }[tone]

  return (
    <div className="border-t px-5 py-2.5 text-[12.5px] leading-relaxed" style={colors}>
      {children}
    </div>
  )
}

function StatusIcon({ status }: { status: ApiUpdate }) {
  const spinning = status.phase === 'downloading' || status.phase === 'verifying' || status.phase === 'applying'
  const bad = status.last_result && !status.last_result.ok

  const [bg, fg, Icon] = bad
    ? ['var(--red-soft)', 'var(--red)', TriangleAlert]
    : status.available || spinning
      ? ['var(--accent-soft)', 'var(--accent)', ArrowUpCircle]
      : ['var(--green-soft)', 'var(--green)', Check]

  return (
    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full" style={{ background: bg }}>
      <Icon size={19} strokeWidth={1.75} className={spinning ? 'animate-pulse' : undefined} style={{ color: fg }} />
    </div>
  )
}

/* -------------------------------------------------------------- labels --- */

type T = ReturnType<typeof useT>

function headline(s: ApiUpdate, t: T): string {
  if (s.phase === 'downloading' || s.phase === 'verifying' || s.phase === 'applying') {
    return phaseLabel(s.phase, t)
  }
  if (s.last_result && !s.last_result.ok) return t('update.failed')
  if (s.available) return t('update.available')
  if (s.last_result?.ok) return t('update.done')
  return t('update.upToDate')
}

function detail(s: ApiUpdate, t: T): string {
  if (s.last_result) {
    return s.last_result.message + (s.last_result.rolled_back ? ' ' + t('update.rolledBack') : '')
  }
  if (s.phase === 'applying') return t('update.installing')
  if (s.available) return `${t('update.current')} ${s.current}`
  return `${t('update.current')} ${s.current}`
}

function phaseLabel(phase: ApiUpdate['phase'], t: T): string {
  switch (phase) {
    case 'checking':
      return t('update.checking')
    case 'downloading':
      return t('update.downloading')
    case 'verifying':
      return t('update.verifying')
    case 'applying':
      return t('update.installing')
    default:
      return ''
  }
}

function mb(bytes: number): string {
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

/** Coarse on purpose: "3 hours ago" is all anyone needs from a check time. */
function relative(iso: string): string {
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  const rtf = new Intl.RelativeTimeFormat(document.documentElement.lang || 'en', { numeric: 'auto' })

  if (secs < 90) return rtf.format(-Math.round(secs), 'second')
  if (secs < 3600) return rtf.format(-Math.round(secs / 60), 'minute')
  if (secs < 86400) return rtf.format(-Math.round(secs / 3600), 'hour')
  return rtf.format(-Math.round(secs / 86400), 'day')
}
