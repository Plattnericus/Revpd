import { useCallback, useEffect, useMemo, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { AlertTriangle, Globe, Info, RotateCcw, TriangleAlert } from 'lucide-react'
import { Button, Card, Field, spring } from '../components/ui'
import { UpdatePanel, useUpdateStatus } from '../components/UpdateCard'
import { api, type ApiConfig, type ApiNetwork, type ApiSetting } from '../lib/api'
import { useLang, useT } from '../lib/lang'
import { settingLabel } from '../lib/i18n.settings'
import { settingHint } from '../lib/i18n.hints'
import type { Key } from '../lib/i18n'

/*
  Everything the gateway can be configured with.

  Two values matter for each setting and both are shown: what revpd.yaml says,
  and what is actually in force. They differ once somebody changes one here,
  and "back to the file" then stays one click away — nobody has to remember
  whether a value came from the installer or from a change last month.

  Nothing is saved field by field. Settings constrain each other, so the whole
  form goes to the server at once and comes back either applied or refused with
  the reason. A refusal changes nothing at all.
*/

export function Settings() {
  const t = useT()
  const updates = useUpdateStatus()

  const [cfg, setCfg] = useState<ApiConfig | null>(null)
  const [edits, setEdits] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  const load = useCallback(async () => {
    try {
      setCfg(await api.config())
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const dirty = Object.keys(edits).length > 0

  const save = async () => {
    setBusy(true)
    setError('')
    try {
      setCfg(await api.saveConfig(edits))
      setEdits({})
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    } catch (e) {
      // The server validates the whole set and explains itself; showing that
      // verbatim beats paraphrasing it into something vaguer.
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const reset = async (key: string) => {
    setBusy(true)
    setError('')
    try {
      setCfg(await api.saveConfig({}, [key]))
      setEdits((e) => {
        const next = { ...e }
        delete next[key]
        return next
      })
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const restart = async () => {
    setBusy(true)
    setError('')
    try {
      await api.restart()
      // The server is going away; wait for it to come back rather than
      // showing a failed request the moment it does.
      setTimeout(load, 6000)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setBusy(false)
    }
  }

  const byGroup = useMemo(() => {
    const out = new Map<string, ApiSetting[]>()
    for (const s of cfg?.settings ?? []) {
      const list = out.get(s.group) ?? []
      list.push(s)
      out.set(s.group, list)
    }
    return out
  }, [cfg])

  if (!cfg) {
    return error ? <Problem>{error}</Problem> : <div className="h-24" />
  }

  const restartNeeded = cfg.runtime.restart_needed

  return (
    <div className="flex flex-col gap-4 pb-24">
      <UpdatePanel ctl={updates} />

      <Card>
        <h2 className="mb-1 text-[15px] font-semibold tracking-[-0.015em]">{t('settings.runningOn')}</h2>
        <div className="mt-2 flex flex-col gap-1.5">
          <Line label={t('settings.portal')} value={cfg.runtime.portal_url} />
          <Line label={t('settings.remoteDesktop')} value={cfg.runtime.gateway} />
        </div>
      </Card>

      <PublicAddress initial={cfg.runtime.network} />


      {restartNeeded && (
        <Banner
          tone="orange"
          icon={<AlertTriangle size={15} strokeWidth={2} />}
          title={t('settings.restartNeeded')}
          body={t('settings.restartNeededHint')}
          action={
            cfg.runtime.can_restart ? (
              <Button variant="primary" onClick={restart} disabled={busy}>
                {t('settings.restartNow')}
              </Button>
            ) : undefined
          }
        />
      )}

      {error && <Problem>{error}</Problem>}

      {cfg.groups.map((group) => {
        const items = byGroup.get(group) ?? []
        if (items.length === 0) return null

        return (
          <Card key={group} padded={false}>
            <div className="border-b px-5 py-3.5">
              <h2 className="text-[15px] font-semibold tracking-[-0.015em]">
                {t(`settings.group.${group}` as Key)}
              </h2>
              <p className="mt-0.5 text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                {t(`settings.group.${group}.hint` as Key)}
              </p>
            </div>

            <div className="flex flex-col divide-y">
              {items.map((s) => (
                <Row
                  key={s.key}
                  setting={s}
                  edited={edits[s.key]}
                  disabled={busy}
                  onChange={(v) =>
                    setEdits((e) => {
                      const next = { ...e }
                      // Typing a value back to what it already is is not a change.
                      if (v === s.value) delete next[s.key]
                      else next[s.key] = v
                      return next
                    })
                  }
                  onReset={() => reset(s.key)}
                />
              ))}
            </div>

            {/* A wrong topic or a revoked webhook is otherwise discovered by
                the alert that never arrives. */}
            {group === 'notify' && <NotifyTest unsaved={dirty} />}
          </Card>
        )
      })}

      <p className="px-1 text-[12px]" style={{ color: 'var(--text-tertiary)' }}>
        {t('settings.fileNote')} <code className="font-mono">/etc/revpd/revpd.yaml</code>
      </p>

      {/* The save bar follows the page: a long form should never hide it. */}
      <AnimatePresence>
        {(dirty || saved) && (
          <motion.div
            initial={{ y: 60, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 60, opacity: 0 }}
            transition={spring}
            className="fixed inset-x-0 bottom-0 z-30 flex justify-center px-4 pb-4"
            style={{ paddingBottom: 'calc(1rem + env(safe-area-inset-bottom))' }}
          >
            <div
              className="flex w-full max-w-[560px] items-center gap-3 rounded-[14px] border px-4 py-3"
              style={{ background: 'var(--surface)', boxShadow: 'var(--shadow-sheet)' }}
            >
              <span className="flex-1 text-[13px]">
                {saved && !dirty
                  ? t('settings.saved')
                  : `${Object.keys(edits).length} ${t('settings.pending')}`}
              </span>
              {dirty && (
                <>
                  <Button size="sm" variant="ghost" onClick={() => setEdits({})} disabled={busy}>
                    {t('common.cancel')}
                  </Button>
                  <Button size="sm" variant="primary" onClick={save} disabled={busy}>
                    {t('common.save')}
                  </Button>
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

/* ----------------------------------------------------------------- row --- */

function Row({
  setting,
  edited,
  disabled,
  onChange,
  onReset,
}: {
  setting: ApiSetting
  edited?: string
  disabled: boolean
  onChange: (v: string) => void
  onReset: () => void
}) {
  const t = useT()
  const { lang } = useLang()
  const current = edited ?? setting.value
  const changed = edited !== undefined

  return (
    <div className="px-5 py-3.5">
      <div className="flex items-start gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-[14px] font-medium">{settingLabel(lang, setting.key)}</label>
            {setting.restart && (
              <span
                className="rounded-full px-1.5 py-[1px] text-[11px] font-medium"
                style={{ background: 'var(--fill)', color: 'var(--text-secondary)' }}
              >
                {t('settings.needsRestart')}
              </span>
            )}
            {setting.pending && (
              <span
                className="rounded-full px-1.5 py-[1px] text-[11px] font-medium"
                style={{ background: 'var(--orange-soft)', color: 'var(--orange)' }}
                title={`${t('settings.stillRunning')} ${setting.running}`}
              >
                {t('settings.pendingRestart')}
              </span>
            )}
            {setting.overridden && !changed && !setting.pending && (
              <button
                onClick={onReset}
                disabled={disabled}
                title={t('settings.backToFile')}
                className="inline-flex items-center gap-1 rounded-full px-1.5 py-[1px] text-[11px] font-medium hover:opacity-70"
                style={{ background: 'var(--accent-soft)', color: 'var(--accent)' }}
              >
                <RotateCcw size={10} strokeWidth={2} />
                {t('settings.changed')}
              </button>
            )}
          </div>

          <p className="mt-0.5 font-mono text-[11.5px]" style={{ color: 'var(--text-tertiary)' }}>
            {setting.key}
          </p>

          {/* Translated where somebody has written it; the server's English
              line stands in for a setting added since. */}
          {(settingHint(lang, setting.key) || setting.warn) && (
            <p className="mt-1 flex items-start gap-1.5 text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
              <Info size={12} strokeWidth={2} className="mt-[3px] shrink-0" />
              {settingHint(lang, setting.key) || setting.warn}
            </p>
          )}

          {/* A list drawn from a fixed set is unusable without the set. */}
          {setting.kind === 'text_list' && setting.options && (
            <p className="mt-1 text-[12px] leading-relaxed" style={{ color: 'var(--text-tertiary)' }}>
              {t('settings.allowedValues')}{' '}
              <span className="font-mono">{setting.options.join(' · ')}</span>
            </p>
          )}

          {setting.overridden && setting.file !== current && (
            <p className="mt-1 text-[12px]" style={{ color: 'var(--text-tertiary)' }}>
              {t('settings.fileSays')} <code className="font-mono">{setting.file || '—'}</code>
            </p>
          )}
        </div>

        <div className="w-[190px] shrink-0">
          <Control setting={setting} value={current} disabled={disabled} onChange={onChange} />
        </div>
      </div>
    </div>
  )
}

function Control({
  setting,
  value,
  disabled,
  onChange,
}: {
  setting: ApiSetting
  value: string
  disabled: boolean
  onChange: (v: string) => void
}) {
  const t = useT()

  if (setting.kind === 'bool') {
    const on = value === 'true'
    return (
      <div className="flex justify-end">
        <button
          role="switch"
          aria-checked={on}
          aria-label={setting.key}
          disabled={disabled}
          onClick={() => onChange(on ? 'false' : 'true')}
          className="relative h-[31px] w-[51px] shrink-0 rounded-full transition-colors disabled:opacity-40"
          style={{ background: on ? 'var(--green)' : 'var(--fill-hover)' }}
        >
          <motion.span
            layout
            transition={spring}
            className="absolute top-[2px] h-[27px] w-[27px] rounded-full bg-white"
            style={{ left: on ? 22 : 2, boxShadow: '0 2px 5px rgba(0,0,0,.25)' }}
          />
        </button>
      </div>
    )
  }

  if (setting.kind === 'choice' && setting.options) {
    return (
      <select
        value={value}
        disabled={disabled}
        aria-label={setting.key}
        onChange={(e) => onChange(e.target.value)}
        className="h-9 w-full rounded-[10px] border px-2 text-[13px] outline-none"
        style={{ background: 'var(--surface-sunken)', color: 'var(--text)' }}
      >
        {setting.options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    )
  }

  if (setting.kind === 'duration') {
    return <DurationField value={value} disabled={disabled} onChange={onChange} />
  }

  if (setting.kind === 'int') {
    return (
      <Field
        type="number"
        min={setting.min}
        max={setting.max}
        value={value}
        disabled={disabled}
        mono
        onChange={(e) => onChange(e.target.value)}
      />
    )
  }

  return (
    <Field
      value={value}
      disabled={disabled}
      mono
      placeholder={setting.kind === 'addr' ? ':443' : undefined}
      hint={
        setting.kind === 'addr_list' || setting.kind === 'text_list'
          ? t('settings.commaSeparated')
          : undefined
      }
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

/*
  Durations travel as seconds. Showing them that way would make "12 hours"
  read as 43200, so the field picks the largest unit the value divides into
  evenly and converts back on the way out.
*/
function DurationField({
  value,
  disabled,
  onChange,
}: {
  value: string
  disabled: boolean
  onChange: (v: string) => void
}) {
  const t = useT()
  const seconds = Number(value) || 0

  const unit = seconds > 0 && seconds % 3600 === 0 ? 3600 : seconds > 0 && seconds % 60 === 0 ? 60 : 1
  const shown = seconds / unit

  const units: { factor: number; label: string }[] = [
    { factor: 1, label: t('settings.seconds') },
    { factor: 60, label: t('settings.minutes') },
    { factor: 3600, label: t('settings.hours') },
  ]

  return (
    <div className="flex gap-1.5">
      <Field
        type="number"
        min={0}
        value={String(shown)}
        disabled={disabled}
        mono
        className="flex-1"
        onChange={(e) => onChange(String(Math.max(0, Number(e.target.value) || 0) * unit))}
      />
      <select
        value={unit}
        disabled={disabled}
        aria-label={t('settings.unit')}
        onChange={(e) => onChange(String(shown * Number(e.target.value)))}
        className="h-9 rounded-[10px] border px-2 text-[13px] outline-none"
        style={{ background: 'var(--surface-sunken)', color: 'var(--text)' }}
      >
        {units.map((u) => (
          <option key={u.factor} value={u.factor}>
            {u.label}
          </option>
        ))}
      </select>
    </div>
  )
}

/* ---------------------------------------------------------- notify test --- */

/*
  Sending one real message to whatever is configured.

  Real rather than simulated, because the failures worth catching — a topic
  name with a typo in it, a webhook that was revoked, a firewall that does not
  let this machine out — all look fine from here and only show up at the far
  end. The alternative is finding out from the alert that never came.
*/
function NotifyTest({ unsaved }: { unsaved: boolean }) {
  const t = useT()
  const [state, setState] = useState<'' | 'busy' | 'sent'>('')
  const [error, setError] = useState('')

  const run = async () => {
    setState('busy')
    setError('')
    try {
      await api.testNotify()
      setState('sent')
      setTimeout(() => setState(''), 4000)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setState('')
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3 border-t px-5 py-3.5">
      <Button size="sm" variant="ghost" onClick={run} disabled={state === 'busy' || unsaved}>
        {state === 'busy' ? t('settings.notifyTesting') : t('settings.notifyTest')}
      </Button>
      <span className="min-w-0 flex-1 text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
        {/* The test uses what is saved, so offering it mid-edit would test the
            old value and report success for a URL nobody has yet. */}
        {unsaved
          ? t('settings.notifySaveFirst')
          : state === 'sent'
            ? t('settings.notifySent')
            : t('settings.notifyTestHint')}
      </span>
      {error && (
        <span className="w-full text-[12.5px]" style={{ color: 'var(--red)' }}>
          {error}
        </span>
      )}
    </div>
  )
}

/* ------------------------------------------------------- from outside --- */

/*
  What to type from somewhere else, and what to forward on the router.

  Neither is visible from a listening socket: behind NAT they only ever see the
  LAN, so the address here comes from a configured domain or from asking a
  machine on the far side. It is display data throughout — nothing on this card
  decides who may connect.

  The two buttons do different things on purpose. Checking asks again what our
  address is; testing opens connections back to it, which is slower, noisier,
  and inconclusive when it fails. Neither runs on its own.
*/
function PublicAddress({ initial }: { initial: ApiNetwork }) {
  const t = useT()

  const [net, setNet] = useState(initial)
  const [busy, setBusy] = useState<'' | 'check' | 'probe'>('')
  const [error, setError] = useState('')

  // Saving the form reloads the whole configuration, and a changed domain
  // arrives with it.
  useEffect(() => setNet(initial), [initial])

  const check = async (probe: boolean) => {
    setBusy(probe ? 'probe' : 'check')
    setError('')
    try {
      setNet(await api.checkNetwork(probe))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy('')
    }
  }

  const source = net.configured
    ? t('network.sourceConfigured')
    : net.detecting
      ? t('network.sourceDetected')
      : t('network.detectOff')

  return (
    <Card>
      <div className="flex items-start gap-2.5">
        <Globe size={15} strokeWidth={2} className="mt-[3px] shrink-0" style={{ color: 'var(--text-secondary)' }} />
        <div className="min-w-0 flex-1">
          <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{t('network.title')}</h2>
          <p className="mt-0.5 text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
            {t('network.hint')}
          </p>
        </div>
      </div>

      {net.host ? (
        <div className="mt-3 flex flex-col gap-2">
          <Endpoint
            label={t('network.remoteDesktop')}
            value={net.rdp.address}
            forwardedTo={net.rdp.forwarded ? net.rdp.listen : undefined}
          />
          <Endpoint
            label={t('network.webInterface')}
            value={net.portal_url ?? net.portal.address}
            forwardedTo={net.portal.forwarded ? net.portal.listen : undefined}
          />
        </div>
      ) : (
        <div
          className="mt-3 rounded-[10px] px-3 py-2.5 text-[13px]"
          style={{ background: 'var(--orange-soft)', color: 'var(--orange)' }}
        >
          <p className="font-medium">{t('network.unknown')}</p>
          <p className="mt-0.5 opacity-80">{t('network.unknownHint')}</p>
        </div>
      )}

      {/* A domain that stopped following the connection is the failure worth
          catching here rather than while away from the machine. */}
      {net.mismatch && (
        <p
          className="mt-2.5 flex items-start gap-1.5 rounded-[10px] px-3 py-2 text-[12.5px]"
          style={{ background: 'var(--orange-soft)', color: 'var(--orange)' }}
        >
          <AlertTriangle size={12} strokeWidth={2} className="mt-[3px] shrink-0" />
          {net.mismatch}
        </p>
      )}

      {net.reach && (
        <p
          className="mt-2.5 rounded-[10px] px-3 py-2 text-[12.5px] leading-relaxed"
          style={
            net.reach.confirmed
              ? { background: 'var(--green-soft)', color: 'var(--green)' }
              : { background: 'var(--fill)', color: 'var(--text-secondary)' }
          }
        >
          {net.reach.confirmed ? t('network.confirmed') : t('network.unconfirmed')}
        </p>
      )}

      {(error || net.error) && (
        <p className="mt-2 text-[12px]" style={{ color: 'var(--text-tertiary)' }}>
          {error || net.error}
        </p>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button size="sm" variant="ghost" onClick={() => check(false)} disabled={busy !== ''}>
          {busy === 'check' ? t('network.checking') : t('network.check')}
        </Button>
        <Button size="sm" variant="ghost" onClick={() => check(true)} disabled={busy !== '' || !net.host}>
          {busy === 'probe' ? t('network.checking') : t('network.testPorts')}
        </Button>
        <span className="text-[12px]" style={{ color: 'var(--text-tertiary)' }}>
          {source}
        </span>
      </div>
    </Card>
  )
}

function Endpoint({
  label,
  value,
  forwardedTo,
}: {
  label: string
  value: string
  forwardedTo?: string
}) {
  const t = useT()

  return (
    <div className="flex items-baseline justify-between gap-4">
      <span className="shrink-0 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
        {label}
      </span>
      <span className="min-w-0 text-right">
        <code className="font-mono text-[13px] font-medium break-all">{value}</code>
        {/* Only spelled out when the outside and inside ports differ, which is
            the case somebody set up deliberately and may want to check. */}
        {forwardedTo && (
          <span className="mt-0.5 block font-mono text-[11.5px]" style={{ color: 'var(--text-tertiary)' }}>
            {t('network.forwards')} {forwardedTo}
          </span>
        )}
      </span>
    </div>
  )
}

/* -------------------------------------------------------------- pieces --- */

function Line({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4">
      <span className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
        {label}
      </span>
      <code className="font-mono text-[13px] font-medium">{value}</code>
    </div>
  )
}

function Problem({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="flex items-start gap-2 rounded-[10px] px-3 py-2.5 text-[13px] leading-relaxed"
      style={{ background: 'var(--red-soft)', color: 'var(--red)' }}
    >
      <TriangleAlert size={14} strokeWidth={2} className="mt-[3px] shrink-0" />
      <span className="whitespace-pre-wrap">{children}</span>
    </div>
  )
}

function Banner({
  tone,
  icon,
  title,
  body,
  action,
}: {
  tone: 'orange'
  icon: React.ReactNode
  title: string
  body: string
  action?: React.ReactNode
}) {
  const colors = { orange: { background: 'var(--orange-soft)', color: 'var(--orange)' } }[tone]

  return (
    <div className="flex items-center gap-3 rounded-[12px] px-4 py-3" style={colors}>
      <span className="shrink-0">{icon}</span>
      <div className="min-w-0 flex-1">
        <p className="text-[13.5px] font-medium">{title}</p>
        <p className="mt-0.5 text-[12.5px] opacity-80">{body}</p>
      </div>
      {action}
    </div>
  )
}
