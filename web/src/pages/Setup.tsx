import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import QRCode from 'qrcode'
import { ArrowRight, Check, Copy, Monitor, Shield, ShieldCheck, Terminal } from 'lucide-react'
import { Button, Card, Field, spring } from '../components/ui'
import { LanguagePicker } from '../components/LanguagePicker'
import { api, setCSRF } from '../lib/api'
import { useT } from '../lib/lang'

/*
  First run. Four steps, one screen at a time, no way to skip the second
  factor — a gateway whose administrator has only a password would defeat the
  entire point of it.
*/

type Step = 'admin' | 'enroll' | 'target' | 'done'

export function Setup() {
  const nav = useNavigate()

  const [step, setStep] = useState<Step>('admin')
  const [gateway, setGateway] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  // Checked once: if the gateway is already configured, nobody should be here.
  useEffect(() => {
    api
      .setupStatus()
      .then((s) => {
        if (!s.setup_required) nav('/login', { replace: true })
        setGateway(s.gateway ?? '')
      })
      .catch(() => {})
  }, [nav])

  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError('')
    try {
      await fn()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center px-4 py-10" style={{ background: 'var(--bg)' }}>
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring} className="w-full max-w-[440px]">
        <div className="mb-6 flex flex-col items-center">
          <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-[12px]" style={{ background: 'var(--accent)' }}>
            <Shield size={22} strokeWidth={2} className="text-white" />
          </div>
          <h1 className="text-[19px] font-semibold tracking-[-0.02em]">Revpd</h1>
          <p className="mt-0.5 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
            {gateway}
          </p>
        </div>

        <Steps current={step} />

        {error && (
          <p className="mb-3 rounded-[10px] px-3 py-2 text-[13px]" style={{ background: 'var(--red-soft)', color: 'var(--red)' }}>
            {error}
          </p>
        )}

        {/*
          One card at a time, sliding in the direction of travel. The key on
          the wrapper is what tells framer-motion a different step arrived.
        */}
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={step}
            initial={{ opacity: 0, x: 24 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -24 }}
            transition={{ type: 'spring', stiffness: 420, damping: 34 }}
          >
            {step === 'admin' && <AdminStep busy={busy} run={run} onDone={() => setStep('enroll')} />}
            {step === 'enroll' && <EnrollStep busy={busy} run={run} onDone={() => setStep('target')} />}
            {step === 'target' && (
              <TargetStep busy={busy} run={run} onDone={() => setStep('done')} onSkip={() => setStep('done')} />
            )}
            {step === 'done' && <DoneStep gateway={gateway} onFinish={() => nav('/', { replace: true })} />}
          </motion.div>
        </AnimatePresence>

        <div className="mt-5 flex justify-center">
          <LanguagePicker compact />
        </div>
      </motion.div>
    </div>
  )
}

const order: Step[] = ['admin', 'enroll', 'target', 'done']

function Steps({ current }: { current: Step }) {
  const at = order.indexOf(current)

  return (
    <div className="mb-5 flex items-center gap-1.5">
      {order.map((s, i) => (
        <div key={s} className="h-[3px] flex-1 overflow-hidden rounded-full" style={{ background: 'var(--fill)' }}>
          {/* Fills left to right as each step completes. */}
          <motion.div
            className="h-full rounded-full"
            style={{ background: 'var(--accent)', originX: 0 }}
            initial={false}
            animate={{ scaleX: i <= at ? 1 : 0 }}
            transition={{ type: 'spring', stiffness: 260, damping: 30 }}
          />
        </div>
      ))}
    </div>
  )
}

/* ---------------------------------------------------------------- step 1 --- */

function AdminStep({
  busy,
  run,
  onDone,
}: {
  busy: boolean
  run: (fn: () => Promise<void>) => Promise<void>
  onDone: () => void
}) {
  const t = useT()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')

  const tooShort = password.length > 0 && password.length < 12
  const mismatch = repeat.length > 0 && password !== repeat
  const ready = username.length > 0 && password.length >= 12 && password === repeat

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    run(async () => {
      // Fetch the status immediately before posting: each call rotates the
      // CSRF cookie, so the token has to be the one from the most recent one.
      const status = await api.setupStatus()
      setCSRF(status.csrf)

      const created = await api.setupAdmin({ username, display_name: username, password })
      setCSRF(created.csrf)

      setPassword('')
      setRepeat('')
      onDone()
    })
  }

  return (
    <Card>
      <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{t('setup.adminTitle')}</h2>
      <p className="mb-4 mt-0.5 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
        {t('setup.adminHint')}
      </p>

      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label={t('login.username')} autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <Field
          label={t('login.password')}
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint={tooShort ? t('setup.passwordShort') : undefined}
        />
        <Field
          label={t('setup.repeat')}
          type="password"
          autoComplete="new-password"
          value={repeat}
          onChange={(e) => setRepeat(e.target.value)}
          hint={mismatch ? t('setup.mismatch') : undefined}
        />
        <Button type="submit" variant="primary" className="mt-1 w-full" disabled={busy || !ready} icon={<ArrowRight size={15} strokeWidth={2} />}>
          {t('login.continue')}
        </Button>
      </form>
    </Card>
  )
}

/* ---------------------------------------------------------------- step 2 --- */

function EnrollStep({
  busy,
  run,
  onDone,
}: {
  busy: boolean
  run: (fn: () => Promise<void>) => Promise<void>
  onDone: () => void
}) {
  const t = useT()
  const [secret, setSecret] = useState('')
  const [codes, setCodes] = useState<string[]>([])
  const [entered, setEntered] = useState('')
  const [saved, setSaved] = useState(false)
  const canvas = useRef<HTMLCanvasElement>(null)
  const started = useRef(false)

  // Once only: a second call would mint a new secret and invalidate the QR
  // code the person may already have scanned.
  useEffect(() => {
    if (started.current) return
    started.current = true

    run(async () => {
      const res = await api.enrollStart()
      setSecret(res.secret)
      setCodes(res.backup_codes)
      if (canvas.current) {
        await QRCode.toCanvas(canvas.current, res.uri, { width: 176, margin: 1 })
      }
    })
  }, [run])

  const confirm = (e: React.FormEvent) => {
    e.preventDefault()
    run(async () => {
      await api.enrollConfirm(entered)
      onDone()
    })
  }

  return (
    <Card>
      <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{t('setup.enrollTitle')}</h2>
      <p className="mb-4 mt-0.5 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
        {t('enroll.hint')}
      </p>

      <div className="flex flex-col items-center gap-3">
        <div className="rounded-[12px] border bg-white p-2">
          <canvas ref={canvas} width={176} height={176} />
        </div>
        {secret && (
          <code className="select-all rounded-[8px] px-2.5 py-1.5 font-mono text-[12px]" style={{ background: 'var(--surface-sunken)', color: 'var(--text-secondary)' }}>
            {secret.match(/.{1,4}/g)?.join(' ')}
          </code>
        )}
      </div>

      {codes.length > 0 && (
        <div className="mt-4 border-t pt-3">
          <p className="text-[13px] font-medium">{t('enroll.backupTitle')}</p>
          <p className="mb-2 text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
            {t('enroll.backupHint')}
          </p>
          <div className="grid grid-cols-2 gap-1.5">
            {codes.map((c) => (
              <code key={c} className="rounded-[8px] px-2 py-1 text-center font-mono text-[12.5px]" style={{ background: 'var(--surface-sunken)' }}>
                {c}
              </code>
            ))}
          </div>
          <Button
            size="sm"
            className="mt-2 w-full"
            icon={saved ? <Check size={13} strokeWidth={2.5} /> : <Copy size={13} strokeWidth={1.75} />}
            onClick={() => {
              navigator.clipboard?.writeText(codes.join('\n'))
              setSaved(true)
            }}
          >
            {saved ? t('common.copied') : t('common.copy')}
          </Button>
        </div>
      )}

      <form onSubmit={confirm} className="mt-4 border-t pt-3">
        <Field
          label={t('setup.confirmCode')}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          mono
          value={entered}
          onChange={(e) => setEntered(e.target.value.replace(/\D/g, ''))}
        />
        <Button type="submit" variant="primary" className="mt-3 w-full" disabled={busy || entered.length !== 6} icon={<ShieldCheck size={15} strokeWidth={2} />}>
          {t('login.continue')}
        </Button>
      </form>
    </Card>
  )
}

/* ---------------------------------------------------------------- step 3 --- */

function TargetStep({
  busy,
  run,
  onDone,
  onSkip,
}: {
  busy: boolean
  run: (fn: () => Promise<void>) => Promise<void>
  onDone: () => void
  onSkip: () => void
}) {
  const t = useT()
  const [name, setName] = useState('')
  const [ip, setIp] = useState('')
  const [mac, setMac] = useState('')

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    run(async () => {
      await api.setupTarget({ name, ip, mac })
      onDone()
    })
  }

  return (
    <Card>
      <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{t('setup.targetTitle')}</h2>
      <p className="mb-4 mt-0.5 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
        {t('setup.targetHint')}
      </p>

      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label={t('targets.name')} autoFocus value={name} onChange={(e) => setName(e.target.value)} />
        <Field label={t('targets.ip')} mono value={ip} onChange={(e) => setIp(e.target.value)} />
        <Field label={t('targets.mac')} mono value={mac} onChange={(e) => setMac(e.target.value)} hint={t('setup.macHint')} />

        <Button type="submit" variant="primary" className="mt-1 w-full" disabled={busy || !name || !ip || !mac} icon={<Monitor size={15} strokeWidth={1.75} />}>
          {t('login.continue')}
        </Button>
        <button type="button" onClick={onSkip} className="rounded-[8px] py-2 text-[13px] font-medium hover:bg-[var(--fill)]" style={{ color: 'var(--text-secondary)' }}>
          {t('setup.later')}
        </button>
      </form>
    </Card>
  )
}

/* ---------------------------------------------------------------- step 4 --- */

function DoneStep({ gateway, onFinish }: { gateway: string; onFinish: () => void }) {
  const t = useT()

  return (
    <Card>
      <div className="flex flex-col items-center text-center">
        {/* The tick springs in once, as a small reward for finishing. */}
        <motion.div
          className="mb-3 flex h-11 w-11 items-center justify-center rounded-full"
          style={{ background: 'var(--green-soft)' }}
          initial={{ scale: 0.4, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: 'spring', stiffness: 500, damping: 18, delay: 0.1 }}
        >
          <motion.span
            initial={{ scale: 0.5 }}
            animate={{ scale: 1 }}
            transition={{ type: 'spring', stiffness: 600, damping: 16, delay: 0.22 }}
          >
            <Check size={22} strokeWidth={2.5} style={{ color: 'var(--green)' }} />
          </motion.span>
        </motion.div>
        <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{t('setup.doneTitle')}</h2>
        <p className="mt-1 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
          {t('setup.doneHint')}
        </p>
      </div>

      <div className="mt-4 rounded-[10px] border p-3" style={{ background: 'var(--surface-sunken)' }}>
        <div className="flex items-center gap-2 text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
          <Terminal size={13} strokeWidth={1.75} />
          {t('setup.connectWith')}
        </div>
        <code className="mt-1.5 block font-mono text-[13px] font-medium">{gateway}</code>
        <code className="mt-1 block font-mono text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
          {t('login.password')} + <span style={{ color: 'var(--accent)' }}>,123456</span>
        </code>
      </div>

      <Button variant="primary" className="mt-4 w-full" onClick={onFinish} icon={<ArrowRight size={15} strokeWidth={2} />}>
        {t('setup.open')}
      </Button>
    </Card>
  )
}
