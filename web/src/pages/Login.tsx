import { useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { ArrowRight, KeyRound, Shield } from 'lucide-react'
import { Button, Field, spring } from '../components/ui'
import { api, setCSRF } from '../lib/api'
import { passkeysAvailable, usePasskey } from '../lib/passkey'
import { useT } from '../lib/lang'

export function Login() {
  const nav = useNavigate()
  const t = useT()

  const [username, setUsername] = useState('')
  const [pw, setPw] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')

    try {
      const res = await api.login(username, pw)
      setPw('') // do not leave it sitting in component state
      nav(res.stage === 'mfa' ? '/mfa' : '/')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  // Passkeys need a secure context. Offering a button that cannot work would
  // be worse than not showing one.
  const canPasskey = passkeysAvailable()

  const withPasskey = async () => {
    setBusy(true)
    setError('')

    try {
      const begin = await api.passkeyLoginBegin(username)
      setCSRF(begin.csrf)

      const credential = await usePasskey(begin.options)
      await api.passkeyLoginFinish(credential)
      nav('/')
    } catch (err) {
      // A cancelled prompt is a choice, not a failure worth shouting about.
      const message = err instanceof Error ? err.message : String(err)
      setError(/NotAllowed|abort/i.test(message) ? '' : message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthFrame title={t('login.title')}>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field
          label={t('login.username')}
          autoComplete="username webauthn"
          autoFocus
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <Field
          label={t('login.password')}
          type="password"
          autoComplete="current-password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
        />

        {error && (
          <p className="text-[13px]" style={{ color: 'var(--red)' }}>
            {error}
          </p>
        )}

        <Button
          type="submit"
          variant="primary"
          className="mt-1 w-full"
          disabled={busy || !username || !pw}
          icon={<ArrowRight size={15} strokeWidth={2} />}
        >
          {t('login.continue')}
        </Button>
      </form>

      {canPasskey && (
        <>
          <div className="my-4 flex items-center gap-3">
            <span className="h-px flex-1" style={{ background: 'var(--hairline)' }} />
            <span className="text-[12px]" style={{ color: 'var(--text-tertiary)' }}>
              {t('login.or')}
            </span>
            <span className="h-px flex-1" style={{ background: 'var(--hairline)' }} />
          </div>

          <Button
            className="w-full"
            disabled={busy}
            icon={<KeyRound size={15} strokeWidth={1.75} />}
            onClick={withPasskey}
          >
            {t('login.passkey')}
          </Button>
        </>
      )}
    </AuthFrame>
  )
}

export function Mfa() {
  const nav = useNavigate()
  const t = useT()
  const [code, setCode] = useState<string[]>(Array(6).fill(''))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const refs = useRef<(HTMLInputElement | null)[]>([])

  const submit = async (full: string) => {
    setBusy(true)
    setError('')

    try {
      await api.verify(full)
      nav('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setCode(Array(6).fill(''))
      refs.current[0]?.focus()
    } finally {
      setBusy(false)
    }
  }

  const setDigit = (i: number, v: string) => {
    const digits = v.replace(/\D/g, '')
    if (!digits) {
      setCode((c) => c.map((x, k) => (k === i ? '' : x)))
      return
    }

    // Pasting the whole code into any box should fill the row.
    let filled: string[] = []
    setCode((c) => {
      const next = [...c]
      for (let k = 0; k < digits.length && i + k < 6; k++) next[i + k] = digits[k]!
      filled = next
      return next
    })

    const landed = Math.min(i + digits.length, 5)
    refs.current[landed]?.focus()

    // Submit as soon as all six are there, so nobody hunts for a button.
    if (filled.every((d) => d !== '')) submit(filled.join(''))
  }

  const onKey = (i: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !code[i] && i > 0) refs.current[i - 1]?.focus()
    if (e.key === 'ArrowLeft' && i > 0) refs.current[i - 1]?.focus()
    if (e.key === 'ArrowRight' && i < 5) refs.current[i + 1]?.focus()
  }

  return (
    <AuthFrame title={t('mfa.title')} subtitle={t('mfa.subtitle')}>
      <div className="flex justify-center gap-2">
        {code.map((d, i) => (
          <input
            key={i}
            ref={(el) => {
              refs.current[i] = el
            }}
            value={d}
            onChange={(e) => setDigit(i, e.target.value)}
            onKeyDown={(e) => onKey(i, e)}
            inputMode="numeric"
            autoComplete={i === 0 ? 'one-time-code' : 'off'}
            aria-label={`Ziffer ${i + 1}`}
            autoFocus={i === 0}
            maxLength={6}
            className="tnum h-[52px] w-[44px] rounded-[10px] border text-center text-[20px] font-semibold outline-none transition-shadow focus:border-transparent focus:ring-2"
            style={{
              background: 'var(--surface-sunken)',
              color: 'var(--text)',
              // @ts-expect-error custom property for the focus ring
              '--tw-ring-color': 'var(--accent)',
            }}
          />
        ))}
      </div>

      {error && (
        <p className="mt-4 text-center text-[13px]" style={{ color: 'var(--red)' }}>
          {error}
        </p>
      )}

      <div className="mt-6">
        <button
          disabled={busy}
          onClick={() => {
            const entered = window.prompt(t('mfa.backup'))
            if (entered) submit(entered.trim())
          }}
          className="w-full rounded-[8px] py-2 text-[13px] font-medium hover:bg-[var(--fill)] disabled:opacity-40"
          style={{ color: 'var(--text-secondary)' }}
        >
          {t('mfa.backup')}
        </button>
      </div>
    </AuthFrame>
  )
}

function AuthFrame({
  children,
  title,
  subtitle,
}: {
  children: React.ReactNode
  title: string
  subtitle?: string
}) {
  return (
    <div className="flex h-full items-center justify-center px-4" style={{ background: 'var(--bg)' }}>
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={spring}
        className="w-full max-w-[340px]"
      >
        <div className="mb-7 flex flex-col items-center">
          <div
            className="mb-3 flex h-11 w-11 items-center justify-center rounded-[12px]"
            style={{ background: 'var(--accent)' }}
          >
            <Shield size={22} strokeWidth={2} className="text-white" />
          </div>
          <h1 className="text-[19px] font-semibold tracking-[-0.02em]">{title}</h1>
          <p className="mt-0.5 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
            {subtitle ?? 'Revpd Gateway'}
          </p>
        </div>

        <div
          className="rounded-[16px] border p-6"
          style={{ background: 'var(--surface)', boxShadow: 'var(--shadow-card)' }}
        >
          {children}
        </div>
      </motion.div>
    </div>
  )
}
