import { motion } from 'framer-motion'
import type { ReactNode, ButtonHTMLAttributes, InputHTMLAttributes } from 'react'
import { createContext, useContext, useEffect, useId, useState } from 'react'
import { Check, X } from 'lucide-react'

export const spring = { type: 'spring', stiffness: 400, damping: 30 } as const

export function cx(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(' ')
}

/* ---------------------------------------------------------------- theme --- */

type Theme = 'light' | 'dark'
const ThemeCtx = createContext<{ theme: Theme; toggle: () => void }>({
  theme: 'light',
  toggle: () => {},
})

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('revpd.theme')
    if (saved === 'light' || saved === 'dark') return saved
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('revpd.theme', theme)
  }, [theme])

  // Follow the system until the user makes their own choice.
  useEffect(() => {
    if (localStorage.getItem('revpd.theme')) return
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const on = (e: MediaQueryListEvent) => setTheme(e.matches ? 'dark' : 'light')
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [])

  return (
    <ThemeCtx.Provider value={{ theme, toggle: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')) }}>
      {children}
    </ThemeCtx.Provider>
  )
}

export const useTheme = () => useContext(ThemeCtx)

/* --------------------------------------------------------------- button --- */

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
  icon?: ReactNode
}

export function Button({
  variant = 'secondary',
  size = 'md',
  icon,
  children,
  className,
  // HTML defaults a button inside a form to submit. That turns every "copy"
  // or "test" button into an accidental submit, so default the other way and
  // let the one real submit button say so explicitly.
  type = 'button',
  ...rest
}: ButtonProps) {
  const base =
    'inline-flex items-center justify-center gap-1.5 font-medium select-none transition-colors ' +
    'disabled:opacity-40 disabled:pointer-events-none whitespace-nowrap'

  const sizes = {
    sm: 'h-7 px-2.5 text-[13px] rounded-[7px]',
    md: 'h-9 px-4 text-[14px] rounded-[10px]',
  }

  const variants = {
    primary: 'text-white',
    secondary: '',
    ghost: '',
    danger: 'text-white',
  }

  const style =
    variant === 'primary'
      ? { background: 'var(--accent)' }
      : variant === 'danger'
        ? { background: 'var(--red)' }
        : variant === 'secondary'
          ? { background: 'var(--fill)', color: 'var(--text)' }
          : { color: 'var(--text-secondary)' }

  return (
    <button
      {...rest}
      type={type}
      style={style}
      className={cx(base, sizes[size], variants[variant], variant === 'ghost' && 'hover:bg-[var(--fill)]', className)}
    >
      {icon}
      {children}
    </button>
  )
}

/* ----------------------------------------------------------------- card --- */

export function Card({
  children,
  className,
  padded = true,
}: {
  children: ReactNode
  className?: string
  padded?: boolean
}) {
  return (
    <div
      className={cx('rounded-[14px] border', padded && 'p-5', className)}
      style={{ background: 'var(--surface)', boxShadow: 'var(--shadow-card)' }}
    >
      {children}
    </div>
  )
}

export function SectionTitle({ children, hint }: { children: ReactNode; hint?: string }) {
  return (
    <div className="mb-3">
      <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{children}</h2>
      {hint && (
        <p className="mt-0.5 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
          {hint}
        </p>
      )}
    </div>
  )
}

/* ---------------------------------------------------------------- field --- */

type FieldProps = InputHTMLAttributes<HTMLInputElement> & { label?: string; hint?: string; mono?: boolean }

export function Field({ label, hint, mono, className, ...rest }: FieldProps) {
  const id = useId()
  return (
    <div className="w-full">
      {label && (
        <label htmlFor={id} className="mb-1.5 block text-[13px] font-medium">
          {label}
        </label>
      )}
      <input
        id={id}
        {...rest}
        className={cx(
          'h-9 w-full rounded-[10px] border px-3 text-[14px] outline-none transition-shadow',
          'focus:border-transparent focus:ring-2',
          mono && 'font-mono text-[13px]',
          className,
        )}
        style={{
          background: 'var(--surface-sunken)',
          color: 'var(--text)',
          // @ts-expect-error custom property for the focus ring
          '--tw-ring-color': 'var(--accent)',
        }}
      />
      {hint && (
        <p className="mt-1 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
          {hint}
        </p>
      )}
    </div>
  )
}

/* --------------------------------------------------------------- toggle --- */

export function Toggle({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  hint?: string
}) {
  return (
    <div className="flex items-start justify-between gap-6 py-2.5">
      <div className="min-w-0">
        <div className="text-[14px] font-medium">{label}</div>
        {hint && (
          <p className="mt-0.5 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
            {hint}
          </p>
        )}
      </div>
      <button
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className="relative h-[31px] w-[51px] shrink-0 rounded-full transition-colors"
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

/* ------------------------------------------------------------ segmented --- */

export function Segmented<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T
  options: { value: T; label: string }[]
  onChange: (v: T) => void
}) {
  return (
    <div className="inline-flex rounded-[9px] p-[2px]" style={{ background: 'var(--fill)' }}>
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className="relative rounded-[7px] px-3 py-1 text-[13px] font-medium transition-colors"
          style={{ color: value === o.value ? 'var(--text)' : 'var(--text-secondary)' }}
        >
          {value === o.value && (
            <motion.span
              layoutId="segmented-thumb"
              transition={spring}
              className="absolute inset-0 rounded-[7px]"
              style={{ background: 'var(--surface)', boxShadow: '0 1px 3px rgba(0,0,0,.12)' }}
            />
          )}
          <span className="relative">{o.label}</span>
        </button>
      ))}
    </div>
  )
}

/* --------------------------------------------------------------- status --- */

export type Tone = 'green' | 'orange' | 'red' | 'grey' | 'accent'

const toneVars: Record<Tone, { fg: string; bg: string }> = {
  green: { fg: 'var(--green)', bg: 'var(--green-soft)' },
  orange: { fg: 'var(--orange)', bg: 'var(--orange-soft)' },
  red: { fg: 'var(--red)', bg: 'var(--red-soft)' },
  grey: { fg: 'var(--grey)', bg: 'var(--grey-soft)' },
  accent: { fg: 'var(--accent)', bg: 'var(--accent-soft)' },
}

export function Dot({ tone, pulse }: { tone: Tone; pulse?: boolean }) {
  return (
    <span className="relative inline-flex h-2 w-2 shrink-0">
      {pulse && (
        <motion.span
          className="absolute inset-0 rounded-full"
          style={{ background: toneVars[tone].fg }}
          animate={{ scale: [1, 2.2], opacity: [0.5, 0] }}
          transition={{ duration: 1.6, repeat: Infinity, ease: 'easeOut' }}
        />
      )}
      <span className="relative h-2 w-2 rounded-full" style={{ background: toneVars[tone].fg }} />
    </span>
  )
}

export function Badge({ tone, children, icon }: { tone: Tone; children: ReactNode; icon?: ReactNode }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full px-2 py-[3px] text-[12px] font-medium"
      style={{ background: toneVars[tone].bg, color: toneVars[tone].fg }}
    >
      {icon}
      {children}
    </span>
  )
}

/* ------------------------------------------------------------ progress ---- */

/** Wake progress. Reads as a countdown, not decoration. */
export function ProgressRing({
  progress,
  size = 44,
  label,
}: {
  progress: number
  size?: number
  label?: string
}) {
  const stroke = 3.5
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--fill)" strokeWidth={stroke} />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="var(--orange)"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          animate={{ strokeDashoffset: c * (1 - Math.min(1, Math.max(0, progress))) }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        />
      </svg>
      {label && (
        <span className="tnum absolute inset-0 flex items-center justify-center text-[11px] font-semibold">
          {label}
        </span>
      )}
    </div>
  )
}

/* ----------------------------------------------------------------- misc --- */

export function EmptyState({
  icon,
  title,
  hint,
  action,
}: {
  icon: ReactNode
  title: string
  hint: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      <div
        className="mb-3 flex h-11 w-11 items-center justify-center rounded-full"
        style={{ background: 'var(--fill)', color: 'var(--text-secondary)' }}
      >
        {icon}
      </div>
      <p className="text-[14px] font-medium">{title}</p>
      <p className="mt-1 max-w-xs text-[13px]" style={{ color: 'var(--text-secondary)' }}>
        {hint}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function Row({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cx('flex items-center gap-3 border-b px-5 py-3 last:border-b-0', className)}>{children}</div>
  )
}

export function KeyValue({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5">
      <span className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
        {label}
      </span>
      <span className={cx('text-[13px] font-medium', mono && 'font-mono tnum')}>{value}</span>
    </div>
  )
}

export function Sheet({
  open,
  onClose,
  title,
  children,
  footer,
}: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="absolute inset-0"
        style={{ background: 'rgba(0,0,0,.35)', backdropFilter: 'blur(4px)' }}
        onClick={onClose}
      />
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={spring}
        className="relative w-full max-w-md overflow-hidden rounded-[20px] border"
        style={{ background: 'var(--surface)', boxShadow: 'var(--shadow-sheet)' }}
      >
        <div className="flex items-center justify-between border-b px-5 py-3.5">
          <h3 className="text-[15px] font-semibold">{title}</h3>
          <button onClick={onClose} aria-label="Schließen" className="rounded-md p-1 hover:bg-[var(--fill)]">
            <X size={16} strokeWidth={1.5} style={{ color: 'var(--text-secondary)' }} />
          </button>
        </div>
        <div className="max-h-[60vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t px-5 py-3.5">{footer}</div>}
      </motion.div>
    </div>
  )
}

export function CheckLine({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 py-1 text-[13px]">
      {ok ? (
        <Check size={14} strokeWidth={2} style={{ color: 'var(--green)' }} />
      ) : (
        <X size={14} strokeWidth={2} style={{ color: 'var(--text-tertiary)' }} />
      )}
      <span style={{ color: ok ? 'var(--text)' : 'var(--text-secondary)' }}>{children}</span>
    </div>
  )
}
