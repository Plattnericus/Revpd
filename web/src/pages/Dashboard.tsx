import { useCallback, useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { Clock, Copy, Download, Monitor, Power, TriangleAlert } from 'lucide-react'
import { Button, Card, Dot, EmptyState, ProgressRing, spring } from '../components/ui'
import { api, subscribeTargets, toTarget } from '../lib/api'
import { duration } from '../lib/format'
import { useT } from '../lib/lang'
import type { Target } from '../lib/types'

/*
  The main screen, and deliberately the plainest one: a row per machine, a
  status dot, one button. State comes from the server over SSE, so a machine
  someone else woke shows up here too.
*/
export function Dashboard() {
  const t = useT()

  const [targets, setTargets] = useState<Target[] | null>(null)
  const [gateway, setGateway] = useState('')
  const [error, setError] = useState('')

  // Grant countdowns are ours, not the server's: the server reports how long
  // a fresh unlock is good for and we tick it down locally.
  const [expiry, setExpiry] = useState<Record<number, number>>({})
  const wakeStart = useRef<Record<number, number>>({})

  const load = useCallback(async () => {
    try {
      const data = await api.targets()
      setTargets(data.targets.map(toTarget))
      setGateway(data.gateway)
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setTargets([])
    }
  }, [])

  useEffect(() => {
    load()
    return subscribeTargets((next) => {
      setTargets(next)
      setError('')
    })
  }, [load])

  // One timer drives both the wake elapsed counter and the grant countdown.
  useEffect(() => {
    const timer = setInterval(() => {
      setExpiry((prev) => {
        const next: Record<number, number> = {}
        for (const [id, left] of Object.entries(prev)) {
          if (left > 1) next[Number(id)] = left - 1
        }
        return next
      })
      // Re-render so the waking counter advances.
      setTargets((prev) => (prev ? [...prev] : prev))
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  const wake = async (target: Target) => {
    wakeStart.current[target.id] = Date.now()

    // Optimistic: the SSE stream confirms within a couple of seconds.
    setTargets((prev) => prev?.map((x) => (x.id === target.id ? { ...x, state: 'waking' } : x)) ?? prev)

    try {
      const res = await api.unlock(target.id)
      setExpiry((prev) => ({ ...prev, [target.id]: res.expires_in }))
      setGateway(res.gateway)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      load()
    }
  }

  if (targets === null) {
    return <div className="h-24" /> // brief, so a spinner would only flash
  }

  return (
    <div className="flex flex-col gap-4">
      {error && (
        <div
          className="flex items-center gap-2 rounded-[10px] px-3 py-2 text-[13px]"
          style={{ background: 'var(--red-soft)', color: 'var(--red)' }}
        >
          <TriangleAlert size={14} strokeWidth={2} />
          {error}
        </div>
      )}

      {targets.length === 0 ? (
        <Card>
          <EmptyState icon={<Monitor size={20} strokeWidth={1.5} />} title={t('dash.empty')} hint={t('dash.emptyHint')} />
        </Card>
      ) : (
        <>
          <div className="flex flex-col gap-2.5">
            {targets.map((x) => (
              <TargetRow
                key={x.id}
                target={x}
                gateway={gateway}
                expiresIn={expiry[x.id]}
                wakingFor={wakeStart.current[x.id] ? Math.round((Date.now() - wakeStart.current[x.id]!) / 1000) : 0}
                onWake={() => wake(x)}
              />
            ))}
          </div>

          <p className="px-1 text-[12.5px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
            {t('dash.hint')}
          </p>
        </>
      )}
    </div>
  )
}

function TargetRow({
  target,
  gateway,
  expiresIn,
  wakingFor,
  onWake,
}: {
  target: Target
  gateway: string
  expiresIn?: number
  wakingFor: number
  onWake: () => void
}) {
  const t = useT()

  const tone = target.state === 'online' ? 'green' : target.state === 'waking' ? 'orange' : 'grey'
  const label =
    target.state === 'online' ? t('state.online') : target.state === 'waking' ? t('state.waking') : t('state.offline')

  return (
    <Card padded={false}>
      <div className="flex items-center gap-3.5 p-4">
        {target.state === 'waking' ? (
          <ProgressRing progress={wakingFor / Math.max(target.bootTimeoutS, 1)} label={`${wakingFor}s`} />
        ) : (
          <div
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full"
            style={{ background: target.state === 'online' ? 'var(--green-soft)' : 'var(--fill)' }}
          >
            <Monitor
              size={19}
              strokeWidth={1.75}
              style={{ color: target.state === 'online' ? 'var(--green)' : 'var(--text-secondary)' }}
            />
          </div>
        )}

        <div className="min-w-0 flex-1">
          <h3 className="truncate text-[15px] font-semibold tracking-[-0.015em]">{target.name}</h3>
          <p className="mt-0.5 flex items-center gap-1.5 text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
            <Dot tone={tone} pulse={target.state === 'waking'} />
            {label}
          </p>
        </div>

        <div className="shrink-0">
          {target.state !== 'waking' && expiresIn === undefined && (
            <Button variant="primary" icon={<Power size={15} strokeWidth={2} />} onClick={onWake}>
              {t('dash.wake')}
            </Button>
          )}
          {expiresIn !== undefined && (
            <a href={api.rdpFileUrl(target.id)} download>
              <Button variant="secondary" icon={<Download size={15} strokeWidth={1.75} />}>
                {t('dash.download')}
              </Button>
            </a>
          )}
        </div>
      </div>

      <AnimatePresence initial={false}>
        {expiresIn !== undefined && gateway && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={spring}
            className="overflow-hidden"
          >
            <ReadyBar gateway={gateway} expiresIn={expiresIn} />
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  )
}

function ReadyBar({ gateway, expiresIn }: { gateway: string; expiresIn: number }) {
  const t = useT()
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard?.writeText(gateway)
    setCopied(true)
    setTimeout(() => setCopied(false), 1600)
  }

  return (
    <div className="flex flex-wrap items-center gap-2 border-t px-4 py-3" style={{ background: 'var(--surface-sunken)' }}>
      <code className="font-mono text-[13px] font-medium">{gateway}</code>
      <Button size="sm" variant="ghost" icon={<Copy size={13} strokeWidth={1.75} />} onClick={copy}>
        {copied ? t('common.copied') : t('common.copy')}
      </Button>

      <span
        className="tnum ml-auto inline-flex items-center gap-1.5 text-[12.5px] font-medium"
        style={{ color: expiresIn < 30 ? 'var(--orange)' : 'var(--text-secondary)' }}
      >
        <Clock size={13} strokeWidth={1.75} />
        {t('dash.expiresIn')} {duration(expiresIn)}
      </span>
    </div>
  )
}
