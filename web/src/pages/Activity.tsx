import { useEffect, useState } from 'react'
import { Activity as ActivityIcon, ShieldCheck, ShieldAlert, Unplug } from 'lucide-react'
import { Badge, Button, Card, Dot, EmptyState, Segmented, SectionTitle } from '../components/ui'
import { api, toAudit, toSession } from '../lib/api'
import { clockTime, relativeTime } from '../lib/format'
import { useLang, useT } from '../lib/lang'
import type { AuditEntry, RdpSession } from '../lib/types'

type Filter = 'all' | 'security' | 'connections'

/** Rejections and failures are the rows an operator scans for. */
function auditTone(action: string): 'red' | 'orange' | 'green' | 'grey' {
  if (action.endsWith('.fail') || action.endsWith('.rejected') || action.endsWith('.denied') || action === 'lockout')
    return 'red'
  if (action.endsWith('.timeout') || action === 'grant.revoked') return 'orange'
  if (action.endsWith('.ok') || action === 'target.online' || action === 'relay.open') return 'green'
  return 'grey'
}

function matches(action: string, filter: Filter): boolean {
  if (filter === 'security')
    return auditTone(action) === 'red' || action.startsWith('mfa') || action.startsWith('login')
  if (filter === 'connections')
    return action.startsWith('relay') || action.startsWith('grant') || action.startsWith('wol')
  return true
}

export function Activity() {
  const { t, lang } = useLang()
  const [filter, setFilter] = useState<Filter>('all')

  const [sessions, setSessions] = useState<RdpSession[]>([])
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [chain, setChain] = useState<{ intact: boolean; count: number } | null>(null)

  useEffect(() => {
    let live = true

    const load = async () => {
      try {
        const [s, a] = await Promise.all([api.sessions(), api.audit()])
        if (!live) return
        setSessions(s.sessions.map(toSession))
        setEntries(a.entries.map(toAudit))
        setChain(a.chain ?? null)
      } catch {
        // Leave whatever is on screen; the next tick tries again.
      }
    }

    load()
    const timer = setInterval(load, 5000)
    return () => {
      live = false
      clearInterval(timer)
    }
  }, [])

  const shown = entries.filter((e) => matches(e.action, filter))

  return (
    <div className="flex flex-col gap-6">
      <section>
        <SectionTitle>{t('activity.sessions')}</SectionTitle>
        <Card padded={false}>
          {sessions.length === 0 ? (
            <EmptyState
              icon={<ActivityIcon size={20} strokeWidth={1.5} />}
              title={t('activity.noSessions')}
              hint={t('activity.noSessionsHint')}
            />
          ) : (
            sessions.map((s) => (
              <div key={s.id} className="flex items-center gap-3 border-b px-5 py-3.5 last:border-b-0">
                <Dot tone="green" pulse />
                <div className="min-w-0 flex-1">
                  <div className="text-[14px] font-medium">
                    {s.user} <span style={{ color: 'var(--text-tertiary)' }}>→</span> {s.target}
                  </div>
                  <p className="truncate font-mono text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                    {s.srcIp} · {relativeTime(s.startedAt, lang)}
                  </p>
                </div>
                <Button size="sm" variant="ghost" icon={<Unplug size={13} strokeWidth={1.75} />}>
                  {t('activity.disconnect')}
                </Button>
              </div>
            ))
          )}
        </Card>
      </section>

      <section>
        <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{t('activity.log')}</h2>
            {chain && (
              <p
                className="mt-0.5 flex items-center gap-1.5 text-[13px]"
                style={{ color: chain.intact ? 'var(--green)' : 'var(--red)' }}
              >
                {chain.intact ? <ShieldCheck size={13} strokeWidth={2} /> : <ShieldAlert size={13} strokeWidth={2} />}
                {t('activity.chainValid')}
              </p>
            )}
          </div>
          <Segmented
            value={filter}
            onChange={setFilter}
            options={[
              { value: 'all', label: t('activity.filterAll') },
              { value: 'security', label: t('activity.filterSecurity') },
              { value: 'connections', label: t('activity.filterConnections') },
            ]}
          />
        </div>

        <Card padded={false}>
          {shown.length === 0 ? (
            <EmptyState
              icon={<ActivityIcon size={20} strokeWidth={1.5} />}
              title={t('activity.log')}
              hint={t('activity.noSessionsHint')}
            />
          ) : (
            shown.map((e) => (
              <div key={e.id} className="flex items-center gap-3 border-b px-5 py-2.5 last:border-b-0">
                <Dot tone={auditTone(e.action)} />
                {/*
                  The raw event name rather than prose. It is the same string
                  the CLI prints and the docs use, so it reads identically in
                  every language and is what an operator greps for.
                */}
                <span className="w-[180px] shrink-0 truncate font-mono text-[12.5px] font-medium">{e.action}</span>
                <span className="min-w-0 flex-1 truncate text-[13px]" style={{ color: 'var(--text-secondary)' }}>
                  {e.actor && <span className="font-medium">{e.actor}</span>}
                  {e.object && ` · ${e.object}`}
                </span>
                {e.srcIp && (
                  <span
                    className="tnum hidden shrink-0 font-mono text-[12px] md:block"
                    style={{ color: 'var(--text-tertiary)' }}
                  >
                    {e.srcIp}
                  </span>
                )}
                <span
                  className="tnum w-[68px] shrink-0 text-right text-[12px]"
                  style={{ color: 'var(--text-tertiary)' }}
                >
                  {clockTime(e.ts, lang)}
                </span>
              </div>
            ))
          )}
        </Card>
      </section>
    </div>
  )
}

export function Enroll() {
  const t = useT()

  return (
    <div className="mx-auto max-w-[400px]">
      <Card>
        <SectionTitle hint={t('enroll.hint')}>{t('enroll.title')}</SectionTitle>
        <p className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
          <code className="font-mono">revpd enroll -u &lt;name&gt;</code>
        </p>
      </Card>
    </div>
  )
}

export { Badge }
