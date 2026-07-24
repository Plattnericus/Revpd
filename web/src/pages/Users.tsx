import { useEffect, useState } from 'react'
import { KeyRound, Lock, LockOpen, ShieldCheck } from 'lucide-react'
import { Badge, Button, Card, KeyValue, Sheet } from '../components/ui'
import { api, toTarget, toUser } from '../lib/api'
import { useT } from '../lib/lang'
import type { Target, User } from '../lib/types'

export function Users() {
  const t = useT()

  const [users, setUsers] = useState<User[]>([])
  const [targets, setTargets] = useState<Target[]>([])
  const [selected, setSelected] = useState<User | null>(null)
  const [error, setError] = useState('')

  const load = async () => {
    try {
      const [u, tg] = await Promise.all([api.users(), api.adminTargets()])
      setUsers(u.users.map(toUser))
      setTargets(tg.targets.map(toTarget))
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  useEffect(() => {
    load()
  }, [])

  const toggleTarget = async (user: User, targetId: number) => {
    const next = user.targetIds.includes(targetId)
      ? user.targetIds.filter((x) => x !== targetId)
      : [...user.targetIds, targetId]

    try {
      await api.setUserTargets(user.id, next)
      const updated = { ...user, targetIds: next }
      setSelected(updated)
      setUsers((prev) => prev.map((x) => (x.id === user.id ? updated : x)))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const toggleLock = async (user: User) => {
    const next = user.status === 'active' ? 'locked' : 'active'
    try {
      await api.setUserStatus(user.id, next)
      setSelected(null)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
        {users.length} {t('users.count')}
      </p>

      {error && (
        <div
          className="rounded-[10px] px-3 py-2 text-[13px]"
          style={{ background: 'var(--red-soft)', color: 'var(--red)' }}
        >
          {error}
        </div>
      )}

      <Card padded={false}>
        {users.map((u) => (
          <button
            key={u.id}
            onClick={() => setSelected(u)}
            className="flex w-full items-center gap-3 border-b px-5 py-3.5 text-left last:border-b-0 hover:bg-[var(--fill)]"
          >
            <div
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-[13px] font-semibold"
              style={{ background: 'var(--fill)', color: 'var(--text-secondary)' }}
            >
              {(u.displayName || u.username).slice(0, 1).toUpperCase()}
            </div>

            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate text-[14px] font-medium">{u.displayName || u.username}</span>
                {u.role === 'admin' && <Badge tone="accent">{t('users.admin')}</Badge>}
                {u.status !== 'active' && (
                  <Badge tone="red" icon={<Lock size={11} strokeWidth={2} />}>
                    {t('users.locked')}
                  </Badge>
                )}
              </div>
              <p className="truncate font-mono text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                {u.username} · {u.targetIds.length}
              </p>
            </div>

            {u.totpEnrolled ? (
              <ShieldCheck size={15} strokeWidth={1.75} style={{ color: 'var(--green)' }} />
            ) : (
              <KeyRound size={15} strokeWidth={1.75} style={{ color: 'var(--orange)' }} />
            )}
          </button>
        ))}
      </Card>

      <Sheet
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected?.displayName || selected?.username || ''}
        footer={
          selected && (
            <>
              <Button
                size="sm"
                variant="ghost"
                icon={
                  selected.status === 'active' ? (
                    <Lock size={13} strokeWidth={1.75} />
                  ) : (
                    <LockOpen size={13} strokeWidth={1.75} />
                  )
                }
                onClick={() => toggleLock(selected)}
              >
                {t('users.locked')}
              </Button>
              <Button size="sm" variant="primary" onClick={() => setSelected(null)}>
                {t('common.done')}
              </Button>
            </>
          )
        }
      >
        {selected && (
          <div className="flex flex-col gap-4">
            <div>
              <KeyValue label={t('login.username')} value={selected.username} mono />
              <KeyValue label={t('users.role')} value={selected.role === 'admin' ? t('users.admin') : '—'} />
            </div>

            <div className="border-t pt-3">
              <p className="mb-2 text-[13px] font-medium">{t('users.secondFactor')}</p>
              <Badge tone={selected.totpEnrolled ? 'green' : 'orange'} icon={<ShieldCheck size={11} strokeWidth={2} />}>
                {selected.totpEnrolled ? t('users.totpActive') : t('users.totpMissing')}
              </Badge>
            </div>

            <div className="border-t pt-3">
              <p className="mb-2 text-[13px] font-medium">{t('users.allowedTargets')}</p>
              <div className="flex flex-wrap gap-1.5">
                {targets.map((x) => {
                  const on = selected.targetIds.includes(x.id)
                  return (
                    <button
                      key={x.id}
                      onClick={() => toggleTarget(selected, x.id)}
                      className="rounded-full px-2.5 py-1 text-[12px] font-medium transition-colors"
                      style={{
                        background: on ? 'var(--accent-soft)' : 'var(--fill)',
                        color: on ? 'var(--accent)' : 'var(--text-secondary)',
                      }}
                    >
                      {x.name}
                    </button>
                  )
                })}
              </div>
            </div>
          </div>
        )}
      </Sheet>
    </div>
  )
}
