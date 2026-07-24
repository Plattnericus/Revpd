import { useEffect, useState } from 'react'
import { Monitor, Plus, Radio } from 'lucide-react'
import { Badge, Button, Card, EmptyState, Field, Sheet } from '../components/ui'
import { api, toTarget } from '../lib/api'
import { useT } from '../lib/lang'
import type { Target } from '../lib/types'

export function Targets() {
  const t = useT()

  const [targets, setTargets] = useState<Target[]>([])
  const [adding, setAdding] = useState(false)
  const [tested, setTested] = useState<number | null>(null)
  const [error, setError] = useState('')

  const [draft, setDraft] = useState({
    name: '',
    hostname: '',
    ip: '',
    rdp_port: 3389,
    mac: '',
    wol_broadcast: '255.255.255.255',
    boot_timeout_s: 120,
    notes: '',
  })

  const load = async () => {
    try {
      const data = await api.adminTargets()
      setTargets(data.targets.map(toTarget))
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  useEffect(() => {
    load()
  }, [])

  const testWol = async (id: number) => {
    setTested(id)
    try {
      await api.testWol(id)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
    setTimeout(() => setTested(null), 2200)
  }

  const create = async () => {
    try {
      await api.createTarget(draft)
      setAdding(false)
      setDraft({ ...draft, name: '', hostname: '', ip: '', mac: '', notes: '' })
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
          {targets.length} {t('targets.count')}
        </p>
        <Button variant="primary" size="sm" icon={<Plus size={14} strokeWidth={2} />} onClick={() => setAdding(true)}>
          {t('targets.add')}
        </Button>
      </div>

      {error && (
        <div
          className="rounded-[10px] px-3 py-2 text-[13px]"
          style={{ background: 'var(--red-soft)', color: 'var(--red)' }}
        >
          {error}
        </div>
      )}

      {targets.length === 0 ? (
        <Card>
          <EmptyState
            icon={<Monitor size={20} strokeWidth={1.5} />}
            title={t('dash.empty')}
            hint={t('dash.emptyHint')}
            action={
              <Button variant="primary" size="sm" icon={<Plus size={14} strokeWidth={2} />} onClick={() => setAdding(true)}>
                {t('targets.add')}
              </Button>
            }
          />
        </Card>
      ) : (
        <Card padded={false}>
          {targets.map((x) => (
            <div key={x.id} className="flex items-center gap-3 border-b px-5 py-3.5 last:border-b-0">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-[14px] font-medium">{x.name}</span>
                  <Badge tone={x.state === 'online' ? 'green' : 'grey'}>
                    {x.state === 'online' ? t('state.online') : t('state.offline')}
                  </Badge>
                </div>
                <p className="truncate font-mono text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                  {x.hostname || x.ip} · {x.mac}
                </p>
              </div>
              <Button size="sm" variant="ghost" icon={<Radio size={13} strokeWidth={1.75} />} onClick={() => testWol(x.id)}>
                {tested === x.id ? t('targets.sent') : t('targets.test')}
              </Button>
            </div>
          ))}
        </Card>
      )}

      <Sheet
        open={adding}
        onClose={() => setAdding(false)}
        title={t('targets.add')}
        footer={
          <>
            <Button size="sm" onClick={() => setAdding(false)}>
              {t('common.cancel')}
            </Button>
            <Button size="sm" variant="primary" onClick={create}>
              {t('common.save')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <Field label={t('targets.name')} value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
          <div className="flex gap-3">
            <Field
              label={t('targets.hostname')}
              value={draft.hostname}
              mono
              onChange={(e) => setDraft({ ...draft, hostname: e.target.value })}
            />
            <Field
              label={t('targets.port')}
              value={draft.rdp_port}
              mono
              className="w-24"
              onChange={(e) => setDraft({ ...draft, rdp_port: Number(e.target.value) || 3389 })}
            />
          </div>
          <Field
            label={t('targets.ip')}
            value={draft.ip}
            mono
            onChange={(e) => setDraft({ ...draft, ip: e.target.value })}
          />
          <Field
            label={t('targets.mac')}
            value={draft.mac}
            mono
            onChange={(e) => setDraft({ ...draft, mac: e.target.value })}
          />
          <div className="flex gap-3">
            <Field
              label={t('targets.broadcast')}
              value={draft.wol_broadcast}
              mono
              onChange={(e) => setDraft({ ...draft, wol_broadcast: e.target.value })}
            />
            <Field
              label={t('targets.bootTimeout')}
              value={draft.boot_timeout_s}
              mono
              className="w-28"
              onChange={(e) => setDraft({ ...draft, boot_timeout_s: Number(e.target.value) || 120 })}
            />
          </div>
          <Field
            label={t('targets.notes')}
            value={draft.notes}
            onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
          />
        </div>
      </Sheet>
    </div>
  )
}
