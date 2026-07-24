import { useEffect, useState } from 'react'
import { Card, Field, SectionTitle, Badge } from '../components/ui'
import { api, toSettings } from '../lib/api'
import { useT } from '../lib/lang'
import type { Settings as S } from '../lib/types'

/*
  Read-only on purpose. These come from revpd.yaml and the environment, so the
  file stays the single source of truth — a value edited here and then
  overwritten on the next restart would be worse than not offering the edit.
*/
export function Settings() {
  const t = useT()
  const [s, setS] = useState<S | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .settings()
      .then((raw) => setS(toSettings(raw)))
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
  }, [])

  if (error) {
    return (
      <div className="rounded-[10px] px-3 py-2 text-[13px]" style={{ background: 'var(--red-soft)', color: 'var(--red)' }}>
        {error}
      </div>
    )
  }
  if (!s) return <div className="h-24" />

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <SectionTitle>{t('settings.gateway')}</SectionTitle>
        <Field label={t('settings.hostname')} value={s.hostname} mono readOnly />
      </Card>

      <Card>
        <div className="mb-1 flex items-center gap-2">
          <h2 className="text-[15px] font-semibold tracking-[-0.015em]">{t('settings.rdpLogin')}</h2>
          <Badge tone={s.jitEnabled ? 'green' : 'grey'}>{s.jitEnabled ? 'on' : 'off'}</Badge>
        </div>
        <p className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
          {t('settings.rdpLoginHint')}
        </p>
      </Card>

      <Card>
        <SectionTitle>{t('settings.grants')}</SectionTitle>
        <div className="flex gap-3">
          <Field label={`${t('settings.ttl')} (${t('settings.seconds')})`} value={s.grantTtlS} mono readOnly />
          <Field label={`${t('settings.reuse')} (${t('settings.seconds')})`} value={s.reuseWindowS} mono readOnly />
        </div>
      </Card>

      <Card>
        <SectionTitle>{t('settings.security')}</SectionTitle>
        <div className="flex gap-3">
          <Field label={t('settings.maxFailures')} value={s.maxFailures} mono readOnly />
          <Field label={`Tarpit (${t('settings.seconds')})`} value={s.tarpitS} mono readOnly />
          <Field label="Conns/IP" value={s.maxConnsPerIp} mono readOnly />
        </div>
      </Card>

      <p className="px-1 text-[12px]" style={{ color: 'var(--text-tertiary)' }}>
        <code className="font-mono">/etc/revpd/revpd.yaml</code>
      </p>
    </div>
  )
}
