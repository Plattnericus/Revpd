import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Check, Monitor, Radar, Search, TriangleAlert, Zap, ZapOff } from 'lucide-react'
import { Badge, Button, Field, Sheet, spring } from './ui'
import { api, type ApiHost, type ApiRange } from '../lib/api'
import { useT } from '../lib/lang'

/*
  Finding machines instead of typing them in.

  The hardware address is the point. An IP address is easy to read off a
  router; a MAC is not, and a target saved without one looks perfectly fine
  until the machine goes to sleep and never wakes again. Discovery gets it for
  free — connecting to a machine is what teaches the kernel its address — so
  the field nobody can fill in reliably is the one nobody has to.
*/

export function DiscoverSheet({
  open,
  onClose,
  onAdded,
}: {
  open: boolean
  onClose: () => void
  onAdded: () => void
}) {
  const t = useT()

  const [ranges, setRanges] = useState<ApiRange[]>([])
  const [cidr, setCidr] = useState('')
  const [ip, setIp] = useState('')
  const [hosts, setHosts] = useState<ApiHost[] | null>(null)
  const [known, setKnown] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [added, setAdded] = useState<string[]>([])

  const loadRanges = useCallback(async () => {
    try {
      const data = await api.discoverRanges()
      setRanges(data.ranges)
      // Preselect the first range small enough to sweep — on a home network
      // that is the only one, and nobody should have to choose.
      const usable = data.ranges.find((r) => !r.too_large)
      if (usable) setCidr(usable.cidr)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    if (open) {
      loadRanges()
      setHosts(null)
      setAdded([])
      setError('')
    }
  }, [open, loadRanges])

  const run = async (fn: () => Promise<{ hosts: ApiHost[]; known: string[] }>) => {
    setBusy(true)
    setError('')
    setHosts(null)
    try {
      const data = await fn()
      setHosts(data.hosts)
      setKnown(data.known)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const add = async (h: ApiHost) => {
    setError('')
    try {
      await api.createTarget({
        name: suggestName(h),
        ip: h.ip,
        mac: h.mac ?? '',
        rdp_port: h.open_ports.includes(3389) ? 3389 : 3389,
        wol_broadcast: '255.255.255.255',
        boot_timeout_s: 120,
      })
      setAdded((a) => [...a, h.ip])
      onAdded()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <Sheet
      open={open}
      onClose={onClose}
      title={t('discover.title')}
      footer={<Button onClick={onClose}>{t('common.done')}</Button>}
    >
      <p className="mb-4 text-[13px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
        {t('discover.intro')}
      </p>

      {/* Sweep a network. */}
      <div className="flex items-end gap-2">
        <div className="flex-1">
          <label className="mb-1.5 block text-[13px] font-medium">{t('discover.network')}</label>
          <select
            value={cidr}
            disabled={busy}
            onChange={(e) => setCidr(e.target.value)}
            className="h-9 w-full rounded-[10px] border px-2 text-[14px] outline-none"
            style={{ background: 'var(--surface-sunken)', color: 'var(--text)' }}
          >
            {ranges.length === 0 && <option value="">{t('discover.noRanges')}</option>}
            {ranges.map((r) => (
              <option key={r.cidr} value={r.cidr} disabled={r.too_large}>
                {r.cidr} — {r.interface}
                {r.too_large ? ` (${t('discover.tooLarge')})` : ` (${r.hosts})`}
              </option>
            ))}
          </select>
        </div>
        <Button
          variant="primary"
          disabled={busy || !cidr}
          icon={<Radar size={15} strokeWidth={2} className={busy ? 'animate-spin' : undefined} />}
          onClick={() => run(() => api.discoverScan(cidr))}
        >
          {t('discover.scan')}
        </Button>
      </div>

      {/* Or just name one. */}
      <div className="mt-3 flex items-end gap-2">
        <Field
          label={t('discover.oneAddress')}
          placeholder="192.168.1.40"
          value={ip}
          disabled={busy}
          mono
          onChange={(e) => setIp(e.target.value)}
        />
        <Button
          disabled={busy || !ip}
          icon={<Search size={15} strokeWidth={2} />}
          onClick={() => run(() => api.discoverHost(ip))}
        >
          {t('discover.check')}
        </Button>
      </div>

      {busy && (
        <p className="mt-4 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
          {t('discover.searching')}
        </p>
      )}

      {error && (
        <div
          className="mt-4 flex items-start gap-2 rounded-[10px] px-3 py-2.5 text-[13px] leading-relaxed"
          style={{ background: 'var(--red-soft)', color: 'var(--red)' }}
        >
          <TriangleAlert size={14} strokeWidth={2} className="mt-[3px] shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {hosts?.length === 0 && !busy && (
        <p className="mt-5 text-[13px]" style={{ color: 'var(--text-secondary)' }}>
          {t('discover.nothingFound')}
        </p>
      )}

      {hosts && hosts.length > 0 && (
        <div className="mt-5 flex flex-col gap-2">
          {hosts.map((h) => (
            <Found
              key={h.ip}
              host={h}
              already={known.includes(h.ip)}
              added={added.includes(h.ip)}
              onAdd={() => add(h)}
            />
          ))}
        </div>
      )}
    </Sheet>
  )
}

function Found({
  host,
  already,
  added,
  onAdd,
}: {
  host: ApiHost
  already: boolean
  added: boolean
  onAdd: () => void
}) {
  const t = useT()
  const done = already || added

  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={spring}
      className="rounded-[12px] border p-3"
      style={{ background: 'var(--surface-sunken)' }}
    >
      <div className="flex items-start gap-3">
        <OsIcon os={host.os} />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[14px] font-medium">{host.hostname || host.ip}</span>
            {host.distro && <Badge tone="grey">{host.distro}</Badge>}
            {host.suggested && <Badge tone="green">{t('discover.reachable')}</Badge>}
          </div>

          <p className="mt-0.5 font-mono text-[12px]" style={{ color: 'var(--text-secondary)' }}>
            {host.ip}
            {host.mac ? ` · ${host.mac}` : ''}
          </p>

          {/* Whether it can be woken is the thing worth knowing before saving. */}
          <p
            className="mt-1 flex items-center gap-1.5 text-[12px]"
            style={{ color: host.wakeable ? 'var(--green)' : 'var(--orange)' }}
          >
            {host.wakeable ? <Zap size={11} strokeWidth={2} /> : <ZapOff size={11} strokeWidth={2} />}
            {host.wakeable ? t('discover.canWake') : t('discover.cannotWake')}
          </p>

          {host.why.length > 0 && (
            <ul className="mt-1 flex flex-col gap-0.5">
              {host.why.map((w, i) => (
                <li key={i} className="text-[12px]" style={{ color: 'var(--text-tertiary)' }}>
                  {w}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="shrink-0">
          {done ? (
            <span className="inline-flex items-center gap-1 text-[12.5px]" style={{ color: 'var(--green)' }}>
              <Check size={13} strokeWidth={2} />
              {already && !added ? t('discover.already') : t('discover.added')}
            </span>
          ) : (
            <Button size="sm" variant={host.suggested ? 'primary' : 'secondary'} onClick={onAdd}>
              {t('common.add')}
            </Button>
          )}
        </div>
      </div>
    </motion.div>
  )
}

/*
  A picture of what the machine is.

  Drawn rather than fetched: the interface loads nothing from third parties —
  the content security policy forbids it — and a logo would be somebody's
  trademark besides. The shape and colour are enough to tell three categories
  apart at a glance, which is all this needs to do.
*/
function OsIcon({ os }: { os: ApiHost['os'] }) {
  const look = {
    windows: { bg: 'var(--accent-soft)', fg: 'var(--accent)' },
    linux: { bg: 'var(--orange-soft)', fg: 'var(--orange)' },
    macos: { bg: 'var(--grey-soft)', fg: 'var(--grey)' },
    unknown: { bg: 'var(--fill)', fg: 'var(--text-tertiary)' },
  }[os]

  return (
    <div
      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[9px]"
      style={{ background: look.bg }}
      aria-hidden
    >
      {os === 'windows' ? (
        // Four panes: the shape everyone reads as Windows without being a logo.
        <svg width="17" height="17" viewBox="0 0 16 16" fill={look.fg}>
          <rect x="0" y="0" width="7" height="7" rx="1" />
          <rect x="9" y="0" width="7" height="7" rx="1" />
          <rect x="0" y="9" width="7" height="7" rx="1" />
          <rect x="9" y="9" width="7" height="7" rx="1" />
        </svg>
      ) : os === 'linux' ? (
        // A terminal prompt.
        <svg width="17" height="17" viewBox="0 0 16 16" fill="none" stroke={look.fg} strokeWidth="1.8">
          <rect x="1" y="2.5" width="14" height="11" rx="2" />
          <path d="M4.5 6.5 L6.8 8.5 L4.5 10.5" strokeLinecap="round" strokeLinejoin="round" />
          <path d="M8.5 10.5 H11.5" strokeLinecap="round" />
        </svg>
      ) : (
        <Monitor size={17} strokeWidth={1.75} style={{ color: look.fg }} />
      )}
    </div>
  )
}

/** A name worth showing, from whatever the machine gave up. */
function suggestName(h: ApiHost): string {
  if (h.hostname) {
    // Strip the domain: "office-pc.lan" is called "office-pc" by its owner.
    const short = h.hostname.split('.')[0]
    if (short) return short
  }
  if (h.distro) return `${h.distro} (${h.ip})`
  return h.ip
}
