import type { Lang } from './i18n'

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

/** A countdown, so it stays terse: 45s, 2:05 min, 1 h 12 min. */
export function duration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`

  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  if (m < 60) return s === 0 ? `${m} min` : `${m}:${String(s).padStart(2, '0')} min`

  const h = Math.floor(m / 60)
  return `${h} h ${m % 60} min`
}

/*
  Dates go through Intl rather than hand-written strings. It already knows how
  all ten languages phrase "2 minutes ago", including the ones with plural
  rules that do not match English (Polish and Russian both have three forms).
*/

export function relativeTime(iso: string, lang: Lang): string {
  const diff = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' })

  if (diff < 60) return rtf.format(-diff, 'second')
  if (diff < 3600) return rtf.format(-Math.floor(diff / 60), 'minute')
  if (diff < 86400) return rtf.format(-Math.floor(diff / 3600), 'hour')
  return rtf.format(-Math.floor(diff / 86400), 'day')
}

export function clockTime(iso: string, lang: Lang): string {
  return new Date(iso).toLocaleTimeString(lang, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}
