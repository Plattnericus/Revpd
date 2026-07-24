import { useEffect, useRef, useState } from 'react'
import { Check, Globe } from 'lucide-react'
import { languages, type Lang } from '../lib/i18n'
import { useLang } from '../lib/lang'
import { cx } from './ui'

/** Compact language menu. Ten entries fit without scrolling, so no search box. */
export function LanguagePicker({ compact = false }: { compact?: boolean }) {
  const { lang, setLang, t } = useLang()
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return

    const onClick = (e: MouseEvent) => {
      if (!box.current?.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)

    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div ref={box} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label={t('common.language')}
        aria-expanded={open}
        className="flex w-full items-center gap-2.5 rounded-[8px] px-2.5 py-[7px] text-[13.5px] font-medium hover:bg-[var(--fill)]"
        style={{ color: 'var(--text-secondary)' }}
      >
        <Globe size={16} strokeWidth={1.75} />
        {!compact && languages[lang]}
      </button>

      {open && (
        <div
          className={cx(
            'absolute z-50 w-[176px] overflow-hidden rounded-[12px] border py-1',
            // In the sidebar the button sits at the bottom of the screen, so
            // the menu has to open upward. In the header it must open down, or
            // it lands off-screen and only the last entry stays reachable.
            compact ? 'right-0 top-full mt-1' : 'bottom-full left-0 mb-1',
          )}
          style={{ background: 'var(--surface)', boxShadow: 'var(--shadow-sheet)' }}
        >
          {(Object.keys(languages) as Lang[]).map((code) => (
            <button
              key={code}
              onClick={() => {
                setLang(code)
                setOpen(false)
              }}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-[13.5px] hover:bg-[var(--fill)]"
              style={{ color: 'var(--text)' }}
            >
              <span className="w-4 shrink-0">
                {code === lang && <Check size={13} strokeWidth={2.5} style={{ color: 'var(--accent)' }} />}
              </span>
              {languages[code]}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
