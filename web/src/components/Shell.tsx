import { NavLink, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Activity, LayoutGrid, LogOut, Monitor, Moon, Settings2, Shield, Sun, Users } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTheme, cx } from './ui'
import { LanguagePicker } from './LanguagePicker'
import { useT } from '../lib/lang'
import type { Key } from '../lib/i18n'

const nav: { to: string; label: Key; icon: typeof LayoutGrid; end: boolean }[] = [
  { to: '/', label: 'nav.overview', icon: LayoutGrid, end: true },
  { to: '/targets', label: 'nav.targets', icon: Monitor, end: false },
  { to: '/users', label: 'nav.users', icon: Users, end: false },
  { to: '/activity', label: 'nav.activity', icon: Activity, end: false },
  { to: '/settings', label: 'nav.settings', icon: Settings2, end: false },
]

export function Shell({ children }: { children: ReactNode }) {
  const { theme, toggle } = useTheme()
  const { pathname } = useLocation()
  const t = useT()

  const current = nav.find((n) => (n.end ? pathname === n.to : pathname.startsWith(n.to)))

  return (
    <div className="flex h-full">
      <aside
        className="hidden w-[212px] shrink-0 flex-col border-r px-3 py-4 md:flex"
        style={{ background: 'var(--surface-sunken)' }}
      >
        <div className="mb-6 flex items-center gap-2 px-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-[8px]" style={{ background: 'var(--accent)' }}>
            <Shield size={15} strokeWidth={2} className="text-white" />
          </div>
          <span className="text-[15px] font-semibold tracking-[-0.02em]">Revpd</span>
        </div>

        <nav className="flex flex-col gap-0.5">
          {nav.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end}>
              {({ isActive }) => (
                <span
                  className={cx(
                    'relative flex items-center gap-2.5 rounded-[8px] px-2.5 py-[7px] text-[13.5px] transition-colors',
                    !isActive && 'hover:bg-[var(--fill)]',
                  )}
                  style={{ color: isActive ? 'var(--text)' : 'var(--text-secondary)' }}
                >
                  {isActive && (
                    <motion.span
                      layoutId="nav-active"
                      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                      className="absolute inset-0 rounded-[8px]"
                      style={{ background: 'var(--fill)' }}
                    />
                  )}
                  <Icon size={16} strokeWidth={1.75} className="relative" />
                  <span className="relative font-medium">{t(label)}</span>
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto flex flex-col gap-0.5 border-t pt-3">
          <LanguagePicker />
          <button
            onClick={toggle}
            className="flex items-center gap-2.5 rounded-[8px] px-2.5 py-[7px] text-[13.5px] font-medium hover:bg-[var(--fill)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            {theme === 'dark' ? <Sun size={16} strokeWidth={1.75} /> : <Moon size={16} strokeWidth={1.75} />}
            {theme === 'dark' ? t('nav.theme.light') : t('nav.theme.dark')}
          </button>
          <NavLink
            to="/login"
            className="flex items-center gap-2.5 rounded-[8px] px-2.5 py-[7px] text-[13.5px] font-medium hover:bg-[var(--fill)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <LogOut size={16} strokeWidth={1.75} />
            {t('nav.logout')}
          </NavLink>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header
          className="sticky top-0 z-20 flex h-[52px] shrink-0 items-center gap-3 border-b px-5"
          style={{
            background: 'color-mix(in srgb, var(--bg) 82%, transparent)',
            backdropFilter: 'saturate(180%) blur(20px)',
            WebkitBackdropFilter: 'saturate(180%) blur(20px)',
          }}
        >
          <h1 className="text-[15px] font-semibold tracking-[-0.015em]">
            {current ? t(current.label) : 'Revpd'}
          </h1>
          <div className="ml-auto flex items-center gap-1 md:hidden">
            <LanguagePicker compact />
            <button onClick={toggle} aria-label="Theme" className="rounded-md p-1.5 hover:bg-[var(--fill)]">
              {theme === 'dark' ? <Sun size={16} strokeWidth={1.75} /> : <Moon size={16} strokeWidth={1.75} />}
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto px-5 py-6">
          <div className="mx-auto max-w-[760px]">{children}</div>
        </main>

        {/* The sidebar disappears below md; this replaces it. */}
        <nav
          className="flex shrink-0 border-t md:hidden"
          style={{ background: 'var(--surface)', paddingBottom: 'env(safe-area-inset-bottom)' }}
        >
          {nav.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className="flex-1">
              {({ isActive }) => (
                <span
                  className="flex flex-col items-center gap-0.5 py-2 text-[10px] font-medium"
                  style={{ color: isActive ? 'var(--accent)' : 'var(--text-secondary)' }}
                >
                  <Icon size={19} strokeWidth={1.75} />
                  {t(label)}
                </span>
              )}
            </NavLink>
          ))}
        </nav>
      </div>
    </div>
  )
}
