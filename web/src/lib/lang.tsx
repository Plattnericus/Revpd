import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { detectLang, dictionaries, type Key, type Lang } from './i18n'

type Ctx = {
  lang: Lang
  setLang: (l: Lang) => void
  t: (key: Key) => string
}

const LangCtx = createContext<Ctx>({ lang: 'en', setLang: () => {}, t: (k) => k })

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detectLang)

  useEffect(() => {
    document.documentElement.lang = lang
  }, [lang])

  const setLang = (l: Lang) => {
    localStorage.setItem('revpd.lang', l)
    setLangState(l)
  }

  // Falling back to English rather than showing a raw key: a missing string
  // should degrade to readable text, not to `dash.wake`.
  const t = (key: Key) => dictionaries[lang][key] ?? dictionaries.en[key] ?? key

  return <LangCtx.Provider value={{ lang, setLang, t }}>{children}</LangCtx.Provider>
}

export const useLang = () => useContext(LangCtx)

/** Shorthand for components that only need the lookup. */
export function useT() {
  return useLang().t
}
