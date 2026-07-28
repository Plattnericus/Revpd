/*
  Not a runtime test — a compile-time one. `Dict` requires every key, so a
  language missing a string fails `tsc` rather than showing a blank label.
  These checks catch the mistakes types cannot: empty strings, and text that
  was copied from German and never actually translated.

  Run with: npx tsx src/lib/i18n.test.ts
*/
import { dictionaries, languages, type Key, type Lang } from './i18n'
import { settingLabels } from './i18n.settings'
import { settingHints } from './i18n.hints'

const langs = Object.keys(dictionaries) as Lang[]
const keys = Object.keys(dictionaries.de) as Key[]

let failures = 0
const fail = (msg: string) => {
  console.error('FAIL ' + msg)
  failures++
}

// Every advertised language must actually exist.
for (const l of Object.keys(languages) as Lang[]) {
  if (!dictionaries[l]) fail(`language ${l} is listed but has no dictionary`)
}

for (const l of langs) {
  const dict = dictionaries[l]

  for (const k of keys) {
    const v = dict[k]

    if (typeof v !== 'string' || v.trim() === '') {
      fail(`${l}.${k} is empty`)
      continue
    }
    // A stray artefact from editing, e.g. a leftover expression.
    if (v.includes('undefined') || v.includes('[object')) {
      fail(`${l}.${k} looks broken: ${JSON.stringify(v)}`)
    }
  }

  if (Object.keys(dict).length !== keys.length) {
    fail(`${l} has ${Object.keys(dict).length} keys, German has ${keys.length}`)
  }
}

// Words that would mean somebody pasted German into another language. A few
// genuinely shared words (Admin, Port, Gateway, MAC) are excluded.
const germanTells = ['Benutzer', 'Einstellungen', 'Abmelden', 'Passwort', 'Sicherheit', 'Freigabe']
for (const l of langs.filter((x) => x !== 'de')) {
  for (const k of keys) {
    const v = dictionaries[l][k]
    for (const tell of germanTells) {
      if (v.includes(tell)) fail(`${l}.${k} still contains German: ${JSON.stringify(v)}`)
    }
  }
}

/*
  The settings page draws from two more dictionaries, and those are typed as
  plain records rather than by a Key union — a setting can be added to the
  server at any time, so the type cannot be closed. That makes them the place
  where a language quietly falls behind, which is what this checks: English is
  the reference, everything else must match it key for key.
*/
for (const [what, table] of [
  ['label', settingLabels],
  ['hint', settingHints],
] as const) {
  const reference = Object.keys(table.en)

  for (const l of langs) {
    const dict = table[l]
    if (!dict) {
      fail(`${what}s are missing entirely for ${l}`)
      continue
    }

    for (const k of reference) {
      const v = dict[k]
      if (typeof v !== 'string' || v.trim() === '') {
        fail(`${l} has no ${what} for ${k}`)
      }
    }
    for (const k of Object.keys(dict)) {
      if (!reference.includes(k)) {
        fail(`${l} has a ${what} for ${k}, which English does not — a removed setting?`)
      }
    }
  }

  for (const l of langs.filter((x) => x !== 'de' && x !== 'en')) {
    for (const k of reference) {
      for (const tell of germanTells) {
        if (dict(table, l, k).includes(tell)) {
          fail(`${l} ${what} ${k} still contains German: ${JSON.stringify(dict(table, l, k))}`)
        }
      }
    }
  }
}

function dict(table: Record<Lang, Record<string, string>>, l: Lang, k: string): string {
  return table[l]?.[k] ?? ''
}

if (failures > 0) {
  console.error(`\n${failures} problem(s) found`)
  process.exit(1)
}
console.log(
  `ok — ${langs.length} languages x ${keys.length} keys, ` +
    `plus ${Object.keys(settingLabels.en).length} setting names and ` +
    `${Object.keys(settingHints.en).length} hints, all present`,
)
