/*
  The routing rules behind the login, checked on their own.

  Run with: npm run test:session
*/
import { destination, nextAfterLogin, type SessionStatus } from './session'

let failures = 0

function check(status: SessionStatus, pathname: string, want: string | null, why: string) {
  const got = destination(status, pathname)
  if (got === want) return

  failures++
  console.error(`FAIL ${why}\n     destination(${status}, ${pathname}) = ${got}, want ${want}`)
}

/* --------------------------------------------- a gateway with no accounts --- */

for (const path of ['/', '/targets', '/users', '/activity', '/settings', '/login', '/mfa', '/enroll']) {
  check('setup', path, '/setup', `a fresh gateway sends ${path} to the wizard`)
}
check('setup', '/setup', null, 'the wizard itself is where it belongs')

/* --------------------- signed in, wizard never finished --- */

for (const path of ['/', '/targets', '/users', '/activity', '/settings', '/login', '/mfa', '/enroll']) {
  check('onboarding', path, '/setup', `an unfinished wizard sends ${path} back, even though ${path} would work`)
}
check('onboarding', '/setup', null, 'resuming the wizard is where it belongs')

/* ---------------------------------------------------------- signed out --- */

check('out', '/', '/login', 'the overview needs a session')
check('out', '/targets', '/login?next=%2Ftargets', 'and remembers where you were going')
check('out', '/users', '/login?next=%2Fusers', 'for every page behind the login')
check('out', '/settings', '/login?next=%2Fsettings', 'settings included')
check('out', '/enroll', '/login?next=%2Fenroll', 'enrolment included')
check('out', '/login', null, 'the login screen is reachable')

// Between the password and the code the session exists but is not full, so
// /api/me refuses it. Bouncing to /login there would make signing in
// impossible — you could never get past the second factor.
check('out', '/mfa', null, 'the second-factor step stays reachable while half signed in')

/* ----------------------------------------------------------- signed in --- */

for (const path of ['/', '/targets', '/users', '/activity', '/settings', '/enroll']) {
  check('in', path, null, `a signed-in user may open ${path}`)
}
check('in', '/login', '/', 'signing in again is pointless')
check('in', '/mfa', '/', 'so is the second-factor step')
check('in', '/setup', '/', 'and the wizard, on a configured gateway')

/* ------------------------------------------------------- still checking --- */

for (const path of ['/', '/login', '/setup', '/targets']) {
  check('checking', path, null, `nothing is decided before the first answer (${path})`)
}

/* --------------------------------------------------- where login lands --- */

const landings: [string, string, string][] = [
  ['?next=%2Ftargets', '/targets', 'returns to the page that was asked for'],
  ['', '/', 'falls back to the overview'],
  ['?next=', '/', 'ignores an empty next'],

  // A login page that forwards anywhere is worth guarding even when the only
  // thing that writes the parameter is our own redirect.
  ['?next=https%3A%2F%2Fevil.example', '/', 'refuses an absolute URL'],
  ['?next=%2F%2Fevil.example', '/', 'refuses a protocol-relative URL'],
  ['?next=javascript%3Aalert(1)', '/', 'refuses a script URL'],
]

for (const [search, want, why] of landings) {
  const got = nextAfterLogin(search)
  if (got !== want) {
    failures++
    console.error(`FAIL ${why}\n     nextAfterLogin(${search}) = ${got}, want ${want}`)
  }
}

if (failures > 0) {
  console.error(`\n${failures} failed`)
  process.exit(1)
}
console.log('ok — redirect rules hold for setup, an unfinished wizard, signed out, half signed in and signed in')
