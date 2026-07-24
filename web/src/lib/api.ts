/*
  The real API client. Every screen reads through here — nothing in the UI
  carries its own data any more.

  The CSRF token is handed to us in the login response and echoed back in a
  header on every state-changing request; the cookie is what the server
  compares it against.
*/
import type { AuditEntry, RdpSession, Settings, Target, User } from './types'

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
  }

  /** True when the session is gone and the UI should return to the login. */
  get unauthenticated() {
    return this.status === 401
  }
}

/*
  The CSRF token is read from storage on every request rather than cached in a
  module variable. The server hands out a fresh one on login, on MFA and during
  setup; a cached copy goes stale the moment any of those happens in a part of
  the app that did not go through this client.
*/
export function setCSRF(token: string | undefined) {
  if (token) sessionStorage.setItem('revpd.csrf', token)
}

function currentCSRF(): string {
  return sessionStorage.getItem('revpd.csrf') ?? ''
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const csrf = currentCSRF()
  if (csrf) headers['X-CSRF-Token'] = csrf

  const resp = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (resp.status === 204) return undefined as T

  const text = await resp.text()
  const parsed = text ? safeParse(text) : {}

  if (!resp.ok) {
    throw new ApiError(resp.status, parsed?.error ?? `request failed with ${resp.status}`)
  }

  setCSRF(parsed?.csrf)
  return parsed as T
}

function safeParse(text: string): any {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

const get = <T,>(path: string) => request<T>('GET', path)
const post = <T,>(path: string, body?: unknown) => request<T>('POST', path, body)

/* ------------------------------------------------------------ session --- */

export type LoginResult =
  | { stage: 'mfa'; methods: string[] }
  | { stage: 'full' }

export const api = {
  login: (username: string, password: string) => post<LoginResult>('/api/login', { username, password }),

  verify: (code: string) => post<{ stage: 'full' }>('/api/mfa', { code }),

  logout: async () => {
    await post('/api/logout')
    sessionStorage.removeItem('revpd.csrf')
  },

  me: () =>
    get<{ username: string; display_name: string; role: 'admin' | 'user'; totp_enrolled: boolean }>('/api/me'),

  /* ------------------------------------------------------ first run --- */

  setupStatus: () =>
    get<{ setup_required: boolean; hostname: string; gateway: string; csrf: string }>('/api/setup/status'),

  setupAdmin: (u: { username: string; display_name: string; password: string }) =>
    post<{ id: number; csrf: string }>('/api/setup/admin', u),

  enrollStart: () => post<{ secret: string; uri: string; backup_codes: string[] }>('/api/setup/enroll'),

  enrollConfirm: (code: string) => post<{ ok: boolean }>('/api/setup/enroll/confirm', { code }),

  setupTarget: (t: { name: string; ip: string; mac: string }) => post<{ id: number }>('/api/setup/target', t),

  /* ------------------------------------------------------- passkeys --- */

  passkeys: () => get<{ passkeys: { id: number; name: string; created_at: string }[] }>('/api/passkey'),

  passkeyRegisterBegin: () => post<any>('/api/passkey/register/begin'),

  passkeyRegisterFinish: (name: string, credential: unknown) =>
    post<{ ok: boolean; name: string }>('/api/passkey/register/finish', { name, credential }),

  passkeyLoginBegin: (username: string) =>
    post<{ options: any; csrf: string }>('/api/passkey/login/begin', { username }),

  passkeyLoginFinish: (credential: unknown) =>
    post<{ stage: 'full' }>('/api/passkey/login/finish', { credential }),

  passkeyDelete: (id: number) => request<{ ok: boolean }>('DELETE', `/api/passkey/${id}`),

  /* ---------------------------------------------------------- targets --- */

  targets: () => get<{ targets: ApiTarget[]; gateway: string }>('/api/targets'),

  unlock: (id: number) =>
    post<{ grant_id: number; expires_in: number; gateway: string; target: ApiTarget }>(
      `/api/targets/${id}/unlock`,
    ),

  rdpFileUrl: (id: number) => `/api/targets/${id}/rdpfile`,

  /* ------------------------------------------------------------ admin --- */

  adminTargets: () => get<{ targets: ApiTarget[] }>('/api/admin/targets'),

  createTarget: (t: Partial<ApiTarget>) => post<{ id: number }>('/api/admin/targets', t),

  testWol: (id: number) => post<{ ok: boolean }>(`/api/admin/targets/${id}/testwol`),

  users: () => get<{ users: ApiUser[] }>('/api/admin/users'),

  createUser: (u: { username: string; display_name: string; password: string; role: string; rdp_hint: string }) =>
    post<{ id: number }>('/api/admin/users', u),

  setUserStatus: (id: number, status: 'active' | 'locked' | 'disabled') =>
    post(`/api/admin/users/${id}/status`, { status }),

  setUserTargets: (id: number, targetIds: number[]) =>
    post(`/api/admin/users/${id}/targets`, { target_ids: targetIds }),

  settings: () => get<ApiSettings>('/api/admin/settings'),

  /* -------------------------------------------------------- activity --- */

  sessions: () => get<{ sessions: ApiSession[] }>('/api/sessions'),

  audit: (action?: string) =>
    get<{ entries: ApiAudit[]; chain?: { intact: boolean; count: number } }>(
      '/api/audit' + (action ? `?action=${encodeURIComponent(action)}` : ''),
    ),
}

/* ------------------------------------------------------ wire formats --- */

export interface ApiTarget {
  id: number
  name: string
  hostname: string
  ip: string
  rdp_port: number
  mac: string
  wol_broadcast: string
  boot_timeout_s: number
  notes: string
  state: 'offline' | 'waking' | 'online' | 'unknown'
}

export interface ApiUser {
  id: number
  username: string
  display_name: string
  role: 'admin' | 'user'
  status: 'active' | 'locked' | 'disabled'
  rdp_hint: string
  totp_enrolled: boolean
  target_ids: number[]
}

export interface ApiSession {
  id: number
  user: string
  target: string
  src_ip: string
  started_at: string
}

export interface ApiAudit {
  id: number
  ts: string
  actor: string
  action: string
  object: string
  src_ip: string
  detail: Record<string, unknown>
}

export interface ApiSettings {
  hostname: string
  relay_listen: string
  gateway: string
  grant_ttl_s: number
  reuse_window_s: number
  jit_enabled: boolean
  jit_hold_timeout_s: number
  max_failures: number
  tarpit_s: number
  max_conns_per_ip: number
  rdgw_enabled: boolean
}

/* ------------------------------------------------------- conversions --- */

export function toTarget(t: ApiTarget): Target {
  return {
    id: t.id,
    name: t.name,
    hostname: t.hostname,
    ip: t.ip,
    rdpPort: t.rdp_port,
    mac: t.mac,
    wolBroadcast: t.wol_broadcast,
    bootTimeoutS: t.boot_timeout_s,
    notes: t.notes,
    state: t.state,
  }
}

export function toUser(u: ApiUser): User {
  return {
    id: u.id,
    username: u.username,
    displayName: u.display_name,
    role: u.role,
    status: u.status,
    rdpHint: u.rdp_hint,
    totpEnrolled: u.totp_enrolled,
    passkeys: 0,
    backupCodesLeft: 0,
    targetIds: u.target_ids,
    lastSeen: null,
  }
}

export function toSession(s: ApiSession): RdpSession {
  return {
    id: s.id,
    user: s.user,
    target: s.target,
    srcIp: s.src_ip,
    startedAt: s.started_at,
    bytesIn: 0,
    bytesOut: 0,
  }
}

export function toAudit(e: ApiAudit): AuditEntry {
  return {
    id: e.id,
    ts: e.ts,
    actor: e.actor,
    action: e.action,
    object: e.object,
    srcIp: e.src_ip,
    detail: e.detail ?? {},
  }
}

export function toSettings(s: ApiSettings): Settings {
  return {
    hostname: s.hostname,
    relayListen: s.relay_listen,
    grantTtlS: s.grant_ttl_s,
    reuseWindowS: s.reuse_window_s,
    jitEnabled: s.jit_enabled,
    jitHoldTimeoutS: s.jit_hold_timeout_s,
    duoConfigured: false,
    maxFailures: s.max_failures,
    tarpitS: s.tarpit_s,
    maxConnsPerIp: s.max_conns_per_ip,
  }
}

/* ------------------------------------------------------------ events --- */

/**
 * Subscribes to the live target stream. Returns an unsubscribe function.
 *
 * EventSource reconnects on its own, so a gateway restart or a flaky link
 * heals without the page noticing.
 */
export function subscribeTargets(onTargets: (targets: Target[]) => void): () => void {
  const src = new EventSource('/api/events', { withCredentials: true })

  src.addEventListener('targets', (e) => {
    try {
      const data = JSON.parse((e as MessageEvent).data) as { targets: ApiTarget[] }
      onTargets(data.targets.map(toTarget))
    } catch {
      // A malformed frame is not worth tearing the stream down for.
    }
  })

  return () => src.close()
}
