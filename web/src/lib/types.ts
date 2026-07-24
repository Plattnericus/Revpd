export type TargetState = 'offline' | 'waking' | 'online' | 'unknown'

export interface Target {
  id: number
  name: string
  hostname: string
  ip: string
  rdpPort: number
  mac: string
  wolBroadcast: string
  bootTimeoutS: number
  notes: string
  state: TargetState
  /** Seconds elapsed while waking. Only meaningful when state is 'waking'. */
  wakingFor?: number
  /** Seconds left on the grant once the target is ready. */
  grantExpiresIn?: number
}

export type Role = 'admin' | 'user'
export type UserStatus = 'active' | 'locked' | 'disabled'

export interface User {
  id: number
  username: string
  displayName: string
  role: Role
  status: UserStatus
  rdpHint: string
  totpEnrolled: boolean
  passkeys: number
  backupCodesLeft: number
  targetIds: number[]
  lastSeen: string | null
}

export interface RdpSession {
  id: number
  user: string
  target: string
  srcIp: string
  startedAt: string
  bytesIn: number
  bytesOut: number
}

export interface AuditEntry {
  id: number
  ts: string
  actor: string
  action: string
  object: string
  srcIp: string
  detail: Record<string, unknown>
}

export interface Settings {
  hostname: string
  relayListen: string
  grantTtlS: number
  reuseWindowS: number
  jitEnabled: boolean
  jitHoldTimeoutS: number
  duoConfigured: boolean
  maxFailures: number
  tarpitS: number
  maxConnsPerIp: number
}
