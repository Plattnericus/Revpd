/*
  Passkeys in the browser.

  The WebAuthn API wants ArrayBuffers where the server speaks base64url, so
  these helpers translate in both directions. Nothing here decides anything —
  every check that matters happens on the server.
*/

// Allocates its own ArrayBuffer rather than using Uint8Array.from, so the
// result is typed as backed by a plain ArrayBuffer. The WebAuthn signatures
// reject a possibly-shared buffer.
const b64ToBytes = (s: string): Uint8Array<ArrayBuffer> => {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/')
  const raw = atob(padded + '=='.slice(0, (4 - (padded.length % 4)) % 4))

  const view = new Uint8Array(new ArrayBuffer(raw.length))
  for (let i = 0; i < raw.length; i++) view[i] = raw.charCodeAt(i)
  return view
}

const bytesToB64 = (b: ArrayBuffer): string => {
  const bytes = new Uint8Array(b)
  let s = ''
  for (const byte of bytes) s += String.fromCharCode(byte)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Passkeys need a secure context; browsers make an exception for localhost. */
export function passkeysAvailable(): boolean {
  return typeof PublicKeyCredential !== 'undefined' && window.isSecureContext
}

/* -------------------------------------------------------- registration --- */

interface RegistrationOptions {
  challenge: string
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  pubKeyCredParams: { type: string; alg: number }[]
  timeout: number
  authenticatorSelection: Record<string, unknown>
  attestation: string
  excludeCredentials: { type: string; id: string }[]
}

export async function createPasskey(options: RegistrationOptions) {
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: b64ToBytes(options.challenge),
      rp: options.rp,
      user: {
        id: b64ToBytes(options.user.id),
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: options.pubKeyCredParams as PublicKeyCredentialParameters[],
      timeout: options.timeout,
      authenticatorSelection: options.authenticatorSelection as AuthenticatorSelectionCriteria,
      attestation: options.attestation as AttestationConveyancePreference,
      excludeCredentials: options.excludeCredentials.map((c) => ({
        type: 'public-key' as const,
        id: b64ToBytes(c.id),
      })),
    },
  })) as PublicKeyCredential | null

  if (!credential) throw new Error('no passkey was created')

  const response = credential.response as AuthenticatorAttestationResponse
  return {
    id: credential.id,
    rawId: bytesToB64(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64(response.clientDataJSON),
      attestationObject: bytesToB64(response.attestationObject),
    },
  }
}

/* ------------------------------------------------------------ assertion --- */

interface AssertionOptions {
  challenge: string
  timeout: number
  rpId: string
  allowCredentials: { type: string; id: string }[]
  userVerification: string
}

export async function usePasskey(options: AssertionOptions) {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: b64ToBytes(options.challenge),
      timeout: options.timeout,
      rpId: options.rpId,
      allowCredentials: options.allowCredentials.map((c) => ({
        type: 'public-key' as const,
        id: b64ToBytes(c.id),
      })),
      userVerification: options.userVerification as UserVerificationRequirement,
    },
  })) as PublicKeyCredential | null

  if (!credential) throw new Error('no passkey was used')

  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: bytesToB64(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64(response.clientDataJSON),
      authenticatorData: bytesToB64(response.authenticatorData),
      signature: bytesToB64(response.signature),
      userHandle: response.userHandle ? bytesToB64(response.userHandle) : '',
    },
  }
}
