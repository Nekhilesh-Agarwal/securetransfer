const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const TOKEN_KEY = 'sentineldrop_token'
const USERNAME_KEY = 'sentineldrop_username'
const ADMIN_KEY = 'sentineldrop_is_admin'
const SESSION_KEY = 'sentineldrop_session_id'
const PEER_KEY = 'sentineldrop_peer_public_key'
const PAIRED_FINGERPRINT_KEY = 'sentineldrop_paired_fingerprint'

async function parseResponse(response) {
  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    const detail = data.detail
    throw new Error(
      typeof detail === 'string'
        ? detail
        : 'Something went wrong.'
    )
  }

  return data
}

function jsonHeaders(extra = {}) {
  return {
    'Content-Type': 'application/json',
    ...extra,
  }
}

export function localApiUrl() {
  return API_BASE_URL
}

export async function registerUser(username, password) {
  const response = await fetch(`${API_BASE_URL}/auth/register`, {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({ username, password }),
  })
  return parseResponse(response)
}

export async function loginUser(username, password) {
  return storeLoginResponse('/auth/login', username, password)
}

export async function adminLoginUser(username, password) {
  return storeLoginResponse('/auth/admin/login', username, password)
}

async function storeLoginResponse(path, username, password) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({ username, password }),
  })

  const data = await parseResponse(response)
  const token = data.access_token || data.token

  if (!token) {
    throw new Error(
      'Login succeeded, but the server did not return an authentication token.'
    )
  }

  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USERNAME_KEY, data.username || username)
  localStorage.setItem(ADMIN_KEY, data.is_admin ? 'true' : 'false')
  return data
}

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY)
}

export function getStoredUsername() {
  return localStorage.getItem(USERNAME_KEY)
}

export function getStoredIsAdmin() {
  return localStorage.getItem(ADMIN_KEY) === 'true'
}

export function getStoredSessionId() {
  return localStorage.getItem(SESSION_KEY)
}

export function getStoredPeerPublicKey() {
  return localStorage.getItem(PEER_KEY)
}

export function storePeerPublicKey(publicKey) {
  if (publicKey) {
    localStorage.setItem(PEER_KEY, publicKey)
  }
}

export function getPairedFingerprintKey() {
  return PAIRED_FINGERPRINT_KEY
}

export async function logoutUser() {
  const token = getStoredToken()
  if (token) {
    await fetch(`${API_BASE_URL}/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    }).catch(() => {})
  }
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USERNAME_KEY)
  localStorage.removeItem(ADMIN_KEY)
  localStorage.removeItem(SESSION_KEY)
  localStorage.removeItem(PEER_KEY)
}

export async function authenticatedFetch(path, options = {}) {
  const token = getStoredToken()
  if (!token) {
    throw new Error('You are not signed in.')
  }

  const headers = new Headers(options.headers || {})
  headers.set('Authorization', `Bearer ${token}`)

  if (
    options.body &&
    typeof options.body === 'object' &&
    !(options.body instanceof FormData) &&
    !headers.has('Content-Type')
  ) {
    headers.set('Content-Type', 'application/json')
    options.body = JSON.stringify(options.body)
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  })

  return parseResponse(response)
}

export async function getLocalPairingInfo() {
  return authenticatedFetch('/devices/me/pairing')
}

export async function getMyPairingQrObjectUrl() {
  const token = getStoredToken()
  const response = await fetch(`${API_BASE_URL}/devices/me/pairing/qr`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!response.ok) {
    throw new Error('Unable to load pairing QR.')
  }
  const blob = await response.blob()
  return URL.createObjectURL(blob)
}

export async function preparePairing(payload) {
  return authenticatedFetch('/devices/pairing/prepare', {
    method: 'POST',
    body: { payload },
  })
}

export async function confirmPairing(payload, fingerprint) {
  const data = await authenticatedFetch('/devices/pairing/confirm', {
    method: 'POST',
    body: { payload, fingerprint },
  })
  storePeerPublicKey(data.public_key)
  if (data.fingerprint) {
    localStorage.setItem(PAIRED_FINGERPRINT_KEY, data.fingerprint)
  }
  return data
}

export async function getSecurityDashboard() {
  return authenticatedFetch('/security/dashboard')
}

export async function getAuditEvents() {
  return authenticatedFetch('/audit/events')
}

export async function verifyAudit() {
  return authenticatedFetch('/audit/verify')
}

export async function getAdminMessageLogs() {
  return authenticatedFetch('/admin/message-logs')
}

export async function getAdminMessageLog(messageId) {
  return authenticatedFetch(`/admin/message-logs/${messageId}`)
}

export async function getAdminMonitorStatus() {
  return authenticatedFetch('/admin/monitor/status')
}

export async function runAdminImageMetrics(file) {
  const body = new FormData()
  body.append('image', file)
  return authenticatedFetch('/admin/evaluation/image-metrics', {
    method: 'POST',
    body,
  })
}

export async function runAdminPerformanceBenchmark() {
  return authenticatedFetch('/admin/evaluation/benchmark', {
    method: 'POST',
  })
}

export async function runAdminTextAnalysis(text) {
  return authenticatedFetch('/admin/evaluation/text-analysis', {
    method: 'POST',
    body: { text },
  })
}

export async function establishSecureSession(peerPublicKey = getStoredPeerPublicKey()) {
  if (!peerPublicKey) {
    throw new Error('Pair and trust the other device before opening a session.')
  }

  const opened = await authenticatedFetch('/sessions/open', {
    method: 'POST',
    body: { device_public_key: peerPublicKey },
  })
  localStorage.setItem(SESSION_KEY, opened.session_id)
  return opened.session_id
}

export async function sendMessage(sessionId, message, messageType = 'text') {
  return authenticatedFetch('/messages/send', {
    method: 'POST',
    body: {
      session_id: sessionId,
      message,
      message_type: messageType,
    },
  })
}

export async function listPendingMessages() {
  return authenticatedFetch('/messages/pending')
}

export async function receiveMessage(encryptedMessage) {
  return authenticatedFetch('/messages/receive', {
    method: 'POST',
    body: encryptedMessage,
  })
}

export async function receiveFile(encryptedFile) {
  return authenticatedFetch('/files/receive-encrypted', {
    method: 'POST',
    body: encryptedFile,
  })
}

export async function listReceivedFiles() {
  return authenticatedFetch('/files/received')
}

export function receivedFileUrl(filename) {
  return `${API_BASE_URL}/files/received/${encodeURIComponent(filename)}`
}

export async function downloadReceivedFile(filename) {
  const token = getStoredToken()
  const response = await fetch(receivedFileUrl(filename), {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    throw new Error(
      typeof data.detail === 'string' ? data.detail : 'Unable to download the file.'
    )
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export async function prepareFile(sessionId, file, messageType = 'image') {
  const token = getStoredToken()
  const form = new FormData()
  form.append('session_id', sessionId)
  form.append('message_type', messageType)
  form.append('mime_type', file.type || 'application/octet-stream')
  form.append('file', file)

  const response = await fetch(`${API_BASE_URL}/files/prepare`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  })
  return parseResponse(response)
}

export async function transcribeVoice(wavBlob) {
  const token = getStoredToken()
  const form = new FormData()
  form.append('file', wavBlob, 'note.wav')
  const response = await fetch(`${API_BASE_URL}/voice/transcribe`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  })
  return parseResponse(response)
}
