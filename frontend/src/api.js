/**
 * MediaShield AI — API Client
 * ============================
 * All fetch calls live here. Components import named functions.
 * Errors are normalized into { message, detail } so the UI has one shape to handle.
 */

const JSON_HEADERS = { 'Content-Type': 'application/json' }

async function handle(res) {
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail || body.error || detail
    } catch {
      /* response wasn't JSON */
    }
    throw new Error(detail)
  }
  return res.json()
}

export async function getHealth() {
  const res = await fetch('/health')
  return handle(res)
}

export async function scanMessage(text) {
  const res = await fetch('/api/scan/message', {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ text }),
  })
  return handle(res)
}

export async function scanImage(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch('/api/scan/image', { method: 'POST', body: form })
  return handle(res)
}

export async function scanAudio(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch('/api/scan/audio', { method: 'POST', body: form })
  return handle(res)
}

export async function scanFull({ image, audio, text }) {
  const form = new FormData()
  if (image) form.append('image', image)
  if (audio) form.append('audio', audio)
  if (text) form.append('text', text)
  const res = await fetch('/api/scan/full', { method: 'POST', body: form })
  return handle(res)
}

export async function verifySource(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch('/api/verify/source', { method: 'POST', body: form })
  return handle(res)
}