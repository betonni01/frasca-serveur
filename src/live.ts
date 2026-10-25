import { randomBytes } from 'node:crypto'

type Ticket = { code: string; name: string; host: boolean; exp: number }
type Peer = { id: string; name: string; host: boolean; send: (data: string) => void }

const tickets = new Map<string, Ticket>()
const rooms = new Map<string, Map<string, Peer>>()
const locks = new Set<string>()

export function issueTicket(code: string, name: string, host = false) {
  const token = randomBytes(24).toString('base64url')
  tickets.set(token, { code, name, host, exp: Date.now() + 1000 * 60 * 2 })
  return token
}

export function isLocked(code: string) {
  return locks.has(code)
}

export function takeTicket(token: string, code: string) {
  const ticket = tickets.get(token)
  tickets.delete(token)
  if (!ticket || ticket.code !== code || ticket.exp < Date.now()) return null
  return ticket
}

export type LiveSession = {
  signal: (to: string, data: unknown) => void
  broadcast: (data: unknown) => void
  leave: () => void
}

export function joinLive(code: string, name: string, host: boolean, send: (data: string) => void): LiveSession | null {
  let room = rooms.get(code)
  if (!room) {
    room = new Map()
    rooms.set(code, room)
  }
  if (room.size >= 12) return null

  const id = randomBytes(8).toString('hex')
  const peers = [...room.values()].map((peer) => ({ id: peer.id, name: peer.name, host: peer.host }))
  const self: Peer = { id, name, host, send }
  room.set(id, self)
  const current = room
  for (const peer of current.values()) {
    if (peer.id !== id) peer.send(JSON.stringify({ type: 'peer-joined', peer: { id, name, host } }))
  }
  send(JSON.stringify({ type: 'welcome', id, host, peers }))

  return {
    signal(to, data) {
      if (rooms.get(code) !== current) return
      current.get(to)?.send(JSON.stringify({ type: 'signal', from: id, data }))
    },
    broadcast(data) {
      if (rooms.get(code) !== current || !data || typeof data !== 'object') return
      const raw = data as { kind?: string; text?: string; raised?: boolean; emoji?: string; image?: string; audio?: string; rate?: number; action?: string; target?: string; mode?: string; active?: boolean }
      let next: Record<string, unknown> | null = null
      if (raw.kind === 'chat') {
        const text = String(raw.text ?? '').trim().slice(0, 200)
        if (!text) return
        next = { kind: 'chat', text }
      } else if (raw.kind === 'hand') {
        next = { kind: 'hand', raised: raw.raised === true }
      } else if (raw.kind === 'reaction') {
        const emoji = String(raw.emoji ?? '').slice(0, 8)
        if (!emoji) return
        next = { kind: 'reaction', emoji }
      } else if (raw.kind === 'frame') {
        const image = String(raw.image ?? '')
        if (image.length < 800 || image.length > 100000) return
        next = { kind: 'frame', image }
      } else if (raw.kind === 'pcm') {
        const audio = String(raw.audio ?? '')
        const rate = Number(raw.rate) || 16000
        if (audio.length < 80 || audio.length > 80000 || rate < 8000 || rate > 48000) return
        next = { kind: 'pcm', audio, rate }
      } else if (raw.kind === 'order') {
        const action = String(raw.action ?? '')
        const hostOnly = action === 'mute-all' || action === 'mute' || action === 'kick' || action === 'lower-hands' || action === 'lock' || action === 'unlock'
        if (hostOnly && !host) return
        if (action === 'kick') {
          const target = String(raw.target ?? '')
          const peer = current.get(target)
          if (!peer) return
          peer.send(JSON.stringify({ type: 'kicked' }))
          current.delete(target)
          for (const other of current.values()) other.send(JSON.stringify({ type: 'peer-left', id: target }))
          return
        }
        if (action === 'lock') locks.add(code)
        if (action === 'unlock') locks.delete(code)
        if (action !== 'mute-all' && action !== 'mute' && action !== 'lower-hands' && action !== 'lock' && action !== 'unlock' && action !== 'record' && action !== 'screen') return
        next = {
          kind: 'order',
          action,
          target: raw.target ? String(raw.target).slice(0, 32) : undefined,
          mode: raw.mode === 'video' ? 'video' : 'audio',
          active: raw.active === true,
        }
      }
      if (!next) return
      const payload = JSON.stringify({ type: 'room', from: id, name, data: next })
      for (const peer of current.values()) {
        if (peer.id !== id) peer.send(payload)
      }
    },
    leave() {
      if (rooms.get(code) !== current || !current.has(id)) return
      current.delete(id)
      if (current.size === 0) rooms.delete(code)
      else {
        for (const peer of current.values()) peer.send(JSON.stringify({ type: 'peer-left', id }))
      }
    },
  }
}

export function closeLive(code: string) {
  const room = rooms.get(code)
  if (!room) return
  for (const peer of room.values()) {
    try {
      peer.send(JSON.stringify({ type: 'closed' }))
    } catch {
      // Le téléphone a déjà quitté.
    }
  }
  rooms.delete(code)
  locks.delete(code)
}
