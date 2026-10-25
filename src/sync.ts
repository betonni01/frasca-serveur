import { createHash, randomBytes } from 'node:crypto'
import bcrypt from 'bcryptjs'
import { sql } from './db.js'

const ORIGIN = 'https://www.fraternite-saint-carlos-acutis.org'
const DIRECTORY = `${ORIGIN}/espace-membre-de-la-chancellerie`
const STALE_MS = 20 * 60 * 60 * 1000

type Member = { id: string; name: string; path: string }
type NewsItem = { key: string; title: string; body: string | null; label: string | null; url: string | null }
type ImageItem = { key: string; title: string; url: string }

let running: Promise<SyncReport> | null = null

export type SyncReport = {
  members: { seen: number; inserted: number; updated: number }
  news: number
  images: number
  errors: string[]
}

export async function syncIfStale() {
  await sql`
    insert into sync_state (id) values ('site')
    on conflict (id) do nothing
  `
  const rows = await sql<{ last: string | null }[]>`
    select last_success as last from sync_state where id = 'site'
  `
  const last = rows[0]?.last ? new Date(rows[0].last).getTime() : 0
  if (Date.now() - last < STALE_MS) return { skipped: true }
  return syncSite()
}

export function syncSite() {
  running ??= runSync().finally(() => {
    running = null
  })
  return running
}

async function runSync(): Promise<SyncReport> {
  const report: SyncReport = {
    members: { seen: 0, inserted: 0, updated: 0 },
    news: 0,
    images: 0,
    errors: [],
  }
  const [directory, home] = await Promise.all([
    readDirectory(),
    readPage(ORIGIN),
  ])

  if (!directory.ok) report.errors.push('Annuaire inaccessible.')
  else {
    const members = directory.members
    if (members.length === 0) report.errors.push('Annuaire vide, aucune fiche retirée.')
    else report.members = await saveMembers(members)
  }

  if (!home.ok) report.errors.push('Page d’accueil inaccessible.')
  else {
    const news = parseNews(home.html)
    const images = parseImages(home.html)
    if (news.length === 0) report.errors.push('Aucune annonce lue, les précédentes restent.')
    else report.news = await replaceKind('news', news.map((item, position) => ({
      key: item.key,
      title: item.title,
      body: item.body,
      imageUrl: null,
      sourceUrl: item.url,
      label: item.label,
      position,
    })))
    if (images.length === 0) report.errors.push('Aucune image lue, les précédentes restent.')
    else report.images = await replaceKind('image', images.map((item, position) => ({
      key: item.key,
      title: item.title,
      body: null,
      imageUrl: item.url,
      sourceUrl: ORIGIN,
      label: null,
      position,
    })))
  }

  if (report.errors.length === 0) {
    await sql`update sync_state set last_success = now(), last_error = null where id = 'site'`
  } else {
    await sql`update sync_state set last_error = ${report.errors.join(' ')} where id = 'site'`
  }
  return report
}

async function readPage(url: string) {
  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'FRASCA-sync', Accept: 'text/html' },
      signal: AbortSignal.timeout(25000),
    })
    if (!response.ok) return { ok: false as const, html: '' }
    return { ok: true as const, html: await response.text() }
  } catch {
    return { ok: false as const, html: '' }
  }
}

export function parseMembers(html: string): Member[] {
  const seen = new Set<string>()
  const members: Member[] = []
  const pattern = /<a\b[^>]*href="(?:https:\/\/www\.fraternite-saint-carlos-acutis\.org)?(\/espace-membre-de-la-chancellerie\/(\d+)_[^"#?]*)"[^>]*>([\s\S]*?)<\/a>/gi
  for (const match of html.matchAll(pattern)) {
    const id = match[2]
    const name = plain(match[3])
    if (!id || !name || seen.has(id)) continue
    seen.add(id)
    members.push({ id, name: name.slice(0, 200), path: match[1] })
  }
  return members
}

async function readDirectory() {
  const first = await readPage(DIRECTORY)
  if (!first.ok) return { ok: false as const, members: [] as Member[] }
  const members = parseMembers(first.html)
  const seen = new Set(members.map((member) => member.id))
  const elements = [...first.html.matchAll(/id="jw-element-(\d+)"[^>]*class="[^"]*\bjw-news\b/gi)].map((match) => match[1])
  const total = Number((first.html.match(/data-page-total="(\d+)"/) || [])[1] ?? '1')
  for (const elementId of elements) {
    for (let page = 1; page < Math.min(total, 8); page += 1) {
      const url = new URL(DIRECTORY)
      url.searchParams.set(`ep[${elementId}][page]`, String(page))
      const next = await readPage(url.toString())
      if (!next.ok) break
      let added = 0
      for (const member of parseMembers(next.html)) {
        if (seen.has(member.id)) continue
        seen.add(member.id)
        members.push(member)
        added += 1
      }
      if (added === 0) break
    }
  }
  return { ok: true as const, members }
}

export function parseNews(html: string): NewsItem[] {
  const start = html.indexOf('DEBUT CODE EMBED FRASCA')
  const end = html.indexOf('FIN CODE EMBED', start + 1)
  if (start < 0 || end < 0) return []
  const embed = html.slice(start, end)
  const items: NewsItem[] = []
  for (const chunk of embed.split('<div class="fc">').slice(1)) {
    const date = (chunk.match(/<div class="fdate">([\s\S]*?)<\/div>/i) || [])[1]
    const head = (chunk.match(/<div class="fhead">([\s\S]*?)<\/div>/i) || [])[1]
    const sub = (chunk.match(/<div class="fsub">([\s\S]*?)<\/div>/i) || [])[1]
    const title = plain(head ?? '')
    if (!title) continue
    const href = (chunk.match(/href="(https?:\/\/[^"]+)"/i) || [])[1] ?? null
    items.push({
      key: keyFor('news', title, plain(date ?? '')),
      title: title.slice(0, 240),
      body: plain(sub ?? '').slice(0, 2000) || null,
      label: plain(date ?? '').slice(0, 120) || null,
      url: href,
    })
  }
  const grid = /<div class="fni">[\s\S]*?<div class="fncat[^"]*"[^>]*>([\s\S]*?)<\/div>[\s\S]*?<div class="fntxt">([\s\S]*?)<\/div>[\s\S]*?<div class="fndate">([\s\S]*?)<\/div>/gi
  for (const match of embed.matchAll(grid)) {
    const title = plain(match[2])
    if (!title) continue
    items.push({
      key: keyFor('note', title, plain(match[3])),
      title: title.slice(0, 240),
      body: plain(match[1]).slice(0, 200) || null,
      label: plain(match[3]).slice(0, 120) || null,
      url: null,
    })
  }
  return items
}

export function parseImages(html: string): ImageItem[] {
  const seen = new Set<string>()
  const images: ImageItem[] = []
  const pattern = /<img\b[^>]*\b(?:src|data-src)="(https:\/\/primary\.jwwb\.nl\/[^"]+)"[^>]*>/gi
  for (const match of html.matchAll(pattern)) {
    const url = match[1]
    const path = url.split('?')[0].toLowerCase()
    if (path.includes('logo') || seen.has(path)) continue
    seen.add(path)
    const alt = plain((match[0].match(/alt="([^"]*)"/i) || [])[1] ?? '')
    images.push({
      key: path.slice(-180),
      title: (alt || 'Image publiée').slice(0, 180),
      url,
    })
    if (images.length >= 8) break
  }
  return images
}

async function saveMembers(members: Member[]) {
  let inserted = 0
  let updated = 0
  for (const member of members) {
    const existing = await sql<{ id: string }[]>`
      select id from users
      where member_number = ${member.id}
        or profile_path = ${member.path}
        or profile_path like ${'%/' + member.id + '_%'}
      order by (member_number ~ '^[0-9]+$'), created_at
      limit 1
    `
    if (existing[0]) {
      await sql`
        update users set full_name = ${member.name}, profile_path = ${member.path}
        where id = ${existing[0].id}
      `
      updated += 1
      continue
    }
    const email = `site-${member.id.toLowerCase().replace(/[^a-z0-9]/g, '')}@membres.frasca.app`
    const passwordHash = await bcrypt.hash(randomBytes(24).toString('hex'), 4)
    await sql`
      insert into users (
        email, password_hash, role, status, full_name, member_number, profile_path
      ) values (
        ${email}, ${passwordHash}, 'member', 'active', ${member.name}, ${member.id}, ${member.path}
      )
    `
    inserted += 1
  }
  return { seen: members.length, inserted, updated }
}

async function replaceKind(kind: 'news' | 'image', rows: Array<{
  key: string
  title: string
  body: string | null
  imageUrl: string | null
  sourceUrl: string | null
  label: string | null
  position: number
}>) {
  await sql.begin(async (tx) => {
    await tx`delete from site_posts where kind = ${kind}`
    for (const row of rows) {
      await tx`
        insert into site_posts (
          kind, external_key, title, body, image_url, source_url, published_label, position
        ) values (
          ${kind}, ${row.key}, ${row.title}, ${row.body}, ${row.imageUrl},
          ${row.sourceUrl}, ${row.label}, ${row.position}
        )
      `
    }
  })
  return rows.length
}

function plain(value: string) {
  return value
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&eacute;/gi, 'é')
    .replace(/&egrave;/gi, 'è')
    .replace(/&ecirc;/gi, 'ê')
    .replace(/&agrave;/gi, 'à')
    .replace(/&ocirc;/gi, 'ô')
    .replace(/&icirc;/gi, 'î')
    .replace(/&ccedil;/gi, 'ç')
    .replace(/&uuml;/gi, 'ü')
    .replace(/&#(\d+);/g, (_, code: string) => String.fromCodePoint(Number(code)))
    .replace(/\s+/g, ' ')
    .trim()
}

function keyFor(kind: string, title: string, label: string) {
  return createHash('sha256').update(`${kind}\n${title}\n${label}`).digest('hex').slice(0, 32)
}
