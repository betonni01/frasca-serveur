import 'dotenv/config'
import { createHmac, randomInt, timingSafeEqual } from 'node:crypto'
import { serve } from '@hono/node-server'
import { createNodeWebSocket } from '@hono/node-ws'
import bcrypt from 'bcryptjs'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { z } from 'zod'
import { migrate, sql } from './db.js'
import { syncIfStale, syncSite } from './sync.js'
import { closeLive, isLocked, issueTicket, joinLive, takeTicket, type LiveSession } from './live.js'

type Profile = {
  id: string
  email: string | null
  role: 'candidate' | 'member'
  status: 'pending' | 'active'
  fullName: string
  phone: string | null
  dioceseName: string | null
  parishName: string | null
  memberNumber: string | null
  siteCode: string | null
  profilePath: string | null
  country: string | null
  profession: string | null
}

const app = new Hono()
const { injectWebSocket, upgradeWebSocket } = createNodeWebSocket({ app })
app.use('*', cors())

function secret() {
  const value = process.env.JWT_SECRET
  if (!value) throw new Error('JWT_SECRET manquant')
  return value
}

function signToken(userId: string) {
  const body = Buffer.from(JSON.stringify({ sub: userId, exp: Date.now() + 1000 * 60 * 60 * 24 * 30 })).toString('base64url')
  const signature = createHmac('sha256', secret()).update(body).digest('base64url')
  return `${body}.${signature}`
}

function readToken(header: string | undefined) {
  if (!header?.startsWith('Bearer ')) return null
  const token = header.slice(7)
  const [body, signature] = token.split('.')
  if (!body || !signature) return null
  const expected = createHmac('sha256', secret()).update(body).digest('base64url')
  const left = Buffer.from(signature)
  const right = Buffer.from(expected)
  if (left.length !== right.length || !timingSafeEqual(left, right)) return null
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString()) as { sub: string; exp: number }
  if (payload.exp < Date.now()) return null
  return payload.sub
}

async function profileById(id: string): Promise<Profile | null> {
  const rows = await sql<Profile[]>`
    select
      u.id,
      case when u.email like '%@membres.frasca.app' then null else u.email end as email,
      u.role,
      u.status,
      u.full_name as "fullName",
      u.phone,
      u.member_number as "memberNumber",
      u.site_code as "siteCode",
      u.profile_path as "profilePath",
      u.country,
      u.profession,
      d.name as "dioceseName",
      p.name as "parishName"
    from users u
    left join delegations d on d.id = u.diocese_id
    left join delegations p on p.id = u.parish_id
    where u.id = ${id}
  `
  return rows[0] ?? null
}

function fail(error: z.ZodError) {
  return error.issues[0]?.message ?? 'Informations incomplètes.'
}

app.get('/', (c) =>
  c.html(`<!doctype html>
<html lang="fr">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FRASCA</title>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#F3F1EE;color:#1C1412;font-family:Georgia,serif">
  <main style="max-width:28rem;padding:2.5rem 1.5rem;text-align:center">
    <p style="letter-spacing:.18em;font-size:.75rem;color:#6B1D2A">FRATERNITÉ SAINT CARLO ACUTIS</p>
    <h1 style="font-weight:500;font-size:2rem;margin:.4rem 0 1rem">Serveur en ligne</h1>
    <p style="line-height:1.5">Cette adresse sert à l’application. Ouvrez FRASCA sur le téléphone pour vous connecter.</p>
  </main>
</body>`),
)

app.get('/health', (c) => c.json({ ok: true }))

app.get('/site/feed', async (c) => {
  const rows = await sql<{
    kind: 'news' | 'image'
    title: string
    body: string | null
    imageUrl: string | null
    sourceUrl: string | null
    publishedLabel: string | null
    updatedAt: string
  }[]>`
    select kind, title, body, image_url as "imageUrl", source_url as "sourceUrl",
      published_label as "publishedLabel", updated_at as "updatedAt"
    from site_posts
    order by kind, position
  `
  const updatedAt = rows.reduce<string | null>((latest, row) => {
    if (!latest || row.updatedAt > latest) return row.updatedAt
    return latest
  }, null)
  return c.json({
    updatedAt,
    news: rows.filter((row) => row.kind === 'news').map(({ kind: _kind, imageUrl: _imageUrl, ...row }) => row),
    images: rows.filter((row) => row.kind === 'image').map((row) => ({
      title: row.title,
      url: row.imageUrl,
    })),
  })
})

app.post('/internal/sync', async (c) => {
  const expected = process.env.SYNC_SECRET
  const given = c.req.header('x-sync-secret')
  if (!expected || !given || given.length !== expected.length) return c.json({ error: 'Non autorisé.' }, 401)
  const valid = timingSafeEqual(Buffer.from(given), Buffer.from(expected))
  if (!valid) return c.json({ error: 'Non autorisé.' }, 401)
  return c.json(await syncSite())
})

app.get('/delegations', async (c) => {
  const rows = await sql`
    select id, name, level, country, parent_id as "parentId"
    from delegations
    order by country, name
  `
  return c.json(rows)
})

app.post('/auth/login', async (c) => {
  const parsed = z.object({
    email: z.string().trim().email('Indiquez un e-mail valide.'),
    password: z.string().min(1, 'Indiquez le mot de passe.'),
  }).safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) return c.json({ error: fail(parsed.error) }, 400)

  const email = parsed.data.email.toLowerCase()
  const rows = await sql<{ id: string; password_hash: string }[]>`
    select id, password_hash from users where email = ${email}
  `
  const user = rows[0]
  if (!user || !(await bcrypt.compare(parsed.data.password, user.password_hash))) {
    return c.json({ error: 'E-mail ou mot de passe incorrect.' }, 401)
  }
  const profile = await profileById(user.id)
  return c.json({ token: signToken(user.id), profile })
})

function fold(value: string) {
  return value.toLowerCase().normalize('NFD').replace(/\p{M}/gu, '').replace(/[^a-z0-9]/g, '')
}

app.post('/auth/identifier', async (c) => {
  const parsed = z.object({
    identifier: z.string().trim().min(2, 'Indiquez votre identifiant.'),
  }).safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) return c.json({ error: fail(parsed.error) }, 400)

  const query = parsed.data.identifier
  const folded = fold(query)
  const rows = await sql<{ id: string; member_number: string; site_code: string | null; full_name: string }[]>`
    select id, member_number, site_code, full_name
    from users
    where role = 'member' and status = 'active' and member_number is not null
  `
  let matches = rows.filter((row) => fold(row.member_number) === folded || (row.site_code !== null && fold(row.site_code) === folded))
  if (matches.length === 0 && /\d/.test(folded)) {
    matches = rows.filter((row) => fold(row.member_number).replace(/[a-z]+$/, '') === folded)
  }
  if (matches.length === 0 && /^\d{5,}$/.test(query)) {
    matches = rows.filter((row) => row.member_number.replace(/\D/g, '') === query)
  }
  if (matches.length === 0) {
    matches = rows.filter((row) => fold(row.full_name) === folded)
  }
  if (matches.length === 0) {
    const words = query.split(/\s+/).map(fold).filter((word) => word.length >= 3)
    if (words.length > 0) {
      matches = rows.filter((row) => {
        const name = fold(row.full_name)
        return words.every((word) => name.includes(word))
      })
    }
  }
  if (matches.length > 1) {
    return c.json({ error: 'Plusieurs membres correspondent. Indiquez l’identifiant complet.' }, 409)
  }
  if (matches.length === 0) {
    return c.json({ error: 'Identifiant non reconnu.' }, 401)
  }
  const profile = await profileById(matches[0].id)
  return c.json({ token: signToken(matches[0].id), profile })
})

app.get('/me', async (c) => {
  const id = readToken(c.req.header('authorization'))
  if (!id) return c.json({ error: 'Connexion requise.' }, 401)
  const profile = await profileById(id)
  if (!profile) return c.json({ error: 'Compte introuvable.' }, 401)
  return c.json(profile)
})

const candidatureSchema = z.object({
  fullName: z.string().trim().min(3, 'Indiquez votre nom et votre prénom.'),
  email: z.string().trim().email('Indiquez un e-mail valide.'),
  password: z.string().min(8, 'Le mot de passe doit contenir au moins 8 caractères.'),
  phone: z.string().trim().min(6, 'Indiquez un numéro de téléphone.'),
  birthDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'La date de naissance suit le format AAAA-MM-JJ.'),
  birthPlace: z.string().trim().min(2, 'Indiquez le lieu de naissance.'),
  address: z.string().trim().min(5, 'Indiquez l’adresse.'),
  profession: z.string().trim().min(2, 'Indiquez la profession.'),
  dioceseId: z.string().uuid('Choisissez un diocèse.'),
  parishId: z.string().uuid('Choisissez une paroisse.'),
  oathPlace: z.string().trim().min(2, 'Indiquez le lieu de l’engagement.'),
  oathOn: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'La date d’engagement suit le format AAAA-MM-JJ.'),
  oathAccepted: z.literal(true, { errorMap: () => ({ message: 'L’engagement est nécessaire pour adhérer.' }) }),
})

app.post('/auth/candidature', async (c) => {
  const parsed = candidatureSchema.safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) return c.json({ error: fail(parsed.error) }, 400)
  const body = parsed.data
  const email = body.email.toLowerCase()

  const parish = await sql<{ parent_id: string }[]>`
    select parent_id from delegations where id = ${body.parishId} and level = 'parish'
  `
  if (parish.length === 0 || parish[0].parent_id !== body.dioceseId) {
    return c.json({ error: 'Choisissez une paroisse de ce diocèse.' }, 400)
  }

  const passwordHash = await bcrypt.hash(body.password, 10)
  try {
    const inserted = await sql<{ id: string }[]>`
      insert into users (
        email, password_hash, role, status, full_name, phone,
        birth_date, birth_place, address, profession,
        diocese_id, parish_id, oath_place, oath_on
      ) values (
        ${email}, ${passwordHash}, 'candidate', 'pending', ${body.fullName}, ${body.phone},
        ${body.birthDate}, ${body.birthPlace}, ${body.address}, ${body.profession},
        ${body.dioceseId}, ${body.parishId}, ${body.oathPlace}, ${body.oathOn}
      )
      returning id
    `
    const profile = await profileById(inserted[0].id)
    return c.json({ token: signToken(inserted[0].id), profile }, 201)
  } catch (error) {
    if (typeof error === 'object' && error && 'code' in error && error.code === '23505') {
      return c.json({ error: 'Un compte existe déjà avec cet e-mail.' }, 409)
    }
    throw error
  }
})

const massSchema = z.object({
  fullName: z.string().trim().min(3, 'Indiquez votre nom.'),
  email: z.string().trim().email('Indiquez un e-mail valide.'),
  kind: z.enum(['action de grâce', 'pour un défunt', 'pour un malade', 'pour une vocation', 'intention personnelle']),
  forWhom: z.string().trim().min(2, 'Indiquez pour qui cette messe est demandée.'),
  intention: z.string().trim().min(5, 'Écrivez l’intention.'),
  preferredDate: z.union([z.string().regex(/^\d{4}-\d{2}-\d{2}$/), z.literal('')]).optional(),
})

const requestSchemas = {
  academy: z.object({
    kind: z.literal('academy'),
    cycle: z.enum(['fondamentale', 'avancee', 'executive'], { errorMap: () => ({ message: 'Choisissez un cycle.' }) }),
    mode: z.enum(['distance', 'presentiel'], { errorMap: () => ({ message: 'Choisissez une modalité.' }) }),
    note: z.string().trim().max(400, 'La note est trop longue.').optional().default(''),
  }),
  subsidy: z.object({
    kind: z.literal('subsidy'),
    regime: z.enum(['omnia', 'medio', 'himself'], { errorMap: () => ({ message: 'Choisissez un régime.' }) }),
    title: z.string().trim().min(3, 'Indiquez le titre de la mission.'),
    detail: z.string().trim().min(10, 'Décrivez la mission.'),
  }),
  shop: z.object({
    kind: z.literal('shop'),
    wish: z.string().trim().min(5, 'Indiquez ce que vous cherchez.'),
  }),
  chancery: z.object({
    kind: z.literal('chancery'),
    subject: z.enum(['concours', 'recompense'], { errorMap: () => ({ message: 'Choisissez concours ou récompense.' }) }),
    detail: z.string().trim().min(10, 'Décrivez la demande.'),
  }),
  contact: z.object({
    kind: z.literal('contact'),
    fullName: z.string().trim().min(2, 'Indiquez votre nom.'),
    email: z.string().trim().email('Indiquez un e-mail valide.'),
    message: z.string().trim().min(10, 'Écrivez votre message.'),
  }),
  newsletter: z.object({
    kind: z.literal('newsletter'),
    email: z.string().trim().email('Indiquez un e-mail valide.'),
  }),
  listening: z.object({
    kind: z.literal('listening'),
    fullName: z.string().trim().min(2, 'Indiquez votre nom.'),
    email: z.string().trim().email('Indiquez un e-mail valide.'),
    message: z.string().trim().min(10, 'Dites ce dont vous avez besoin.'),
  }),
  booklet: z.object({
    kind: z.literal('booklet'),
    fullName: z.string().trim().min(2, 'Indiquez votre nom.'),
    email: z.string().trim().email('Indiquez un e-mail valide.'),
    which: z.enum(['jeudi', 'adoration', 'solidarite', 'evangelisation'], { errorMap: () => ({ message: 'Choisissez un livret.' }) }),
  }),
  project: z.object({
    kind: z.literal('project'),
    title: z.string().trim().min(3, 'Indiquez le titre du projet.'),
    detail: z.string().trim().min(10, 'Décrivez le projet.'),
    level: z.enum(['paroissial', 'diocesain', 'national', 'regional', 'international'], { errorMap: () => ({ message: 'Choisissez un niveau.' }) }),
    duration: z.string().trim().min(2, 'Indiquez la durée.'),
    result: z.string().trim().min(5, 'Indiquez le résultat attendu.'),
    beneficiaries: z.string().trim().min(2, 'Indiquez les bénéficiaires.'),
  }),
  contest: z.object({
    kind: z.literal('contest'),
    activity: z.string().trim().min(2, 'Choisissez une activité.'),
    note: z.string().trim().max(400, 'La note est trop longue.').optional().default(''),
  }),
  programme: z.object({
    kind: z.literal('programme'),
    programme: z.string().trim().min(2, 'Choisissez un programme.'),
    note: z.string().trim().max(400, 'La note est trop longue.').optional().default(''),
  }),
}

const publicKinds = new Set(['contact', 'newsletter', 'listening', 'booklet'])

app.post('/requests', async (c) => {
  const raw = await c.req.json().catch(() => null) as { kind?: string } | null
  const kind = raw?.kind
  if (!kind || !(kind in requestSchemas)) return c.json({ error: 'Cette demande n’est pas reconnue.' }, 400)

  const tokenUser = readToken(c.req.header('authorization'))
  const profile = tokenUser ? await profileById(tokenUser) : null
  if (!publicKinds.has(kind) && !profile) {
    return c.json({ error: 'Connectez-vous pour envoyer cette demande.' }, 401)
  }

  const parsed = requestSchemas[kind as keyof typeof requestSchemas].safeParse(raw)
  if (!parsed.success) return c.json({ error: fail(parsed.error) }, 400)

  const payload = profile && !publicKinds.has(kind)
    ? {
        ...parsed.data,
        fullName: profile.fullName,
        role: profile.role,
        ...(profile.email ? { email: profile.email } : {}),
      }
    : parsed.data
  const rows = await sql<{ id: string }[]>`
    insert into service_requests (user_id, kind, payload)
    values (${profile?.id ?? null}, ${kind}, ${sql.json(payload)})
    returning id
  `
  return c.json({ id: rows[0].id }, 201)
})

app.post('/mass-intentions', async (c) => {
  const parsed = massSchema.safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) return c.json({ error: fail(parsed.error) }, 400)
  const body = parsed.data
  const date = body.preferredDate ? body.preferredDate : null
  const rows = await sql<{ id: string }[]>`
    insert into mass_intentions (full_name, email, kind, for_whom, intention, preferred_date)
    values (${body.fullName}, ${body.email.toLowerCase()}, ${body.kind}, ${body.forWhom}, ${body.intention}, ${date})
    returning id
  `
  return c.json({ id: rows[0].id }, 201)
})

const gatheringKinds = ['prayer', 'meeting', 'call'] as const

function gatheringCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  let value = ''
  for (let index = 0; index < 6; index += 1) value += alphabet[randomInt(alphabet.length)]
  return value
}

function foldName(value: string) {
  return value.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase()
}

function callWhen(startsAt: string | null) {
  if (!startsAt) return 'maintenant'
  const date = new Date(startsAt)
  if (Number.isNaN(date.getTime()) || date.getTime() - Date.now() < 60_000) return 'maintenant'
  return date.toLocaleString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' })
}

function spacedCode(code: string) {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code
}

async function delegatesOf(gatheringId: string) {
  return sql<{ id: string; fullName: string }[]>`
    select u.id, u.full_name as "fullName"
    from gathering_delegates d
    join users u on u.id = d.user_id
    where d.gathering_id = ${gatheringId}
    order by d.created_at
  `
}

async function viewerManages(gatheringId: string, hostId: string, viewer: string | null) {
  if (!viewer) return false
  if (viewer === hostId) return true
  const rows = await sql<{ ok: number }[]>`
    select 1 as ok
    from gathering_delegates
    where gathering_id = ${gatheringId} and user_id = ${viewer}
    limit 1
  `
  return rows.length > 0
}

app.get('/people', async (c) => {
  const viewer = readToken(c.req.header('authorization'))
  if (!viewer) return c.json({ error: 'Connectez-vous pour chercher une personne.' }, 401)
  const query = foldName((c.req.query('q') ?? '').trim())
  if (query.length < 2) return c.json([])
  const rows = await sql<{ id: string; fullName: string }[]>`
    select id, full_name as "fullName"
    from users
    where status = 'active' and id <> ${viewer}
  `
  const matches = rows.filter((row) => foldName(row.fullName).includes(query)).slice(0, 8)
  return c.json(matches)
})

app.get('/notifications', async (c) => {
  const viewer = readToken(c.req.header('authorization'))
  if (!viewer) return c.json({ error: 'Connectez-vous pour voir vos invitations.' }, 401)
  const rows = await sql`
    select id, kind, title, body, code, read_at as "readAt", created_at as "createdAt"
    from notifications
    where user_id = ${viewer}
    order by created_at desc
    limit 20
  `
  return c.json(rows)
})

app.post('/notifications/read', async (c) => {
  const viewer = readToken(c.req.header('authorization'))
  if (!viewer) return c.json({ error: 'Connectez-vous.' }, 401)
  const parsed = z.object({
    ids: z.array(z.string().uuid()).max(20),
  }).safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) return c.json({ error: 'Lecture impossible.' }, 400)
  if (parsed.data.ids.length > 0) {
    await sql`
      update notifications
      set read_at = now()
      where user_id = ${viewer}
        and read_at is null
        and id in ${sql(parsed.data.ids)}
    `
  }
  return c.json({ ok: true })
})

app.get('/gatherings', async (c) => {
  const viewer = readToken(c.req.header('authorization'))
  const rows = await sql<Array<{ id: string; hostId: string; pendingKnocks: number; delegate: boolean; startsAt: string | null }>>`
    select
      g.id,
      g.kind,
      g.title,
      g.intention,
      g.code,
      g.starts_at as "startsAt",
      g.created_at as "createdAt",
      u.id as "hostId",
      u.full_name as "hostName",
      (
        select count(*)::int
        from gathering_knocks k
        where k.gathering_id = g.id and k.status = 'pending'
      ) as "pendingKnocks",
      exists (
        select 1 from gathering_delegates d
        where d.gathering_id = g.id and d.user_id = ${viewer ?? '00000000-0000-0000-0000-000000000000'}
      ) as "delegate"
    from gatherings g
    join users u on u.id = g.host_id
    where g.status = 'open' and g.created_at > now() - interval '14 days'
    order by coalesce(g.starts_at, g.created_at) desc
  `
  return c.json(rows.map((row) => ({
    ...row,
    pendingKnocks: viewer === row.hostId || row.delegate ? Number(row.pendingKnocks) : 0,
  })))
})

app.get('/gatherings/:code', async (c) => {
  const code = c.req.param('code').replace(/\s/g, '').toUpperCase()
  const viewer = readToken(c.req.header('authorization'))
  const rows = await sql<Array<{ id: string; hostId: string; status: string; startsAt: string | null }>>`
    select
      g.id,
      g.kind,
      g.title,
      g.intention,
      g.code,
      g.status,
      g.starts_at as "startsAt",
      g.created_at as "createdAt",
      u.id as "hostId",
      u.full_name as "hostName"
    from gatherings g
    join users u on u.id = g.host_id
    where g.code = ${code}
  `
  const row = rows[0]
  if (!row || row.status !== 'open') return c.json({ error: 'Ce salon est fermé ou inconnu.' }, 404)
  const delegates = await delegatesOf(row.id)
  let viewerRole: 'host' | 'delegate' | 'invited' | null = null
  let invites: { id: string; fullName: string }[] | undefined
  if (viewer && viewer === row.hostId) {
    viewerRole = 'host'
    invites = await sql<{ id: string; fullName: string }[]>`
      select u.id, u.full_name as "fullName"
      from gathering_invites i
      join users u on u.id = i.user_id
      where i.gathering_id = ${row.id}
      order by u.full_name
    `
  } else if (viewer && delegates.some((person) => person.id === viewer)) {
    viewerRole = 'delegate'
  } else if (viewer) {
    const invited = await sql<{ ok: number }[]>`
      select 1 as ok from gathering_invites
      where gathering_id = ${row.id} and user_id = ${viewer}
      limit 1
    `
    if (invited.length > 0) viewerRole = 'invited'
  }
  return c.json({ ...row, delegates, invites, viewerRole })
})

app.post('/gatherings', async (c) => {
  const hostId = readToken(c.req.header('authorization'))
  if (!hostId) return c.json({ error: 'Connectez-vous pour ouvrir un salon.' }, 401)
  const host = await profileById(hostId)
  if (!host) return c.json({ error: 'Compte introuvable.' }, 401)

  const parsed = z.object({
    kind: z.enum(gatheringKinds),
    title: z.string().trim().min(3, 'Donnez un titre au salon.').max(80, 'Le titre est trop long.'),
    intention: z.string().trim().max(240, 'L’intention est trop longue.').optional().default(''),
    startsAt: z.string().datetime().nullable().optional(),
    inviteIds: z.array(z.string().uuid()).max(40).optional().default([]),
  }).safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) return c.json({ error: fail(parsed.error) }, 400)

  const intention = parsed.data.intention.length > 0 ? parsed.data.intention : null
  let startsAt: string | null = null
  if (parsed.data.startsAt) {
    const moment = new Date(parsed.data.startsAt)
    if (!Number.isNaN(moment.getTime()) && moment.getTime() - Date.now() > 60_000 && moment.getTime() - Date.now() < 1000 * 60 * 60 * 24 * 60) {
      startsAt = moment.toISOString()
    }
  }
  const inviteIds = [...new Set(parsed.data.inviteIds.filter((id) => id !== hostId))]
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const code = gatheringCode()
    try {
      const inserted = await sql<{ id: string; code: string }[]>`
        insert into gatherings (host_id, kind, title, intention, code, starts_at)
        values (${hostId}, ${parsed.data.kind}, ${parsed.data.title}, ${intention}, ${code}, ${startsAt})
        returning id, code
      `
      const roomId = inserted[0].id
      const when = callWhen(startsAt)
      const known = inviteIds.length
        ? await sql<{ id: string }[]>`
            select id from users
            where status = 'active' and id in ${sql(inviteIds)}
          `
        : []
      for (const person of known) {
        await sql`
          insert into gathering_invites (gathering_id, user_id)
          values (${roomId}, ${person.id})
          on conflict do nothing
        `
        await sql`
          insert into notifications (user_id, kind, title, body, code)
          values (
            ${person.id},
            'invite',
            'Invitation FRASCA',
            ${`${host.fullName} vous invite : « ${parsed.data.title} », ${when}. Code ${spacedCode(code)}.`},
            ${code}
          )
        `
      }
      return c.json({
        id: roomId,
        code: inserted[0].code,
        kind: parsed.data.kind,
        title: parsed.data.title,
        intention,
        startsAt,
        hostId,
        hostName: host.fullName,
        invited: known.length,
      }, 201)
    } catch (error) {
      if (!(typeof error === 'object' && error && 'code' in error && error.code === '23505')) throw error
    }
  }
  return c.json({ error: 'Le salon n’a pas pu être ouvert. Réessayez.' }, 500)
})

app.post('/gatherings/:code/delegates', async (c) => {
  const hostId = readToken(c.req.header('authorization'))
  if (!hostId) return c.json({ error: 'Connectez-vous pour déléguer.' }, 401)
  const code = c.req.param('code').replace(/\s/g, '').toUpperCase()
  const parsed = z.object({ userId: z.string().uuid() }).safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) return c.json({ error: 'Choisissez une personne.' }, 400)
  const rooms = await sql<{ id: string; title: string }[]>`
    select id, title from gatherings
    where code = ${code} and host_id = ${hostId} and status = 'open'
  `
  const room = rooms[0]
  if (!room) return c.json({ error: 'Seul le gérant peut déléguer.' }, 403)
  if (parsed.data.userId === hostId) return c.json({ error: 'Vous gérez déjà ce salon.' }, 400)
  const people = await sql<{ id: string; fullName: string }[]>`
    select id, full_name as "fullName" from users
    where id = ${parsed.data.userId} and status = 'active'
  `
  const person = people[0]
  if (!person) return c.json({ error: 'Cette personne est introuvable.' }, 404)
  const current = await delegatesOf(room.id)
  if (current.some((item) => item.id === person.id)) return c.json({ delegates: current })
  if (current.length >= 2) return c.json({ error: 'Deux personnes peuvent déjà gérer avec vous.' }, 400)
  await sql`
    insert into gathering_delegates (gathering_id, user_id)
    values (${room.id}, ${person.id})
  `
  const host = await profileById(hostId)
  await sql`
    insert into notifications (user_id, kind, title, body, code)
    values (
      ${person.id},
      'delegate',
      'Vous gérez un salon',
      ${`${host?.fullName ?? 'Le gérant'} vous demande de gérer « ${room.title} » avec lui. Code ${spacedCode(code)}.`},
      ${code}
    )
  `
  return c.json({ delegates: await delegatesOf(room.id) }, 201)
})

app.delete('/gatherings/:code/delegates/:userId', async (c) => {
  const hostId = readToken(c.req.header('authorization'))
  if (!hostId) return c.json({ error: 'Connectez-vous pour retirer un gérant.' }, 401)
  const code = c.req.param('code').replace(/\s/g, '').toUpperCase()
  const userId = z.string().uuid().safeParse(c.req.param('userId'))
  if (!userId.success) return c.json({ error: 'Personne introuvable.' }, 404)
  const rooms = await sql<{ id: string }[]>`
    select id from gatherings
    where code = ${code} and host_id = ${hostId} and status = 'open'
  `
  const room = rooms[0]
  if (!room) return c.json({ error: 'Seul le gérant peut retirer une délégation.' }, 403)
  await sql`
    delete from gathering_delegates
    where gathering_id = ${room.id} and user_id = ${userId.data}
  `
  return c.json({ delegates: await delegatesOf(room.id) })
})

app.post('/gatherings/:code/close', async (c) => {
  const hostId = readToken(c.req.header('authorization'))
  if (!hostId) return c.json({ error: 'Connectez-vous pour fermer le salon.' }, 401)
  const code = c.req.param('code').replace(/\s/g, '').toUpperCase()
  const rows = await sql<{ id: string }[]>`
    update gatherings set status = 'closed'
    where code = ${code} and host_id = ${hostId} and status = 'open'
    returning id
  `
  if (rows.length === 0) return c.json({ error: 'Seul l’hôte peut fermer ce salon.' }, 403)
  closeLive(code)
  return c.json({ ok: true })
})

function messageText(data: unknown) {
  if (typeof data === 'string') return data
  if (Buffer.isBuffer(data)) return data.toString()
  return ''
}

app.post('/gatherings/:code/ticket', async (c) => {
  const code = c.req.param('code').replace(/\s/g, '').toUpperCase()
  const parsed = z.object({
    knockId: z.string().uuid().optional(),
  }).safeParse(await c.req.json().catch(() => ({})))
  if (!parsed.success) return c.json({ error: 'Entrée impossible.' }, 400)

  const rooms = await sql<{ id: string; hostId: string; status: string }[]>`
    select id, host_id as "hostId", status
    from gatherings
    where code = ${code}
  `
  const room = rooms[0]
  if (!room || room.status !== 'open') return c.json({ error: 'Ce salon est fermé ou inconnu.' }, 404)

  const viewer = readToken(c.req.header('authorization'))
  let name: string | null = null
  const manager = await viewerManages(room.id, room.hostId, viewer)
  if (manager && viewer) {
    const person = await profileById(viewer)
    name = person?.fullName ?? 'Gérant'
  } else if (viewer) {
    const invited = await sql<{ ok: number }[]>`
      select 1 as ok from gathering_invites
      where gathering_id = ${room.id} and user_id = ${viewer}
      limit 1
    `
    if (invited.length > 0) {
      const person = await profileById(viewer)
      name = person?.fullName ?? 'Invité'
    }
  }
  if (!name && parsed.data.knockId) {
    const knocks = await sql<{ displayName: string; status: string }[]>`
      select display_name as "displayName", status
      from gathering_knocks
      where id = ${parsed.data.knockId} and gathering_id = ${room.id}
    `
    const knock = knocks[0]
    if (knock?.status === 'accepted') name = knock.displayName
  }
  if (!name) return c.json({ error: 'L’hôte doit d’abord accepter votre entrée.' }, 403)
  if (isLocked(code) && !manager) return c.json({ error: 'Le gérant a fermé les entrées.' }, 403)
  return c.json({ ticket: issueTicket(code, name, manager), name })
})

app.get('/gatherings/:code/live', upgradeWebSocket((c) => {
  const code = (c.req.param('code') ?? '').replace(/\s/g, '').toUpperCase()
  const token = c.req.query('ticket') ?? ''
  let session: LiveSession | null = null
  return {
    onOpen(_event, ws) {
      const ticket = takeTicket(token, code)
      if (!ticket) {
        ws.send(JSON.stringify({ type: 'error', error: 'Entrée refusée.' }))
        ws.close()
        return
      }
      session = joinLive(code, ticket.name, ticket.host, (data) => {
        try {
          const backlog = (ws as unknown as { raw?: { bufferedAmount?: number } }).raw?.bufferedAmount ?? 0
          if (backlog > 48_000 && data.includes('"kind":"frame"')) return
          ws.send(data)
        } catch { /* Le téléphone a quitté. */ }
      })
      if (!session) {
        ws.send(JSON.stringify({ type: 'error', error: 'Ce salon est complet.' }))
        ws.close()
      }
    },
    onMessage(event) {
      if (!session) return
      try {
        const message = JSON.parse(messageText(event.data)) as { type?: string; to?: string; data?: unknown }
        if (message.type === 'signal' && typeof message.to === 'string' && message.data) {
          session.signal(message.to, message.data)
        }
        if (message.type === 'room' && message.data) session.broadcast(message.data)
      } catch {
        // Message ignoré.
      }
    },
    onClose() {
      session?.leave()
      session = null
    },
  }
}))

app.post('/gatherings/:code/knocks', async (c) => {
  const code = c.req.param('code').replace(/\s/g, '').toUpperCase()
  const parsed = z.object({
    displayName: z.string().trim().min(2, 'Indiquez votre nom.').max(48, 'Le nom est trop long.'),
  }).safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) return c.json({ error: fail(parsed.error) }, 400)

  const viewer = readToken(c.req.header('authorization'))
  const rooms = await sql<{ id: string; hostId: string }[]>`
    select id, host_id as "hostId"
    from gatherings
    where code = ${code} and status = 'open'
  `
  const room = rooms[0]
  if (!room) return c.json({ error: 'Ce salon est fermé ou inconnu.' }, 404)
  if (await viewerManages(room.id, room.hostId, viewer)) return c.json({ error: 'Vous gérez déjà ce salon.' }, 400)
  if (viewer) {
    const invited = await sql<{ ok: number }[]>`
      select 1 as ok from gathering_invites
      where gathering_id = ${room.id} and user_id = ${viewer}
      limit 1
    `
    if (invited.length > 0) return c.json({ error: 'Vous êtes invité : entrez directement.' }, 400)
  }

  const displayName = parsed.data.displayName.replace(/\s+/g, ' ')
  const existing = await sql<{ id: string; status: string; displayName: string }[]>`
    select id, status, display_name as "displayName"
    from gathering_knocks
    where gathering_id = ${room.id}
      and display_name = ${displayName}
      and status = 'pending'
      and created_at > now() - interval '2 hours'
    order by created_at desc
    limit 1
  `
  if (existing[0]) return c.json(existing[0])

  const inserted = await sql<{ id: string; status: string; displayName: string }[]>`
    insert into gathering_knocks (gathering_id, display_name)
    values (${room.id}, ${displayName})
    returning id, status, display_name as "displayName"
  `
  return c.json(inserted[0], 201)
})

app.get('/gatherings/:code/knocks', async (c) => {
  const viewer = readToken(c.req.header('authorization'))
  if (!viewer) return c.json({ error: 'Connectez-vous pour voir les demandes.' }, 401)
  const code = c.req.param('code').replace(/\s/g, '').toUpperCase()
  const rooms = await sql<{ id: string; hostId: string }[]>`
    select id, host_id as "hostId"
    from gatherings
    where code = ${code} and status = 'open'
  `
  const room = rooms[0]
  if (!room || !(await viewerManages(room.id, room.hostId, viewer))) return c.json([])
  const rows = await sql`
    select k.id, k.display_name as "displayName", k.status, k.created_at as "createdAt"
    from gathering_knocks k
    where k.gathering_id = ${room.id} and k.status = 'pending'
    order by k.created_at asc
  `
  return c.json(rows)
})

app.get('/gatherings/:code/knocks/:id', async (c) => {
  const code = c.req.param('code').replace(/\s/g, '').toUpperCase()
  const id = z.string().uuid().safeParse(c.req.param('id'))
  if (!id.success) return c.json({ error: 'Demande introuvable.' }, 404)
  const rows = await sql<{ id: string; status: string; displayName: string }[]>`
    select k.id, k.status, k.display_name as "displayName"
    from gathering_knocks k
    join gatherings g on g.id = k.gathering_id
    where k.id = ${id.data} and g.code = ${code} and g.status = 'open'
  `
  const row = rows[0]
  if (!row) return c.json({ error: 'Demande introuvable.' }, 404)
  return c.json(row)
})

app.post('/gatherings/:code/knocks/:id', async (c) => {
  const hostId = readToken(c.req.header('authorization'))
  if (!hostId) return c.json({ error: 'Connectez-vous pour accepter une entrée.' }, 401)
  const code = c.req.param('code').replace(/\s/g, '').toUpperCase()
  const id = z.string().uuid().safeParse(c.req.param('id'))
  if (!id.success) return c.json({ error: 'Demande introuvable.' }, 404)
  const parsed = z.object({
    action: z.enum(['accept', 'reject']),
  }).safeParse(await c.req.json().catch(() => null))
  if (!parsed.success) return c.json({ error: 'Action impossible.' }, 400)
  const status = parsed.data.action === 'accept' ? 'accepted' : 'rejected'
  const rooms = await sql<{ id: string; hostId: string }[]>`
    select id, host_id as "hostId"
    from gatherings
    where code = ${code} and status = 'open'
  `
  const room = rooms[0]
  if (!room || !(await viewerManages(room.id, room.hostId, hostId))) {
    return c.json({ error: 'Seul un gérant peut accepter une entrée.' }, 403)
  }
  const rows = await sql<{ id: string }[]>`
    update gathering_knocks
    set status = ${status}
    where id = ${id.data}
      and gathering_id = ${room.id}
      and status = 'pending'
    returning id
  `
  if (rows.length === 0) return c.json({ error: 'Cette demande n’est plus en attente.' }, 404)
  return c.json({ ok: true, status })
})

await migrate()

const port = Number(process.env.PORT ?? 8787)
const server = serve({ fetch: app.fetch, port, hostname: '0.0.0.0' }, (info) => {
  console.log(`FRASCA API http://localhost:${info.port}`)
})
injectWebSocket(server)
void syncIfStale().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'synchronisation impossible'
  console.error(`Synchronisation du site : ${message}`)
})
