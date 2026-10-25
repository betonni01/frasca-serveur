import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import postgres from 'postgres'

const url = process.env.DATABASE_URL
if (!url) {
  throw new Error('DATABASE_URL manquant')
}

export const sql = postgres(url, { max: 5, idle_timeout: 20, connect_timeout: 30 })

const IDS = {
  mere: '11111111-1111-4111-8111-111111111111',
  afrique: '22222222-2222-4222-8222-222222222222',
  france: '33333333-3333-4333-8333-333333333333',
  benin: '44444444-4444-4444-8444-444444444444',
  togo: '55555555-5555-4555-8555-555555555555',
  burkina: '66666666-6666-4666-8666-666666666666',
  senegal: '77777777-7777-4777-8777-777777777777',
  paris: '88888888-8888-4888-8888-888888888888',
  paroisseParis: '99999999-9999-4999-8999-999999999999',
  cotonou: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  paroisseCotonou: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
}

export async function migrate() {
  const schema = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'schema.sql'), 'utf8')
  await sql.unsafe(schema)

  const rows: Array<[string, string, string, string, string | null]> = [
    [IDS.mere, 'Maison Mère', 'maison_mere', 'France', null],
    [IDS.afrique, 'Délégation Afrique', 'regional', 'Afrique', IDS.mere],
    [IDS.france, 'Délégation France', 'national', 'France', IDS.mere],
    [IDS.benin, 'Délégation Bénin', 'national', 'Bénin', IDS.afrique],
    [IDS.togo, 'Délégation Togo', 'national', 'Togo', IDS.afrique],
    [IDS.burkina, 'Délégation Burkina Faso', 'national', 'Burkina Faso', IDS.afrique],
    [IDS.senegal, 'Délégation Sénégal', 'national', 'Sénégal', IDS.afrique],
    [IDS.paris, 'Diocèse de Paris', 'diocese', 'France', IDS.france],
    [IDS.cotonou, 'Archidiocèse de Cotonou', 'diocese', 'Bénin', IDS.benin],
    [IDS.paroisseParis, 'Paroisse du 18e, Paris', 'parish', 'France', IDS.paris],
    [IDS.paroisseCotonou, 'Paroisse Saint-Michel, Cotonou', 'parish', 'Bénin', IDS.cotonou],
  ]

  for (const [id, name, level, country, parentId] of rows) {
    await sql`
      insert into delegations (id, name, level, country, parent_id)
      values (${id}, ${name}, ${level}, ${country}, ${parentId})
      on conflict (id) do nothing
    `
  }

}
