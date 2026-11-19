// Tests d'isolation multi-tenant (14.1, scénario de validation n° 2) : deux organisations, aucune ne peut lire
// ou modifier les données de l'autre, même si une requête oublie le filtre ou cible explicitement l'autre.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { prisma, asTenant, asPlatform, TenantViolation } from '../src/db.js'

const suffix = Date.now().toString(36)
let orgA: any, orgB: any, projA: any, projB: any

beforeAll(async () => {
  orgA = await asPlatform(() => prisma.organization.create({ data: { name: `Iso A ${suffix}` } }))
  orgB = await asPlatform(() => prisma.organization.create({ data: { name: `Iso B ${suffix}` } }))
  projA = await asTenant(orgA.id, () => prisma.project.create({ data: { name: 'Projet A' } as any }))
  projB = await asTenant(orgB.id, () => prisma.project.create({ data: { name: 'Projet B' } as any }))
})
afterAll(async () => {
  await asPlatform(() => prisma.organization.deleteMany({ where: { id: { in: [orgA.id, orgB.id] } } }))
  await prisma.$disconnect()
})

describe('isolation imposée par l\'ORM', () => {
  it('renseigne orgId à la création et filtre les lectures', async () => {
    expect(projA.orgId).toBe(orgA.id)
    const seenByA = await asTenant(orgA.id, () => prisma.project.findMany())
    expect(seenByA.map((p) => p.id)).toContain(projA.id)
    expect(seenByA.map((p) => p.id)).not.toContain(projB.id)
  })
  it('rend invisible une ressource ciblée par son identifiant depuis une autre organisation (anti-IDOR)', async () => {
    const r = await asTenant(orgA.id, () => prisma.project.findFirst({ where: { id: projB.id } }))
    expect(r).toBeNull()
    const u = await asTenant(orgA.id, () => prisma.project.findUnique({ where: { id: projB.id } }))
    expect(u).toBeNull()
  })
  it('refuse les mises à jour et suppressions croisées', async () => {
    const upd = await asTenant(orgA.id, () => prisma.project.updateMany({ where: { id: projB.id }, data: { name: 'piraté' } }))
    expect(upd.count).toBe(0)
    const del = await asTenant(orgA.id, () => prisma.project.deleteMany({ where: { id: projB.id } }))
    expect(del.count).toBe(0)
    const still = await asPlatform(() => prisma.project.findUnique({ where: { id: projB.id } }))
    expect(still?.name).toBe('Projet B')
  })
  it('lève une violation si une requête cible explicitement une autre organisation', async () => {
    await expect(asTenant(orgA.id, () => prisma.project.findMany({ where: { orgId: orgB.id } }))).rejects.toBeInstanceOf(TenantViolation)
    await expect(asTenant(orgA.id, () => prisma.project.create({ data: { orgId: orgB.id, name: 'x' } }))).rejects.toBeInstanceOf(TenantViolation)
  })
  it('le contexte plateforme (Super Administrateur) voit tout', async () => {
    const all = await asPlatform(() => prisma.project.findMany({ where: { id: { in: [projA.id, projB.id] } } }))
    expect(all.length).toBe(2)
  })
})
