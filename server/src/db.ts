// Client Prisma avec isolation multi-tenant imposée au niveau de l'ORM (section 14.1).
//
// Principe : chaque requête HTTP authentifiée s'exécute dans un contexte (AsyncLocalStorage) qui porte
// l'organisation active. L'objet `prisma` exporté est un proxy : à chaque accès (prisma.project…), il choisit
// un client Prisma étendu propre à l'organisation courante. Pour tout modèle possédant une colonne orgId, ce client :
//   - ajoute automatiquement orgId au filtre de lecture/mise à jour/suppression,
//   - refuse toute requête qui ciblerait explicitement une autre organisation,
//   - renseigne orgId à la création.
// Même un oubli dans une route ne peut donc pas exposer les données d'un autre client.
// (Le contexte est lu au moment de l'accès à la propriété, car Prisma perd le contexte asynchrone à l'intérieur
// de ses extensions.)
import { PrismaClient } from '@prisma/client'
import { AsyncLocalStorage } from 'node:async_hooks'

export type TenantStore = { orgId: string }
export const tenant = new AsyncLocalStorage<TenantStore>()

export class TenantViolation extends Error {
  constructor(model: string, op: string) {
    super(`Isolation multi-tenant : accès refusé (${model}.${op})`)
  }
}

const TENANT_MODELS = new Set([
  'Project', 'Application', 'Scan', 'Finding', 'FindingComment', 'TestResult', 'PerformanceMetric',
  'MonitorCheck', 'Incident', 'Notification', 'Report', 'Payment', 'UsageRecord',
])
const WHERE_OPS = new Set(['findFirst', 'findFirstOrThrow', 'findMany', 'findUnique', 'findUniqueOrThrow', 'update', 'updateMany', 'delete', 'deleteMany', 'count', 'aggregate', 'groupBy', 'upsert'])

function guardWhere(where: any, orgId: string, model: string, op: string) {
  const w = where ?? {}
  if (w.orgId !== undefined && w.orgId !== orgId) throw new TenantViolation(model, op)
  return { ...w, orgId }
}
function guardData(data: any, orgId: string, model: string, op: string) {
  if (!data) return data
  if (data.orgId !== undefined && data.orgId !== orgId) throw new TenantViolation(model, op)
  return { ...data, orgId }
}

const base = new PrismaClient({ log: process.env.PRISMA_LOG ? ['query', 'warn', 'error'] : ['warn', 'error'] })

function clientFor(orgId: string) {
  return base.$extends({
    name: `tenant:${orgId}`,
    query: {
      $allModels: {
        async $allOperations({ model, operation, args, query }) {
          if (!TENANT_MODELS.has(model)) return query(args)
          const a: any = { ...(args as any) }
          if (WHERE_OPS.has(operation)) a.where = guardWhere(a.where, orgId, model, operation)
          if (operation === 'create') a.data = guardData(a.data, orgId, model, operation)
          if (operation === 'upsert') a.create = guardData(a.create, orgId, model, operation)
          if (operation === 'createMany' || operation === 'createManyAndReturn') {
            const d = Array.isArray(a.data) ? a.data : [a.data]
            a.data = d.map((x: any) => guardData(x, orgId, model, operation))
          }
          return query(a)
        },
      },
    },
  })
}
// Un client étendu par organisation, mis en cache (ils partagent le même moteur et le même pool de connexions).
const clients = new Map<string, ReturnType<typeof clientFor>>()
function current(): any {
  const s = tenant.getStore()
  if (!s) return base
  let c = clients.get(s.orgId)
  if (!c) {
    if (clients.size > 500) clients.delete(clients.keys().next().value!)
    c = clientFor(s.orgId)
    clients.set(s.orgId, c)
  }
  return c
}

export const prisma: PrismaClient = new Proxy({} as PrismaClient, {
  get(_t, prop) {
    const c = current()
    const v = c[prop as any]
    return typeof v === 'function' ? v.bind(c) : v
  },
})

/** Exécute fn dans le contexte d'une organisation (routes authentifiées, moteurs, monitoring). */
export const asTenant = <T>(orgId: string, fn: () => Promise<T>): Promise<T> => tenant.run({ orgId }, fn)
/** Exécute fn hors de tout contexte d'organisation (Super Administrateur, tâches de plateforme). Chaque usage doit être justifié. */
export const asPlatform = <T>(fn: () => Promise<T>): Promise<T> => tenant.exit(fn)
export const connectDb = () => base.$connect()
