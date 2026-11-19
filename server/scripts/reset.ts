// Vide entièrement la base de démonstration : npm run reset (dans server/)
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
for (const m of ['auditLog', 'emailOutbox', 'platformSetting', 'usageRecord', 'payment', 'report', 'notification', 'incident', 'monitorCheck', 'findingComment', 'finding', 'testResult', 'performanceMetric', 'scan', 'application', 'project', 'organizationMember', 'token', 'session', 'organization', 'user'] as const) {
  await (prisma as any)[m].deleteMany()
}
console.log('Base vidée.')
await prisma.$disconnect()
