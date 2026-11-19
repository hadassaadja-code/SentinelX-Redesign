// Promeut un compte existant en Super Administrateur : npm run superadmin -- email@exemple.com
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
const email = (process.argv[2] ?? '').trim().toLowerCase()
if (!email) {
  console.error('Usage : npm run superadmin -- email@exemple.com')
  process.exit(1)
}
const u = await prisma.user.findUnique({ where: { email } })
if (!u) {
  console.error(`Aucun compte avec l'e-mail ${email}. Créez d'abord le compte via l'inscription.`)
  process.exit(1)
}
await prisma.user.update({ where: { id: u.id }, data: { isSuperAdmin: true } })
await prisma.auditLog.create({ data: { userId: u.id, action: 'admin.promoted', detail: `Super Administrateur via script (${email})` } })
console.log(`${email} est maintenant Super Administrateur.`)
await prisma.$disconnect()
