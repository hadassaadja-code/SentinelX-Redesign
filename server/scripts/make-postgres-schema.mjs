// Génère prisma/schema.postgresql.prisma à partir de schema.prisma (même modèle, datasource PostgreSQL).
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'prisma')
const src = fs.readFileSync(path.join(dir, 'schema.prisma'), 'utf8')
const out = src.replace(/datasource db \{[\s\S]*?\}/, 'datasource db {\n  provider = "postgresql"\n  url      = env("DATABASE_URL")\n}')
fs.writeFileSync(path.join(dir, 'schema.postgresql.prisma'), '// FICHIER GÉNÉRÉ par scripts/make-postgres-schema.mjs — ne pas modifier à la main.\n' + out)
console.log('prisma/schema.postgresql.prisma généré.')
