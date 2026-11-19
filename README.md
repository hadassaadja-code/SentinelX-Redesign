# SentinelX

Plateforme SaaS multi-tenant de QA, cybersécurité et performance (voir `Cahier_des_charges_SentinelX.pdf`).
Chaque organisation enregistre ses applications, déclare ses autorisations d'audit, lance des campagnes
(QA, sécurité, API, performance, charge), surveille la disponibilité et suit les corrections.

## Lancer l'application

Prérequis : Node.js 20 ou plus récent.

```bash
npm run setup     # une seule fois : dépendances, base SQLite, navigateur Chromium pour Playwright
npm start         # compile le frontend et démarre le serveur (API + moteurs + monitoring)
```

Ouvrir ensuite http://localhost:3000. Sans aucune configuration, la plateforme tourne en **mode démonstration** :
SQLite, file de tâches en mémoire, e-mails journalisés (les liens de vérification, d'invitation et de
réinitialisation sont affichés dans l'interface), changement de formule sans paiement.

Commandes utiles (dossier `server/`) :

| Commande | Rôle |
|---|---|
| `npm run superadmin -- email@exemple.com` | Promouvoir un compte existant Super Administrateur |
| `npm run reset` | Vider la base de démonstration |
| `npm test` | Tests unitaires, d'isolation et d'intégration (ces derniers exigent un serveur démarré) |
| `npm run typecheck` | Vérification TypeScript |
| `npm run worker` | Démarrer un worker seul (nécessite `REDIS_URL`) |
| `npm run db:postgres` | Générer le schéma PostgreSQL et l'appliquer (`DATABASE_URL`) |

## Déploiement (PostgreSQL, Redis, BullMQ, Docker)

```bash
cp .env.example .env        # renseigner APP_URL, mots de passe, SMTP, Stripe…
docker compose up -d --build
docker compose exec api npx tsx scripts/superadmin.ts admin@exemple.com
```

`docker-compose.yml` démarre PostgreSQL, Redis, l'API, un worker isolé (CPU/mémoire limités, système de
fichiers en lecture seule) et Nginx. L'image inclut les trois navigateurs Playwright. Le schéma Prisma de référence
est SQLite ; `scripts/make-postgres-schema.mjs` génère la variante PostgreSQL (même modèle). Le rôle du processus
est choisi par `PROCESS_ROLE` (`api`, `worker` ou `all`). Toutes les variables sont décrites dans `.env.example`.

## Parcours de démonstration

1. Créer un compte : l'organisation est créée, vous en êtes administrateur. Confirmer l'e-mail (lien affiché en démo).
2. Créer un projet, ajouter une application (URL d'un site qui vous appartient).
3. Ouvrir « Autorisation » : vérifier la propriété du domaine (DNS TXT, fichier `.well-known` ou balise meta),
   choisir le périmètre (passif ; actif ; charge) et signer la déclaration.
4. Lancer un audit (profil standard, approfondi ou test de charge) et suivre la progression en direct.
5. Explorer le détail : synthèse, constats avec preuves et références CWE/OWASP, tests (statiques, navigateur,
   accessibilité, formulaires, comparaison visuelle), métriques, captures d'écran, comparaison avec l'audit précédent.
6. Télécharger le rapport (PDF, JSON, CSV, SARIF) ou créer un lien de partage à durée limitée.
7. Qualifier, assigner et commenter les vulnérabilités ; activer le monitoring et ses règles ; inviter des
   collaborateurs ; activer la 2FA ; changer de formule.
8. Super Administration (`/admin`) : organisations, quotas, moteurs, journaux, boîte d'envoi.

## Ce qui est couvert

| Domaine | Contenu |
|---|---|
| Comptes | Inscription, vérification d'e-mail, connexion, mot de passe oublié, profil, sessions révocables (expiration absolue et par inactivité), 2FA TOTP avec codes de récupération, blocage persistant après 5 échecs, politique de mots de passe |
| Multi-tenant | Isolation imposée au niveau de l'ORM (`server/src/db.ts`) : toute requête d'une session est automatiquement filtrée sur son organisation ; un utilisateur peut appartenir à plusieurs organisations ; 4 rôles et matrice de permissions centralisée |
| Projets | Projets avec responsable technique, archivage, suppression contrôlée, statistiques ; fiche application (technologies, propriétaire, OpenAPI, périmètre de chemins, budget de requêtes, en-têtes chiffrés, navigateurs, audits planifiés) |
| Autorisation | Déclaration tracée, vérification de propriété (DNS/HTTP/meta), périmètres passif/actif/charge, expiration, révocation ; les contrôles actifs et la charge exigent une validation spécifique et la vérification en production |
| QA | Contrôles statiques, liens et ressources, page 404 ; en navigateur réel (Playwright) : erreurs JS, console, ressources en échec, Core Web Vitals, images, formulaires (validation sans soumission), accessibilité axe-core, affichage mobile, captures et comparaison visuelle ; Chromium, Firefox, WebKit selon la formule |
| Sécurité | TLS (validité, expiration, protocoles obsolètes acceptés, suites faibles), HSTS et CSP analysées, en-têtes, cookies, contenu mixte, formulaires, SRI, bibliothèques JS obsolètes, 15 fichiers sensibles, listage de répertoires, robots.txt, security.txt, traces d'erreur, SPF/DMARC/CAA ; en mode actif : CORS, méthodes HTTP, réflexion non échappée, signatures d'erreur SQL, redirections ouvertes. Chaque constat porte CWE et OWASP |
| API | Import ou découverte OpenAPI, analyse statique cartographiée sur l'OWASP API Top 10 (authentification, BOLA, mass assignment, données sensibles, limites, 429, dépréciation), contrôles dynamiques en lecture seule (authentification réellement appliquée, fuites, erreurs, rate limiting) |
| Performance | Moyenne, P50/P90/P95/P99, TTFB, écart-type, débit, compression, cache, ressources lourdes, budget de performance ; tests de charge encadrés (VU et durée plafonnés par la formule, seuils, arrêt automatique si la cible souffre, séries par seconde) |
| Monitoring | Vérifications périodiques (code attendu, mot-clé, temps maximal), seuil d'échecs consécutifs, incidents regroupés avec prise en charge et notes, fenêtres de maintenance, disponibilité 24 h / 7 j / 30 j, surveillance des certificats |
| Rapports | PDF avec page de garde, scores et graphiques ; JSON ; CSV ; SARIF ; synthèse d'organisation par période ; comparaison entre deux campagnes ; liens de partage à durée limitée et révocables |
| Notifications | Dans l'application, par e-mail (SMTP) et par webhook (Slack/Discord/outil interne) ; préférences par utilisateur ; synthèse hebdomadaire |
| Abonnement | 3 formules, quotas appliqués côté serveur et verrouillés contre les requêtes concurrentes, Stripe (Checkout, portail, webhooks, factures) ou mode démonstration |
| Super Admin | Organisations (statut, formule, quotas personnalisés), utilisateurs, audits en cours, formules globales, inscriptions, journal de plateforme, boîte d'envoi ; tout accès à un dossier client exige un motif journalisé |

## Sécurité de la plateforme

- Mots de passe Argon2id ; blocage persistant après 5 échecs ; limitation de débit par IP sur l'API et l'authentification.
- Cookie de session `HttpOnly` + `SameSite=Strict`, en-tête obligatoire sur les requêtes modifiantes (CSRF), en-têtes de sécurité et CSP sur toutes les réponses.
- Isolation multi-tenant au niveau de l'ORM, testée (`server/test/isolation.test.ts`).
- Secrets au repos chiffrés (AES-256-GCM) : secrets TOTP, en-têtes d'audit. Jetons à usage unique hachés.
- Protection SSRF : adresses internes refusées, y compris après résolution DNS, à chaque redirection et dans le navigateur Playwright.
- Aucun audit sans autorisation déclarée ; périmètre et budget de requêtes par campagne ; actions sensibles journalisées.

## Écarts restants avec le cahier des charges

| Prévu | État |
|---|---|
| OWASP ZAP, Semgrep, Trivy, k6, Lighthouse | Contrôles écrits en Node.js (sécurité, charge, vitals via Playwright) ; analyse de dépendances limitée aux bibliothèques JS détectées ; SAST non réalisé |
| Scénarios de connexion sur comptes de test, IDOR avec deux comptes | Non réalisés (les en-têtes d'audit permettent déjà d'auditer une zone authentifiée) |
| Tests E2E complets | Tests unitaires, d'isolation et d'intégration API fournis ; E2E navigateur à compléter |
