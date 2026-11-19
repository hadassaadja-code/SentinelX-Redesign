// Facturation (12.2) : intégration Stripe (Checkout + portail client + webhooks). Sans clé Stripe, la plateforme
// reste en mode démonstration : changement de formule immédiat, sans paiement.
import Stripe from 'stripe'
import { config } from './config.js'
import { prisma, asPlatform, alert, audit, PLANS } from './core.js'

export const stripe = config.stripe.enabled ? new Stripe(config.stripe.secretKey) : null
export const billingMode = () => (stripe ? 'stripe' : 'demo')

export async function ensureCustomer(org: any, email: string): Promise<string> {
  if (org.stripeCustomerId) return org.stripeCustomerId
  const c = await stripe!.customers.create({ name: org.name, email, metadata: { orgId: org.id } })
  await asPlatform(() => prisma.organization.update({ where: { id: org.id }, data: { stripeCustomerId: c.id } }))
  return c.id
}

/** Crée une session Checkout pour souscrire à une formule payante. */
export async function createCheckout(org: any, email: string, plan: string): Promise<string> {
  const price = config.stripe.prices[plan]
  if (!price) throw new Error(`Aucun prix Stripe configuré pour la formule ${plan} (STRIPE_PRICE_${plan})`)
  const customer = await ensureCustomer(org, email)
  const session = await stripe!.checkout.sessions.create({
    mode: 'subscription', customer,
    line_items: [{ price, quantity: 1 }],
    success_url: `${config.appUrl}/app/billing?checkout=success`,
    cancel_url: `${config.appUrl}/app/billing?checkout=cancel`,
    metadata: { orgId: org.id, plan },
    subscription_data: { metadata: { orgId: org.id, plan } },
  })
  return session.url!
}

/** Portail client Stripe : changer de moyen de paiement, factures, annulation. */
export async function createPortal(org: any, email: string): Promise<string> {
  const customer = await ensureCustomer(org, email)
  const s = await stripe!.billingPortal.sessions.create({ customer, return_url: `${config.appUrl}/app/billing` })
  return s.url
}

const planFromPrice = (priceId: string | undefined) => Object.entries(config.stripe.prices).find(([, p]) => p === priceId)?.[0]

/** Traite un évènement webhook signé par Stripe. */
export async function handleWebhook(rawBody: Buffer, signature: string) {
  const event = stripe!.webhooks.constructEvent(rawBody, signature, config.stripe.webhookSecret)
  await asPlatform(async () => {
    switch (event.type) {
      case 'checkout.session.completed': {
        const s: any = event.data.object
        const orgId = s.metadata?.orgId
        if (orgId && s.subscription) await prisma.organization.update({ where: { id: orgId }, data: { stripeSubscriptionId: String(s.subscription), subscriptionStatus: 'ACTIVE', plan: s.metadata?.plan ?? undefined } })
        break
      }
      case 'customer.subscription.updated':
      case 'customer.subscription.created': {
        const sub: any = event.data.object
        const org = await prisma.organization.findFirst({ where: { OR: [{ stripeSubscriptionId: sub.id }, { stripeCustomerId: String(sub.customer) }] } })
        if (!org) break
        const plan = planFromPrice(sub.items?.data?.[0]?.price?.id) ?? sub.metadata?.plan ?? org.plan
        const status = ({ active: 'ACTIVE', trialing: 'TRIALING', past_due: 'PAST_DUE', canceled: 'CANCELED', unpaid: 'PAST_DUE' } as any)[sub.status] ?? 'ACTIVE'
        await prisma.organization.update({ where: { id: org.id }, data: { stripeSubscriptionId: sub.id, subscriptionStatus: status, plan: PLANS[plan] ? plan : org.plan, currentPeriodEnd: sub.current_period_end ? new Date(sub.current_period_end * 1000) : null } })
        if (status === 'PAST_DUE') await alert(org.id, { type: 'PAYMENT_FAILED', title: 'Paiement en échec', body: 'Mettez à jour votre moyen de paiement pour conserver votre formule.', link: '/app/billing' })
        break
      }
      case 'customer.subscription.deleted': {
        const sub: any = event.data.object
        const org = await prisma.organization.findFirst({ where: { stripeSubscriptionId: sub.id } })
        if (org) {
          await prisma.organization.update({ where: { id: org.id }, data: { subscriptionStatus: 'CANCELED', plan: 'STARTER', stripeSubscriptionId: null, currentPeriodEnd: null } })
          await alert(org.id, { type: 'SUBSCRIPTION_CANCELED', title: 'Abonnement résilié', body: 'Votre organisation est repassée en formule Starter.', link: '/app/billing' })
        }
        break
      }
      case 'invoice.paid':
      case 'invoice.payment_failed': {
        const inv: any = event.data.object
        const org = await prisma.organization.findFirst({ where: { stripeCustomerId: String(inv.customer) } })
        if (!org) break
        await prisma.payment.upsert({
          where: { externalId: inv.id },
          create: { orgId: org.id, externalId: inv.id, plan: planFromPrice(inv.lines?.data?.[0]?.price?.id) ?? org.plan, amount: inv.amount_paid ?? inv.amount_due ?? 0, currency: inv.currency ?? 'eur', status: event.type === 'invoice.paid' ? 'PAID' : 'FAILED', invoiceUrl: inv.hosted_invoice_url ?? '' },
          update: { status: event.type === 'invoice.paid' ? 'PAID' : 'FAILED', amount: inv.amount_paid ?? inv.amount_due ?? 0, invoiceUrl: inv.hosted_invoice_url ?? '' },
        })
        break
      }
    }
    await audit(null, null, 'billing.webhook', `${event.type} (${event.id})`)
  })
}
