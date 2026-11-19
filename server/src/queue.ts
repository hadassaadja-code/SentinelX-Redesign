// File de tâches (13.1) : BullMQ sur Redis lorsque REDIS_URL est défini (workers séparés possibles),
// sinon une file en mémoire dans le processus du serveur (démonstration, instance unique).
import { config } from './config.js'
import { runScan, failScan } from './engine.js'

export type QueueStats = { backend: 'redis' | 'memory'; waiting: number; active: number; completed: number; failed: number; workers: number }

interface Backend {
  enqueue(scanId: string): Promise<void>
  stats(): Promise<QueueStats>
  close(): Promise<void>
}

// ---------- Mémoire ----------
class MemoryQueue implements Backend {
  private pending: string[] = []
  private running = 0
  private completed = 0
  private failed = 0
  constructor(private concurrency: number) {}
  async enqueue(scanId: string) {
    this.pending.push(scanId)
    this.pump()
  }
  private pump() {
    while (this.running < this.concurrency && this.pending.length) {
      const id = this.pending.shift()!
      this.running++
      runScan(id)
        .then(() => this.completed++)
        .catch(async (e) => {
          this.failed++
          await failScan(id, e)
        })
        .finally(() => {
          this.running--
          this.pump()
        })
    }
  }
  async stats(): Promise<QueueStats> {
    return { backend: 'memory', waiting: this.pending.length, active: this.running, completed: this.completed, failed: this.failed, workers: 1 }
  }
  async close() {}
}

// ---------- Redis / BullMQ ----------
class RedisQueue implements Backend {
  private queue: any
  private worker: any
  constructor(private url: string, private withWorker: boolean, private concurrency: number) {}
  async init() {
    const { Queue, Worker } = await import('bullmq')
    const connection = { url: this.url, maxRetriesPerRequest: null as any }
    this.queue = new Queue('sentinelx-scans', { connection, defaultJobOptions: { attempts: 1, removeOnComplete: 500, removeOnFail: 500 } })
    if (this.withWorker) {
      this.worker = new Worker('sentinelx-scans', async (job: any) => {
        try {
          await runScan(job.data.scanId)
        } catch (e) {
          await failScan(job.data.scanId, e)
          throw e
        }
      }, { connection, concurrency: this.concurrency, lockDuration: 10 * 60_000 })
      this.worker.on('failed', (job: any, err: any) => console.error('[worker] tâche en échec', job?.id, err?.message))
      console.log(`Worker BullMQ démarré (concurrence ${this.concurrency})`)
    }
  }
  async enqueue(scanId: string) {
    await this.queue.add('scan', { scanId }, { jobId: scanId })
  }
  async stats(): Promise<QueueStats> {
    const c = await this.queue.getJobCounts('waiting', 'active', 'completed', 'failed')
    const workers = await this.queue.getWorkers().catch(() => [])
    return { backend: 'redis', waiting: c.waiting ?? 0, active: c.active ?? 0, completed: c.completed ?? 0, failed: c.failed ?? 0, workers: workers.length }
  }
  async close() {
    await this.worker?.close()
    await this.queue?.close()
  }
}

let backend: Backend | null = null
export async function initQueue(): Promise<Backend> {
  if (backend) return backend
  const withWorker = config.processRole !== 'api'
  if (config.redisUrl) {
    const q = new RedisQueue(config.redisUrl, withWorker, config.workerConcurrency)
    await q.init()
    backend = q
    console.log(`File de tâches : Redis (${config.redisUrl.replace(/\/\/.*@/, '//***@')})`)
  } else {
    backend = new MemoryQueue(config.workerConcurrency)
    console.log('File de tâches : mémoire (définir REDIS_URL pour BullMQ)')
  }
  return backend
}
export const enqueueScan = async (scanId: string) => (await initQueue()).enqueue(scanId)
export const queueStats = async () => (await initQueue()).stats()
export const closeQueue = async () => backend?.close()
