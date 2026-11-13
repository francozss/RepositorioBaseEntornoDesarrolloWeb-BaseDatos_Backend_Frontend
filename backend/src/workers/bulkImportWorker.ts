import { Worker } from 'bullmq';
import dotenv from 'dotenv';

dotenv.config();

const redisHost = process.env.REDIS_HOST || 'redis';
const redisPort = Number(process.env.REDIS_PORT) || 6379;

console.log(`[Worker] Iniciando procesador asíncrono conectado a Redis en ${redisHost}:${redisPort}...`);

const importWorker = new Worker(
  'bulk-import-queue',
  async job => {
    console.log(`[Worker] Procesando lote ID: ${job.id}, Tipo: ${job.data.importType}`);
    // Simulación de procesamiento por lotes segura
    await new Promise(resolve => setTimeout(resolve, 3000));
    console.log(`[Worker] Lote ID: ${job.id} procesado con éxito.`);
    return { processed: true, rows: job.data.totalRows || 50 };
  },
  {
    connection: {
      host: redisHost,
      port: redisPort,
    },
  }
);

importWorker.on('completed', job => {
  console.log(`[Worker] Trabajo #${job.id} completado satisfactoriamente.`);
});

importWorker.on('failed', (job, err) => {
  console.error(`[Worker] Trabajo #${job?.id} falló:`, err);
});
