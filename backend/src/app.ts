import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { Pool } from 'pg';

dotenv.config();

const app = express();
const port = process.env.BACKEND_PORT || 4000;

app.use(helmet());
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.get('/api/health', async (req, res) => {
  try {
    const dbResult = await pool.query('SELECT NOW()');
    res.json({
      status: 'success',
      message: 'SportCorp ERP Backend funcionando correctamente',
      database_time: dbResult.rows[0].now,
    });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Error de conexión con la base de datos', error });
  }
});

app.listen(port, () => {
  console.log(`[Backend] Servidor ejecutándose en el puerto ${port}`);
});
