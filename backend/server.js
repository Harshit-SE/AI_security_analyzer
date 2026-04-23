/**
 * AI Security Scanner - Backend Server (server.js)
 * Local Llama3 + RAG Architecture
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import { urlScanRouter }    from './routes/scanUrl.js';
import { codeScanRouter }   from './routes/scanCode.js';
import { apiAnalyzeRouter } from './routes/analyzeApi.js';
import { errorHandler }     from './middleware/errorHandler.js';

const app  = express();
const PORT = process.env.PORT || 3001;
const RAG_SERVICE_URL = process.env.RAG_SERVICE_URL || 'http://localhost:5001';

// ── Security middleware ───────────────────────────────────────────────────────
app.use(helmet());

const allowedOrigins = [
  process.env.FRONTEND_URL || 'http://localhost:3000',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS: origin "${origin}" not allowed`));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests — please slow down.' },
});
app.use('/api/', limiter);

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/scan-url',    urlScanRouter);
app.use('/api/scan-code',   codeScanRouter);
app.use('/api/analyze-api', apiAnalyzeRouter);

// Health-check
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV || 'development',
    ragServiceConfigured: true,
    ragServiceUrl: RAG_SERVICE_URL
  });
});

// ── Global error handler (must be last) ──────────────────────────────────────
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`🛡️  AI Security Scanner backend running on http://localhost:${PORT}`);
  console.log(`🧠 Connected to Local AI RAG Service at: ${RAG_SERVICE_URL}`);
  console.log(`🦙 Ensure Ollama (Llama 3) is running on port 11434`);
});

export default app;