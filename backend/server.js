/**
 * OmniScan AI - Backend Server (server.js)
 * Local Phi-3 + RAG Architecture
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

// ── Trust proxy ───────────────────────────────────────────────────────────────
// Set to 1 if directly behind one trusted reverse proxy (nginx/Caddy).
// Leave false if no proxy sits in front (avoids X-Forwarded-For spoofing).
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);

// ── Security middleware ───────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc:  ["'none'"],
    },
  },
}));

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
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
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
// 100kb is ample for all scan inputs. 5MB was dangerously large.
app.use(express.json({ limit: '100kb' }));
// extended: false uses the simpler querystring module — avoids prototype pollution
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// ── Optional API key authentication ──────────────────────────────────────────
// Set API_KEY in .env to enforce authentication. Leave unset for local dev only.
const API_KEY = process.env.API_KEY;
app.use('/api/', (req, res, next) => {
  if (!API_KEY) return next(); // No key configured — skip (local dev only)
  const provided = req.headers['x-api-key'];
  if (!provided || provided !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized — invalid or missing API key' });
  }
  next();
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/scan-url',    urlScanRouter);
app.use('/api/scan-code',   codeScanRouter);
app.use('/api/analyze-api', apiAnalyzeRouter);

// Health-check — intentionally minimal, does NOT expose internal URLs or env
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Global error handler (must be last) ──────────────────────────────────────
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`  OmniScan AI backend running on http://localhost:${PORT}`);
  console.log(`  API key enforcement: ${API_KEY ? 'ENABLED' : 'DISABLED (set API_KEY in .env to enable)'}`);
});

export default app;