import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { randomBytes, createHash } from 'crypto';
import busboy from 'busboy';
import bcrypt from 'bcrypt';

// ============================================
// 1. ENVIRONMENT SETUP
// ============================================
dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();
const httpServer = http.createServer(app);
const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const BCRYPT_ROUNDS = 12;
const MAX_FILE_SIZE = 50 * 1024 * 1024;
const ROOM_EXPIRY_MS = 24 * 60 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;

const allowedOrigins = ['https://abysslink.vercel.app'];

// ============================================
// 2. SECURITY MIDDLEWARE
// ============================================
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.socket.io", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://i.ibb.co", "blob:"],
      connectSrc: ["'self'", "wss://abysslink.onrender.com", "https://abysslink.onrender.com"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'no-referrer' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' }
}));

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Permissions-Policy', 'interest-cohort=(), geolocation=(), microphone=(), camera=()');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  credentials: false,
  maxAge: 86400
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '1mb' }));

// ============================================
// 3. RATE LIMITING
// ============================================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  keyGenerator: (req) => req.ip + (req.body?.roomId || '')
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20
});

// ============================================
// 4. STORAGE
// ============================================
const uploadDir = '/app/uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { mode: 0o700 });

app.use('/uploads', (req, res, next) => {
  const filename = path.basename(req.path);
  if (!/^[a-zA-Z0-9_-]{16,32}\.bin$/.test(filename)) return res.status(403).end();
  const filePath = path.join(uploadDir, filename);
  if (!filePath.startsWith(uploadDir)) return res.status(403).end();
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
}, express.static(uploadDir, { dotfiles: 'deny', index: false }));

const rooms = new Map();
const authTokens = new Map(); // { token: { roomId, expiresAt } }
const socketToRoom = new Map();

// ============================================
// 5. UTILS
// ============================================
function generateSecureToken(len = 32) {
  return randomBytes(len).toString('base64url');
}

function secureZero(buffer) {
  if (buffer && typeof buffer.fill === 'function') buffer.fill(0);
}

// ============================================
// 6. API ROUTES
// ============================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'active', version: '2.1-hardened' });
});

// DISABLE ROOM CREATION FOR MAX OPSEC
app.post('/api/rooms/create', (req, res) => {
  res.status(403).json({ error: 'Room creation disabled for max security' });
});

app.post('/api/rooms/validate', authLimiter, async (req, res) => {
  const { roomId, password } = req.body;
  if (!roomId || !password) return res.status(400).json({ error: 'Invalid input' });
  const room = rooms.get(roomId);
  if (!room || room.expiresAt <= Date.now()) {
    rooms.delete(roomId);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const isValid = await bcrypt.compare(password, room.password);
  if (!isValid) {
    secureZero(password);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = generateSecureToken();
  authTokens.set(token, { roomId, expiresAt: room.expiresAt });
  secureZero(password);
  res.json({ token, roomId: room.id, topic: room.topic, encryptionSalt: room.encryptionSalt, expiresAt: room.expiresAt });
});

// ============================================
// 7. SOCKET.IO
// ============================================
const io = new Server(httpServer, {
  cors: false,
  transports: ['websocket'],
  pingTimeout: 30000,
  pingInterval: 25000,
  maxHttpBufferSize: 500 * 1024,
  serveClient: false,
  path: '/socket'
});

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const roomId = socket.handshake.auth.roomId;
  const auth = authTokens.get(token);
  if (!auth || auth.roomId !== roomId || auth.expiresAt <= Date.now()) return next(new Error('Unauthorized'));
  authTokens.delete(token);
  socket.roomId = roomId;
  next();
});

io.on('connection', (socket) => {
  const room = rooms.get(socket.roomId);
  if (!room) return socket.disconnect(true);
  socket.join(socket.roomId);
  socketToRoom.set(socket.id, socket.roomId);

  socket.on('message', async (data) => {
    if (!data || !data.iv || !data.ct || !data.mac) return;
    const mac = await crypto.subtle.sign('HMAC', room.macKey, Buffer.from(data.iv + data.ct, 'base64'));
    if (!crypto.timingSafeEqual(Buffer.from(data.mac, 'base64'), Buffer.from(mac))) return;
    io.to(socket.roomId).emit('message', data);
  });

  socket.on('disconnect', () => socketToRoom.delete(socket.id));
});

// ============================================
// 8. CLEANUP + START
// ============================================
setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms.entries()) if (room.expiresAt <= now) rooms.delete(id);
  for (const [token, auth] of authTokens.entries()) if (auth.expiresAt <= now) authTokens.delete(token);
}, CLEANUP_INTERVAL_MS);

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`[MAX SECURITY] AbyssLink Backend v2.1-hardened on port ${PORT}`);
});
