// backend/server.js
import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import bcrypt from 'bcrypt';

// ES Module equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const httpServer = createServer(app);

// Environment config
const PORT = process.env.PORT || 10000;
const FRONTEND_URL = (process.env.FRONTEND_URL || 'https://abysslink.vercel.app').split(',').map(o => o.trim());
const NODE_ENV = process.env.NODE_ENV || 'development';

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// CORS
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (FRONTEND_URL.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // 👈 Preflight support
app.use(express.json({ limit: '50mb' }));

// Socket.IO
const io = new Server(httpServer, {
  cors: corsOptions,
  transports: ['websocket']
});

// Uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// In-memory storage
const rooms = new Map();
const socketToRoom = new Map();

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${Date.now()}.bin`);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1000 } });

// Helpers
async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// === API Routes ===
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', activeRooms: rooms.size });
});

app.post('/api/rooms/create', async (req, res) => {
  try {
    const { topic, password } = req.body;
    if (!topic || !password || password.length < 8) {
      return res.status(400).json({ error: 'Topic and password (min 8 chars) required' });
    }
    const roomId = uuidv4();
    const hashedPassword = await hashPassword(password);
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
    rooms.set(roomId, { id: roomId, topic, password: hashedPassword, expiresAt, messages: [], files: [], participants: new Set() });
    res.json({ roomId, expiresAt, topic });
  } catch (err) {
    console.error('[CREATE ERROR]', err);
    res.status(500).json({ error: 'Failed to create room' });
  }
});

// ... (keep rest of your existing API routes unchanged)

// === Socket.IO ===
io.on('connection', (socket) => {
  // ... your existing socket logic
});

// === Helpers ===
function destroyRoom(roomId) {
  // ... your existing cleanup logic
}

setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms) {
    if (room.expiresAt <= now) {
      console.log(`[CLEANUP EXPIRED] ${id}`);
      destroyRoom(id);
    }
  }
}, 60 * 1000);

// === Start Server ===
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log('=================================');
  console.log(`🚀 AbyssLink Server`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 Environment: ${NODE_ENV}`);
  console.log(`✅ Allowed origins: ${FRONTEND_URL.join(', ')}`);
  console.log('=================================');
});

process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] Cleaning up...');
  for (const [id] of rooms) destroyRoom(id);
  httpServer.close(() => process.exit(0));
});
