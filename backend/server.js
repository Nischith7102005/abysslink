// backend/server.js
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcrypt';

// Load environment variables
dotenv.config();

// Resolve __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const httpServer = http.createServer(app);

const PORT = process.env.PORT || 10000;
const FRONTEND_URL = (process.env.FRONTEND_URL || 'https://abysslink.vercel.app')
  .split(',')
  .map(origin => origin.trim())
  .filter(origin => origin.length > 0);

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// JSON parsing
app.use(express.json({ limit: '50mb' }));

// ========================
// CORS Configuration
// ========================

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., curl, Postman, mobile)
    if (!origin) return callback(null, true);
    if (FRONTEND_URL.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS', 'DELETE'],
  allowedHeaders: ['Content-Type']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle preflight for all routes

// ========================
// Rate Limiting
// ========================

const createRoomLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { error: 'Too many room creation attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================
// Storage & Uploads
// ========================

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${Date.now()}.bin`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1000 }, // 50MB
  fileFilter: (req, file, cb) => {
    // Allow any binary (encrypted) file
    cb(null, true);
  }
});

app.use('/uploads', express.static(uploadDir));

// ========================
// In-Memory State
// ========================

const activeRooms = new Map(); // roomId → { hostId, password?, participants: Set, messages: [], files: [] }

// ========================
// Helper Functions
// ========================

async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

function generateRoomId(length = 6) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  if (activeRooms.has(result)) {
    return generateRoomId(length);
  }
  return result;
}

// ========================
// API Routes
// ========================

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    activeRooms: activeRooms.size
  });
});

// Create room
app.post('/api/rooms/create', createRoomLimiter, async (req, res) => {
  const { hostId, password } = req.body;

  if (!hostId || typeof hostId !== 'string' || hostId.trim().length === 0) {
    return res.status(400).json({ error: 'Valid hostId is required' });
  }

  let roomPassword = null;
  if (password) {
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    roomPassword = await hash<PASSWORD>(password);
  }

  const roomId = generateRoomId();
  activeRooms.set(roomId, {
    hostId,
    password: <PASSWORD>,
    participants: new Set([hostId]),
    messages: [],
    files: [],
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
  });

  console.log(`Room created: ${roomId} by ${hostId}`);
  res.json({ roomId, hostId, requiresPassword: !!password });
});

// Get room info
app.get('/api/rooms/:roomId', (req, res) => {
  const { roomId } = req.params;
  const room = activeRooms.get(roomId);
  
  if (!room) {
    return res.status(404).json({ error: 'Room not found' });
  }

  res.json({
    roomId,
    hostId: room.hostId,
    participantCount: room.participants.size,
    requiresPassword: !!room.password
  });
});

// Join room (password check)
app.post('/api/rooms/:roomId/join', async (req, res) => {
  const { roomId } = req.params;
  const { userId, password } = req.body;

  const room = activeRooms.get(roomId);
  if (!room) {
    return res.status(404).json({ error: 'Room not found' });
  }

  if (room.password) {
    if (!password) {
      return res.status(401).json({ error: 'Password required' });
    }
    const isValid = await verifyPassword(password, room.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }
  }

  room.participants.add(userId);
  res.json({ success: true });
});

// File upload
app.post('/api/rooms/:roomId/upload', upload.single('file'), (req, res) => {
  const { roomId } = req.params;
  const room = activeRooms.get(roomId);

  if (!room) {
    return res.status(404).json({ error: 'Room not found' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const fileRecord = {
    id: uuidv4(),
    name: 'encrypted.bin', // Original name hidden
    path: req.file.path,
    size: req.file.size,
    uploadedAt: Date.now()
  };

  room.files.push(fileRecord);
  res.json({ fileId: fileRecord.id, size: fileRecord.size });
});

// Delete room (for host)
app.delete('/api/rooms/:roomId', (req, res) => {
  const { roomId } = req.params;
  if (activeRooms.has(roomId)) {
    activeRooms.delete(roomId);
    console.log(`Room deleted: ${roomId}`);
    return res.json({ success: true });
  }
  res.status(404).json({ error: 'Room not found' });
});

// ========================
// Socket.IO
// ========================

const io = new Server(httpServer, {
  cors: corsOptions,
  transports: ['websocket']
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-room', (data) => {
    const { roomId, userId } = data;
    const room = activeRooms.get(roomId);
    if (!room) {
      socket.emit('error', { message: 'Room does not exist' });
      return;
    }

    socket.join(roomId);
    room.participants.add(userId || socket.id);
    console.log(`User ${userId || socket.id} joined room ${roomId}`);

    socket.to(roomId).emit('user-joined', { userId: userId || socket.id });
  });

  socket.on('offer', (data) => {
    socket.to(data.roomId).emit('offer', data);
  });

  socket.on('answer', (data) => {
    socket.to(data.roomId).emit('answer', data);
  });

  socket.on('ice-candidate', (data) => {
    socket.to(data.roomId).emit('ice-candidate', data);
  });

  socket.on('disconnect', () => {
    for (const [roomId, room] of activeRooms.entries()) {
      if (room.participants.has(socket.id)) {
        room.participants.delete(socket.id);
        socket.to(roomId).emit('user-left', { userId: socket.id });
        console.log(`User ${socket.id} disconnected from room ${roomId}`);
        break;
      }
    }
  });
});

// ========================
// Cleanup expired rooms
// ========================

setInterval(() => {
  const now = Date.now();
  for (const [roomId, room] of activeRooms.entries()) {
    if (room.expiresAt <= now) {
      console.log(`[EXPIRED] Cleaning up room ${roomId}`);
      activeRooms.delete(roomId);
    }
  }
}, 60000); // Every minute

// ========================
// Start Server
// ========================

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log('========================================');
  console.log(`🚀 AbyssLink Backend`);
  console.log(`📡 Listening on port ${PORT}`);
  console.log(`🌐 Allowed origins: ${FRONTEND_URL.join(', ')}`);
  console.log(`🕒 Node.js ${process.version}`);
  console.log('========================================');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] Cleaning up rooms...');
  activeRooms.clear();
  httpServer.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});
