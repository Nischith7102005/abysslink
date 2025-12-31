import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import bcrypt from 'bcrypt';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const httpServer = createServer(app);

// Environment config
const PORT = process.env.PORT || 10000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://abysslink.vercel.app';
const NODE_ENV = process.env.NODE_ENV || 'development';

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// CORS (strict)
const corsOptions = {
  origin: FRONTEND_URL.split(','),
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));

// Socket.IO
const io = new Server(httpServer, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

// Serve uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// In-memory storage
const rooms = new Map();
const socketToRoom = new Map();

// Multer setup (encrypted files only)
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

// 🔐 Hash password with bcrypt (async)
async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

// 🔐 Verify password
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// ==================== API ENDPOINTS ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', activeRooms: rooms.size });
});

// Create room
app.post('/api/rooms/create', async (req, res) => {
  try {
    const { topic, password } = req.body;
    if (!topic || !password || password.length < 8) {
      return res.status(400).json({ error: 'Topic and password (min 8 chars) required' });
    }
    const roomId = uuidv4();
    const hashedPassword = await hashPassword(password);
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;

    rooms.set(roomId, {
      id: roomId,
      topic,
      password: hashedPassword,
      expiresAt,
      messages: [],
      files: [],
      participants: new Set()
    });

    res.json({ roomId, expiresAt, topic });
  } catch (err) {
    console.error('[CREATE ERROR]', err);
    res.status(500).json({ error: 'Failed to create room' });
  }
});

// Validate room — always return 401 (stealth)
app.post('/api/rooms/validate', async (req, res) => {
  try {
    const { roomId, password } = req.body;
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);

    // Add artificial delay to prevent timing attacks
    if (!room) {
      await new Promise(r => setTimeout(r, 50));
      return res.status(401).json({ error: 'Invalid room key or password' });
    }

    const isValid = await verifyPassword(password, room.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid room key or password' });
    }

    res.json({ roomId: room.id, topic: room.topic, expiresAt: room.expiresAt });
  } catch (err) {
    console.error('[VALIDATE ERROR]', err);
    res.status(500).json({ error: 'Validation failed' });
  }
});

// Vanish room
app.post('/api/rooms/vanish', async (req, res) => {
  try {
    const { roomId, password } = req.body;
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);

    if (!room) {
      await new Promise(r => setTimeout(r, 50));
      return res.status(401).json({ error: 'Invalid room key or password' });
    }

    const isValid = await verifyPassword(password, room.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid room key or password' });
    }

    console.log(`[ROOM VANISHED] ${cleanRoomId}`);
    io.to(cleanRoomId).emit('room_vanished');
    destroyRoom(cleanRoomId);
    res.json({ success: true });
  } catch (err) {
    console.error('[VANISH ERROR]', err);
    res.status(500).json({ error: 'Failed to vanish room' });
  }
});

// Encrypted file upload
app.post('/api/rooms/:roomId/upload', upload.single('encryptedFile'), (req, res) => {
  try {
    const cleanRoomId = String(req.params.roomId).trim();
    const room = rooms.get(cleanRoomId);
    if (!room) return res.status(401).json({ error: 'Room not found' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const encryptedName = JSON.parse(req.body.encryptedName);
    const originalSize = parseInt(req.body.originalSize);

    const fileData = {
      id: uuidv4(),
      encryptedName,
      originalSize,
      url: `/uploads/${req.file.filename}`,
      uploadedAt: Date.now()
    };

    room.files.push(fileData);
    io.to(cleanRoomId).emit('file_uploaded', fileData);
    res.json(fileData);
  } catch (err) {
    console.error('[UPLOAD ERROR]', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ==================== SOCKET.IO ====================

io.on('connection', (socket) => {
  socket.on('join_room', async ({ roomId, password }) => {
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);
    if (!room) {
      socket.emit('error', 'Invalid room key or password');
      return;
    }

    const isValid = await verifyPassword(password, room.password);
    if (!isValid) {
      socket.emit('error', 'Invalid room key or password');
      return;
    }

    socket.join(cleanRoomId);
    room.participants.add(socket.id);
    socketToRoom.set(socket.id, cleanRoomId);

    socket.emit('join_success', {
      expiresAt: room.expiresAt,
      topic: room.topic,
      participantCount: room.participants.size
    });

    socket.emit('chat_history', room.messages);
    room.files.forEach(file => socket.emit('file_uploaded', file));

    // System message: join
    const joinMessage = {
      id: uuidv4(),
      text: 'A participant joined the room',
      timestamp: Date.now(),
      type: 'system',
      sender: 'system'
    };
    room.messages.push(joinMessage);
    socket.broadcast.to(cleanRoomId).emit('new_message', joinMessage);
    io.to(cleanRoomId).emit('participant_joined', {
      count: room.participants.size,
      message: 'Participant joined'
    });
  });

  // Accept E2EE messages only
  socket.on('send_message', ({ roomId, encrypted }) => {
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);
    if (!room || !encrypted) return;

    const msg = {
      id: uuidv4(),
      encrypted,
      timestamp: Date.now(),
      sender: socket.id
    };
    room.messages.push(msg);
    io.to(cleanRoomId).emit('new_message', msg);
  });

  socket.on('disconnect', () => {
    const roomId = socketToRoom.get(socket.id);
    if (roomId) {
      const room = rooms.get(roomId);
      if (room) {
        const leaveMessage = {
          id: uuidv4(),
          text: 'A participant left the room',
          timestamp: Date.now(),
          type: 'system',
          sender: 'system'
        };
        room.messages.push(leaveMessage);
        io.to(roomId).emit('new_message', leaveMessage);
        room.participants.delete(socket.id);
        io.to(roomId).emit('participant_left', {
          count: room.participants.size,
          message: 'Participant left'
        });
      }
      socketToRoom.delete(socket.id);
    }
  });
});

// ==================== HELPERS ====================

function destroyRoom(roomId) {
  const room = rooms.get(roomId);
  if (!room) return;

  // Notify all clients
  io.to(roomId).emit('new_message', {
    id: uuidv4(),
    text: 'Room has been destroyed',
    timestamp: Date.now(),
    type: 'system',
    sender: 'system'
  });
  io.to(roomId).emit('room_vanished');

  // Cleanup files
  room.files.forEach(file => {
    try {
      const fullPath = path.join(__dirname, file.url);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    } catch (e) {
      console.error(`[FILE DELETE ERROR] ${file.url}`, e);
    }
  });

  rooms.delete(roomId);
  console.log(`[ROOM DESTROYED] ${roomId}`);
}

// Safety net: hourly cleanup
setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms) {
    if (room.expiresAt <= now) {
      console.log(`[CLEANUP EXPIRED] ${id}`);
      destroyRoom(id);
    }
  }
}, 60 * 1000); // check every minute

// ==================== START SERVER ====================

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log('=================================');
  console.log(`🚀 AbyssLink Server`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 Environment: ${NODE_ENV}`);
  console.log('=================================');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] Cleaning up...');
  for (const [id] of rooms) {
    destroyRoom(id);
  }
  httpServer.close(() => process.exit(0));
});
