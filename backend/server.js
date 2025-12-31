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

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const httpServer = createServer(app);

// Environment config
const PORT = process.env.PORT || 10000;
const FRONTEND_URL = process.env.FRONTEND_URL || '*';
const NODE_ENV = process.env.NODE_ENV || 'development';

console.log('🔧 Environment:', NODE_ENV);
console.log('🌐 Frontend URL:', FRONTEND_URL);

// CORS
const corsOptions = {
  origin: FRONTEND_URL === '*' ? '*' : FRONTEND_URL.split(','),
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
};

app.use(cors(corsOptions));
app.use(express.json());

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
const roomTimers = new Map();

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${file.originalname}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1000 } // 50MB
});

// ==================== API ENDPOINTS ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', activeRooms: rooms.size });
});

// Create room
app.post('/api/rooms/create', (req, res) => {
  try {
    const { topic, password } = req.body;
    if (!topic || !password || password.length < 8) {
      return res.status(400).json({ error: 'Topic and password (min 8 chars) required' });
    }

    const roomId = uuidv4();
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24h

    rooms.set(roomId, {
      id: roomId,
      topic,
      password,
      expiresAt,
      messages: [],
      files: [],
      participants: new Set()
    });

    // Auto-expire timer
    const timer = setTimeout(() => {
      console.log(`[AUTO-EXPIRE] Room ${roomId}`);
      destroyRoom(roomId);
    }, 24 * 60 * 60 * 1000);
    roomTimers.set(roomId, timer);

    console.log(`[ROOM CREATED] ${roomId}`);
    res.json({ roomId, expiresAt });
  } catch (err) {
    console.error('[CREATE ERROR]', err);
    res.status(500).json({ error: 'Failed to create room' });
  }
});

// Validate room (for joining)
app.post('/api/rooms/validate', (req, res) => {
  try {
    const { roomId, password } = req.body;
    const room = rooms.get(roomId);

    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    if (room.password !== password) {
      return res.status(401).json({ error: 'Invalid room key or password' });
    }

    res.json({
      roomId: room.id,
      topic: room.topic,
      expiresAt: room.expiresAt
    });
  } catch (err) {
    console.error('[VALIDATE ERROR]', err);
    res.status(500).json({ error: 'Validation failed' });
  }
});

// Vanish room (any participant with password can trigger)
app.post('/api/rooms/vanish', (req, res) => {
  try {
    const { roomId, password } = req.body;
    const room = rooms.get(roomId);

    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    if (room.password !== password) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    console.log(`[ROOM VANISHED] ${roomId}`);
    io.to(roomId).emit('room_vanished');
    destroyRoom(roomId);
    res.json({ success: true });
  } catch (err) {
    console.error('[VANISH ERROR]', err);
    res.status(500).json({ error: 'Failed to vanish room' });
  }
});

// File upload
app.post('/api/rooms/:roomId/upload', upload.single('file'), (req, res) => {
  try {
    const room = rooms.get(req.params.roomId);
    if (!room) return res.status(404).json({ error: 'Room not found' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const fileData = {
      id: uuidv4(),
      name: req.file.originalname,
      url: `/uploads/${req.file.filename}`,
      size: req.file.size,
      uploadedAt: Date.now()
    };

    room.files.push(fileData);
    io.to(req.params.roomId).emit('file_uploaded', fileData);
    res.json(fileData);
  } catch (err) {
    console.error('[UPLOAD ERROR]', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ==================== SOCKET.IO ====================
io.on('connection', (socket) => {
  socket.on('join_room', ({ roomId, password }) => {
    const room = rooms.get(roomId);
    if (!room || room.password !== password) {
      socket.emit('error', 'Unauthorized');
      socket.disconnect(true);
      return;
    }

    socket.join(roomId);
    room.participants.add(socket.id);

    // Send history
    socket.emit('chat_history', room.messages);
    room.files.forEach(f => socket.emit('file_uploaded', f));
    io.to(roomId).emit('participant_joined', { count: room.participants.size });
  });

  socket.on('send_message', ({ roomId, message }) => {
    const room = rooms.get(roomId);
    if (!room || !message?.trim()) return;

    const msg = {
      id: uuidv4(),
      text: message.trim(),
      timestamp: Date.now(),
      sender: socket.id
    };
    room.messages.push(msg);
    io.to(roomId).emit('new_message', msg);
  });

  socket.on('disconnect', () => {
    // Find room this socket belonged to
    for (const [roomId, room] of rooms) {
      if (room.participants.has(socket.id)) {
        room.participants.delete(socket.id);
        io.to(roomId).emit('participant_left', { count: room.participants.size });
        break;
      }
    }
  });
});

// ==================== HELPERS ====================
function destroyRoom(roomId) {
  const room = rooms.get(roomId);
  if (!room) return;

  // Clean up files
  room.files.forEach(file => {
    try {
      const fullPath = path.join(__dirname, file.url);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    } catch (e) {
      console.error(`[FILE DELETE ERROR] ${file.url}`, e);
    }
  });

  // Clear timer
  const timer = roomTimers.get(roomId);
  if (timer) clearTimeout(timer);
  roomTimers.delete(roomId);

  rooms.delete(roomId);
}

// Periodic cleanup (optional safety net)
setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms) {
    if (room.expiresAt <= now) {
      console.log(`[CLEANUP EXPIRED] ${id}`);
      io.to(id).emit('room_vanished');
      destroyRoom(id);
    }
  }
}, 60 * 60 * 1000); // hourly

// ==================== START ====================
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log('=================================');
  console.log(`🚀 AbyssLink Server`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 Environment: ${NODE_ENV}`);
  console.log('=================================');
});

process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] Cleaning up...');
  for (const [id] of rooms) {
    io.to(id).emit('room_vanished');
    destroyRoom(id);
  }
  httpServer.close(() => process.exit(0));
});
