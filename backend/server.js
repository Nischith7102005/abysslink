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

// Environment variables
const PORT = process.env.PORT || 10000;
const FRONTEND_URL = process.env.FRONTEND_URL || '*';
const NODE_ENV = process.env.NODE_ENV || 'development';

console.log('🔧 Environment:', NODE_ENV);
console.log('🌐 Frontend URL:', FRONTEND_URL);

// CORS configuration
const corsOptions = {
  origin: FRONTEND_URL === '*' ? '*' : FRONTEND_URL.split(','),
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json());

// Socket.IO with CORS
const io = new Server(httpServer, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// In-memory storage
const rooms = new Map();
const roomTimers = new Map();
const socketToRoom = new Map();

// File upload configuration
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
  limits: { fileSize: 50 * 1024 * 1024 }
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    activeRooms: rooms.size,
    uptime: process.uptime(),
    environment: NODE_ENV
  });
});

app.get('/', (req, res) => {
  res.json({
    name: 'AbyssLink API',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      health: '/api/health',
      createRoom: 'POST /api/rooms/create',
      joinRoom: 'POST /api/rooms/join',
      vanishRoom: 'POST /api/rooms/vanish'
    }
  });
});

// ==================== CREATE ROOM ====================
app.post('/api/rooms/create', (req, res) => {
  try {
    const { topic, password } = req.body;
    
    if (!topic || !password) {
      return res.status(400).json({ error: 'Topic and password are required' });
    }

    const roomId = uuidv4();
    const creatorKey = uuidv4();
    const expiresAt = Date.now() + (24 * 60 * 60 * 1000);

    rooms.set(roomId, {
      id: roomId,
      topic,
      password,
      creatorKey,
      createdAt: Date.now(),
      expiresAt,
      messages: [],
      files: [],
      participants: new Set()
    });

    console.log(`[CREATE] Room: ${roomId} | Topic: ${topic}`);

    const timer = setTimeout(() => {
      console.log(`[EXPIRE] Room: ${roomId}`);
      destroyRoom(roomId);
    }, 24 * 60 * 60 * 1000);
    
    roomTimers.set(roomId, timer);

    res.json({
      roomId,
      creatorKey,
      inviteLink: roomId,
      expiresAt
    });
  } catch (error) {
    console.error('[CREATE ERROR]', error);
    res.status(500).json({ error: 'Failed to create room' });
  }
});

// ==================== JOIN ROOM ====================
app.post('/api/rooms/join', (req, res) => {
  try {
    const { roomId, password } = req.body;
    const room = rooms.get(roomId);

    if (!room) {
      return res.status(404).json({ error: 'Room not found or expired' });
    }

    if (room.password !== password) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    console.log(`[JOIN] Room: ${roomId}`);

    res.json({
      roomId: room.id,
      topic: room.topic,
      expiresAt: room.expiresAt,
      timeRemaining: room.expiresAt - Date.now(),
      messageCount: room.messages.length
    });
  } catch (error) {
    console.error('[JOIN ERROR]', error);
    res.status(500).json({ error: 'Failed to join room' });
  }
});

// ==================== VANISH ROOM ====================
app.post('/api/rooms/vanish', (req, res) => {
  try {
    const { roomId, creatorKey } = req.body;
    const room = rooms.get(roomId);

    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }

    if (room.creatorKey !== creatorKey) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    console.log(`[VANISH] Room: ${roomId}`);
    
    io.to(roomId).emit('room_vanished', {
      message: 'This room has been destroyed by the creator'
    });

    destroyRoom(roomId);
    
    res.json({ success: true, message: 'Room vanished' });
  } catch (error) {
    console.error('[VANISH ERROR]', error);
    res.status(500).json({ error: 'Failed to vanish room' });
  }
});

// ==================== UPLOAD FILE ====================
app.post('/api/rooms/:roomId/upload', upload.single('file'), (req, res) => {
  try {
    const room = rooms.get(req.params.roomId);
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const fileData = {
      id: uuidv4(),
      name: req.file.originalname,
      url: `/uploads/${req.file.filename}`,
      size: req.file.size,
      uploadedAt: Date.now()
    };

    room.files.push(fileData);
    
    console.log(`[FILE] Room: ${req.params.roomId} | File: ${req.file.originalname}`);

    io.to(req.params.roomId).emit('file_uploaded', fileData);

    res.json(fileData);
  } catch (error) {
    console.error('[UPLOAD ERROR]', error);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

// ==================== SOCKET.IO ====================
io.on('connection', (socket) => {
  console.log(`[SOCKET] Connected: ${socket.id}`);

  socket.on('join_room', ({ roomId }) => {
    const room = rooms.get(roomId);
    
    if (!room) {
      socket.emit('error', 'Room not found');
      return;
    }

    socket.join(roomId);
    room.participants.add(socket.id);
    socketToRoom.set(socket.id, roomId);

    console.log(`[SOCKET] ${socket.id} joined ${roomId} (${room.participants.size} users)`);

    socket.emit('chat_history', room.messages);
    room.files.forEach(file => socket.emit('file_uploaded', file));
    
    io.to(roomId).emit('participant_joined', {
      count: room.participants.size
    });
  });

  socket.on('send_message', ({ roomId, message }) => {
    const room = rooms.get(roomId);
    
    if (!room || !message || !message.trim()) return;

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
    const roomId = socketToRoom.get(socket.id);
    
    if (roomId) {
      const room = rooms.get(roomId);
      
      if (room) {
        room.participants.delete(socket.id);
        io.to(roomId).emit('participant_left', {
          count: room.participants.size
        });
      }
      
      socketToRoom.delete(socket.id);
    }
    
    console.log(`[SOCKET] Disconnected: ${socket.id}`);
  });
});

// ==================== HELPERS ====================
function destroyRoom(roomId) {
  const room = rooms.get(roomId);
  if (!room) return;

  console.log(`[DESTROY] Room: ${roomId}`);

  room.files.forEach(file => {
    try {
      const filePath = path.join(__dirname, file.url);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    } catch (error) {
      console.error(`[DESTROY] File error:`, error);
    }
  });

  const timer = roomTimers.get(roomId);
  if (timer) clearTimeout(timer);
  roomTimers.delete(roomId);

  room.participants.forEach(socketId => socketToRoom.delete(socketId));
  rooms.delete(roomId);
}

// Cleanup expired rooms every hour
setInterval(() => {
  const now = Date.now();
  rooms.forEach((room, roomId) => {
    if (room.expiresAt <= now) {
      console.log(`[CLEANUP] Expired: ${roomId}`);
      io.to(roomId).emit('room_vanished', { message: 'Room expired' });
      destroyRoom(roomId);
    }
  });
}, 60 * 60 * 1000);

// ==================== START SERVER ====================
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log('=================================');
  console.log(`🚀 AbyssLink Server`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 Environment: ${NODE_ENV}`);
  console.log(`🔗 Frontend: ${FRONTEND_URL}`);
  console.log('=================================');
});

process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] Cleaning up...');
  rooms.forEach((room, roomId) => {
    io.to(roomId).emit('room_vanished', { message: 'Server shutdown' });
    destroyRoom(roomId);
  });
  httpServer.close(() => process.exit(0));
});