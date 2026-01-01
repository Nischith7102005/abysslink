// backend/server.js
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import cors from 'cors';
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

// Environment
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

// JSON body parser
app.use(express.json({ limit: '50mb' }));

// ========================
// CORS
// ========================
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl)
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
app.options('*', cors(corsOptions)); 

// ========================
// Uploads
// ========================
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${Date.now()}.bin`);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1000 } });
app.use('/uploads', express.static(uploadDir));

// ========================
// In-Memory Storage
// ========================
const rooms = new Map();
const socketToRoom = new Map();

// ========================
// Helpers
// ========================
async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// ========================
// API Routes
// ========================
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

    rooms.set(roomId, {
      id: roomId,
      topic,
      password: hashedPassword, // Fixed: removed <PASSWORD> placeholder
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

app.post('/api/rooms/validate', async (req, res) => {
  try {
    const { roomId, password } = req.body;
    if (!roomId || !password) return res.status(400).json({ error: 'Missing credentials' });
    
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);
    
    if (!room) {
      await new Promise(r => setTimeout(r, 100)); // Anti-timing attack
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

app.post('/api/rooms/vanish', async (req, res) => {
  try {
    const { roomId, password } = req.body;
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);
    
    if (!room) {
      return res.status(401).json({ error: 'Invalid room key or password' });
    }

    const isValid = await verifyPassword(password, room.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid room key or password' });
    }

    // Inform participants before deleting
    io.to(cleanRoomId).emit('room_vanished');
    
    rooms.delete(cleanRoomId);
    console.log(`[ROOM VANISHED] ${cleanRoomId}`);
    res.json({ success: true });
  } catch (err) {
    console.error('[VANISH ERROR]', err);
    res.status(500).json({ error: 'Failed to vanish room' });
  }
});

app.post('/api/rooms/:roomId/upload', upload.single('encryptedFile'), (req, res) => {
  try {
    const cleanRoomId = String(req.params.roomId).trim();
    const room = rooms.get(cleanRoomId);
    if (!room) return res.status(401).json({ error: 'Room not found' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const fileData = {
      id: uuidv4(),
      url: `/uploads/${req.file.filename}`,
      uploadedAt: Date.now(),
      originalSize: req.body.originalSize,
      encryptedName: req.body.encryptedName ? JSON.parse(req.body.encryptedName) : null
    };
    
    room.files.push(fileData);
    // Broadcast to the room that a file is available
    io.to(cleanRoomId).emit('file_uploaded', fileData);
    
    res.json(fileData);
  } catch (err) {
    console.error('[UPLOAD ERROR]', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ========================
// Socket.IO
// ========================
const io = new Server(httpServer, {
  cors: corsOptions,
  transports: ['websocket', 'polling']
});

io.on('connection', (socket) => {
  socket.on('join_room', async ({ roomId, password }) => {
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);
    
    if (!room || !(await verifyPassword(password, room.password))) {
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

    // Notify others
    socket.to(cleanRoomId).emit('participant_joined', {
      count: room.participants.size,
      message: 'A new node has entered the abyss.'
    });
  });

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
        room.participants.delete(socket.id);
        io.to(roomId).emit('participant_left', {
          count: room.participants.size,
          message: 'A node has disconnected.'
        });
      }
      socketToRoom.delete(socket.id);
    }
  });
});

// Cleanup expired rooms and their files
setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms.entries()) {
    if (room.expiresAt <= now) {
      // In a real production app, you would also fs.unlink the files in room.files here
      rooms.delete(id);
    }
  }
}, 60000);

// Start server
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log('========================================');
  console.log(`🚀 AbyssLink Backend`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 Allowed origins: ${FRONTEND_URL.join(', ')}`);
  console.log('========================================');
});
