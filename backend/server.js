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

// 1. ENVIRONMENT SETUP
dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const httpServer = http.createServer(app);

const PORT = process.env.PORT || 10000;

// Allow both production and local development origins
const allowedOrigins = [
  'https://abysslink.vercel.app',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:3000'
];

// 2. MIDDLEWARE
app.use(express.json({ limit: '50mb' }));

// Enhanced CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Security Headers (Adjusted for production compatibility)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});

// 3. STORAGE & UPLOADS
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

const upload = multer({ 
    storage, 
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit 
});

app.use('/uploads', express.static(uploadDir));

// In-Memory Data
const rooms = new Map();
const socketToRoom = new Map();

// 4. SOCKET.IO INITIALIZATION
const io = new Server(httpServer, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
  connectionStateRecovery: {} // Helps with minor disconnects
});

// 5. API ROUTES
app.get('/api/health', (req, res) => {
  res.json({ status: 'active', rooms: rooms.size, timestamp: new Date() });
});

// Create Room
app.post('/api/rooms/create', async (req, res) => {
  try {
    const { topic, password } = req.body;
    if (!topic || !password || password.length < 8) {
      return res.status(400).json({ error: 'Topic and password (min 8 characters) required' });
    }

    const roomId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 12);
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    rooms.set(roomId, {
      id: roomId,
      topic,
      password: hashedPassword,
      expiresAt,
      messages: [],
      files: [],
      participants: new Set()
    });
    
    console.log(`[ROOM CREATED] ${roomId}`);
    res.status(201).json({ roomId, expiresAt, topic });
  } catch (err) {
    console.error('[CREATE ERROR]', err);
    res.status(500).json({ error: 'Internal server error during room creation' });
  }
});

// Validate Room Access
app.post('/api/rooms/validate', async (req, res) => {
  try {
    const { roomId, password } = req.body;
    const room = rooms.get(String(roomId).trim());
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found or expired' });
    }

    const isValid = await bcrypt.compare(password, room.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    res.json({ roomId: room.id, topic: room.topic, expiresAt: room.expiresAt });
  } catch (err) {
    res.status(500).json({ error: 'Validation process failed' });
  }
});

// Manual Vanish
app.post('/api/rooms/vanish', async (req, res) => {
  const { roomId, password } = req.body;
  const room = rooms.get(roomId);
  
  if (room && await bcrypt.compare(password, room.password)) {
    // Clean up physical files
    room.files.forEach(file => {
      const filePath = path.join(uploadDir, path.basename(file.url));
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    });
    
    io.to(roomId).emit('room_vanished');
    rooms.delete(roomId);
    return res.json({ success: true });
  }
  res.status(401).json({ error: 'Unauthorized' });
});

// File Upload
app.post('/api/rooms/:roomId/upload', upload.single('encryptedFile'), (req, res) => {
  const room = rooms.get(req.params.roomId);
  if (!room || !req.file) return res.status(400).json({ error: 'Invalid upload request' });

  const fileData = {
    id: uuidv4(),
    url: `/uploads/${req.file.filename}`,
    uploadedAt: Date.now(),
    originalSize: req.body.originalSize,
    encryptedName: req.body.encryptedName ? JSON.parse(req.body.encryptedName) : null
  };
  
  room.files.push(fileData);
  io.to(req.params.roomId).emit('file_uploaded', fileData);
  res.json(fileData);
});

// 6. SOCKET LOGIC
io.on('connection', (socket) => {
  socket.on('join_room', async ({ roomId, password }) => {
    const room = rooms.get(roomId);
    
    if (room && await bcrypt.compare(password, room.password)) {
      socket.join(roomId);
      room.participants.add(socket.id);
      socketToRoom.set(socket.id, roomId);

      socket.emit('join_success', {
        expiresAt: room.expiresAt,
        topic: room.topic,
        participantCount: room.participants.size
      });

      io.to(roomId).emit('participant_update', { count: room.participants.size });
    } else {
      socket.emit('error_message', 'Authentication failed');
    }
  });

  socket.on('send_message', ({ roomId, encrypted }) => {
    const room = rooms.get(roomId);
    if (!room) return;

    const msg = { id: uuidv4(), encrypted, timestamp: Date.now(), sender: socket.id };
    room.messages.push(msg);
    io.to(roomId).emit('new_message', msg);
  });

  socket.on('disconnect', () => {
    const roomId = socketToRoom.get(socket.id);
    if (roomId) {
      const room = rooms.get(roomId);
      if (room) {
        room.participants.delete(socket.id);
        io.to(roomId).emit('participant_update', { count: room.participants.size });
      }
      socketToRoom.delete(socket.id);
    }
  });
});

// 7. CLEANUP TASK (Runs every 10 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms.entries()) {
    if (room.expiresAt <= now) {
      // Delete associated files from disk
      room.files.forEach(file => {
        const filePath = path.join(uploadDir, path.basename(file.url));
        if (fs.existsSync(filePath)) {
          fs.unlink(filePath, (err) => { if(err) console.error("File cleanup error:", err); });
        }
      });
      rooms.delete(id);
      console.log(`[CLEANUP] Room ${id} removed due to expiration.`);
    }
  }
}, 600000);

// 8. START SERVER
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`\n--- AbyssLink Backend ---`);
  console.log(`Status: Running`);
  console.log(`Port:   ${PORT}`);
  console.log(`Origins Allowed: ${allowedOrigins.join(', ')}`);
  console.log(`-------------------------\n`);
});
