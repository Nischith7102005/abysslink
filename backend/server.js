// backend/server.js
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// Load environment variables
dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 10000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// In-memory storage
const activeRooms = new Map(); // roomId → { hostId, participants: Set }

// ========================
// Security Middleware
// ========================

// Basic security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// Parse JSON bodies
app.use(express.json({ limit: '100kb' }));

// ========================
// CORS Configuration
// ========================

// Safely parse and trim allowed origins
const allowedOrigins = FRONTEND_URL.split(',').map(origin => origin.trim());

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
};

// Apply CORS globally
app.use(cors(corsOptions));

// Explicitly handle preflight requests for all routes
app.options('*', cors(corsOptions));

// ========================
// Rate Limiting
// ========================

const createRoomLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 room creations per window
  message: { error: 'Too many room creation attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

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
app.post('/api/rooms/create', createRoomLimiter, (req, res) => {
  const { hostId } = req.body;
  
  if (!hostIsString(hostId)) {
    return res.status(400).json({ error: 'Valid hostId is required' });
  }

  const roomId = generateRoomId(6);
  activeRooms.set(roomId, {
    hostId,
    participants: new Set([hostId])
  });

  console.log(`Room created: ${roomId} by ${hostId}`);
  res.json({ roomId, hostId });
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
    participantCount: room.participants.size
  });
});

// Delete room
app.delete('/api/rooms/:roomId', (req, res) => {
  const { roomId } = req.params;
  if (activeRooms.has(roomId)) {
    activeRooms.delete(roomId);
    console.log(`Room deleted: ${roomId}`);
    return res.json({ success: true });
  }
  res.status(404).json({ error: 'Room not found' });
});

function hostIsString(hostId) {
  return typeof hostId === 'string' && hostId.trim().length > 0;
}

function generateRoomId(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  // Ensure uniqueness
  if (activeRooms.has(result)) {
    return generateRoomId(length);
  }
  return result;
}

// ========================
// Serve Static Frontend (fallback)
// ========================

const frontendPath = path.join(__dirname, '..', 'frontend');
if (fs.existsSync(frontendPath)) {
  app.use(express.static(frontendPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(frontendPath, 'index.html'));
  });
} else {
  app.get('*', (req, res) => {
    res.status(404).send('Frontend not found. Run `npm run build` in frontend/');
  });
}

// ========================
// Socket.IO
// ========================

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  },
  // Disable long polling if you only want WebSocket
  transports: ['websocket']
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-room', (roomId) => {
    const room = activeRooms.get(roomId);
    if (!room) {
      socket.emit('error', { message: 'Room does not exist' });
      return;
    }

    socket.join(roomId);
    room.participants.add(socket.id);
    console.log(`User ${socket.id} joined room ${roomId}`);

    // Notify others in room
    socket.to(roomId).emit('user-joined', { userId: socket.id });
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
    // Clean up participant from any room
    for (const [roomId, room] of activeRooms.entries()) {
      if (room.participants.has(socket.id)) {
        room.participants.delete(socket.id);
        socket.to(roomId).emit('user-left', { userId: socket.id });
        console.log(`User ${socket.id} disconnected from room ${roomId}`);
        
        // Optional: delete empty rooms
        // if (room.participants.size === 0) {
        //   activeRooms.delete(roomId);
        // }
        break;
      }
    }
  });
});

// ========================
// Start Server
// ========================

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Allowed origins: ${allowedOrigins.join(', ')}`);
});

module.exports = { app, server };
