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
const socketToRoom = new Map();

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
      participants: new Set(),
      participantNames: new Map() // Track participant info for display
    });

    // Auto-expire timer
    const timer = setTimeout(() => {
      console.log(`[AUTO-EXPIRE] Room ${roomId}`);
      destroyRoom(roomId);
    }, 24 * 60 * 60 * 1000);
    roomTimers.set(roomId, timer);

    console.log(`[ROOM CREATED] ${roomId}`);
    res.json({ 
      roomId, 
      expiresAt,
      topic // Include topic in response
    });
  } catch (err) {
    console.error('[CREATE ERROR]', err);
    res.status(500).json({ error: 'Failed to create room' });
  }
});

// Validate room (for joining)
app.post('/api/rooms/validate', (req, res) => {
  try {
    const { roomId, password } = req.body;
    
    // Ensure roomId is a string and trim whitespace
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);

    if (!room) {
      console.log(`[VALIDATE] Room not found: ${cleanRoomId}`);
      return res.status(404).json({ error: 'Room not found' });
    }
    
    if (room.password !== password) {
      console.log(`[VALIDATE] Invalid password for room: ${cleanRoomId}`);
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
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);

    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    if (room.password !== password) {
      return res.status(401).json({ error: 'Invalid password' });
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

// File upload
app.post('/api/rooms/:roomId/upload', upload.single('file'), (req, res) => {
  try {
    const cleanRoomId = String(req.params.roomId).trim();
    const room = rooms.get(cleanRoomId);
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
    io.to(cleanRoomId).emit('file_uploaded', fileData);
    res.json(fileData);
  } catch (err) {
    console.error('[UPLOAD ERROR]', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ==================== SOCKET.IO ====================
io.on('connection', (socket) => {
  console.log(`[SOCKET CONNECTED] ${socket.id}`);

  socket.on('join_room', ({ roomId, password }) => {
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);
    
    if (!room) {
      console.log(`[JOIN FAILED] Room not found: ${cleanRoomId}`);
      socket.emit('error', 'Room not found');
      return;
    }
    
    if (room.password !== password) {
      console.log(`[JOIN FAILED] Invalid password for room: ${cleanRoomId}`);
      socket.emit('error', 'Invalid room key or password');
      return;
    }

    // Join room
    socket.join(cleanRoomId);
    room.participants.add(socket.id);
    socketToRoom.set(socket.id, cleanRoomId);

    console.log(`[JOINED] Socket ${socket.id} joined room ${cleanRoomId} (${room.participants.size} users)`);
    
    // Send join confirmation with full room data
    socket.emit('join_success', {
      expiresAt: room.expiresAt,
      topic: room.topic,
      participantCount: room.participants.size
    });
    
    // Send history
    socket.emit('chat_history', room.messages);
    room.files.forEach(file => socket.emit('file_uploaded', file));
    
    // Send system message that user joined
    const joinMessage = {
      id: uuidv4(),
      text: 'A participant joined the room',
      timestamp: Date.now(),
      type: 'system',
      sender: 'system'
    };
    room.messages.push(joinMessage);
    socket.broadcast.to(cleanRoomId).emit('new_message', joinMessage);
    
    // Notify others about participant count change
    io.to(cleanRoomId).emit('participant_joined', { 
      count: room.participants.size,
      message: 'Participant joined'
    });
  });

  socket.on('send_message', ({ roomId, message }) => {
    const cleanRoomId = String(roomId).trim();
    const room = rooms.get(cleanRoomId);
    if (!room || !message?.trim()) return;

    const msg = {
      id: uuidv4(),
      text: message.trim(),
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
        // Send system message that user left
        const leaveMessage = {
          id: uuidv4(),
          text: 'A participant left the room',
          timestamp: Date.now(),
          type: 'system',
          sender: 'system'
        };
        room.messages.push(leaveMessage);
        io.to(roomId).emit('new_message', leaveMessage);
        
        // Update participant count
        room.participants.delete(socket.id);
        io.to(roomId).emit('participant_left', { 
          count: room.participants.size,
          message: 'Participant left'
        });
      }
      socketToRoom.delete(socket.id);
    }
    console.log(`[SOCKET DISCONNECTED] ${socket.id}`);
  });
});

// ==================== HELPERS ====================
function destroyRoom(roomId) {
  const room = rooms.get(roomId);
  if (!room) return;

  // Send final system message
  const vanishMessage = {
    id: uuidv4(),
    text: 'Room has been destroyed',
    timestamp: Date.now(),
    type: 'system',
    sender: 'system'
  };
  room.messages.push(vanishMessage);
  io.to(roomId).emit('new_message', vanishMessage);
  io.to(roomId).emit('room_vanished');

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

  // Remove from storage
  rooms.delete(roomId);
  console.log(`[ROOM DESTROYED] ${roomId}`);
}

// Periodic cleanup (safety net)
setInterval(() => {
  const now = Date.now();
  for (const [id, room] of rooms) {
    if (room.expiresAt <= now) {
      console.log(`[CLEANUP EXPIRED] ${id}`);
      destroyRoom(id);
    }
  }
}, 60 * 60 * 1000); // hourly

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

socket.on('join_success', (data) => {
  expiresAt = data.expiresAt; // Use this for countdown
  document.getElementById('roomTopic').textContent = data.topic || 'Untitled Session';
  updateParticipants(data.participantCount);
  updateTimer(); // Start your countdown
});

function addMessage(msg) {
  const el = document.createElement('div');
  
  if (msg.type === 'system') {
    el.className = 'system-message';
    el.textContent = msg.text;
  } else {
    el.className = `message ${msg.sender === myId ? 'own' : 'other'}`;
    // ... rest of your message rendering
  }
  
  document.getElementById('messages').appendChild(el);
  el.scrollIntoView();
}
