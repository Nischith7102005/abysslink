const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);

// Environment config
const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// CORS - Allow multiple origins
const allowedOrigins = [
  'https://abysslink.vercel.app',
  'https://abysslink.onrender.com',
  'http://localhost:3000',
  'http://localhost:5173'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
};

app.use(cors(corsOptions));
app.use(express.json());

// Socket.IO setup
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

// Room storage
const rooms = new Map();

// Room class
class Room {
  constructor(id) {
    this.id = id;
    this.users = new Map();
    this.createdAt = Date.now();
  }

  addUser(socketId, username) {
    this.users.set(socketId, {
      id: socketId,
      username,
      joinedAt: Date.now()
    });
  }

  removeUser(socketId) {
    this.users.delete(socketId);
  }

  getUsers() {
    return Array.from(this.users.values());
  }

  getUserCount() {
    return this.users.size;
  }

  isEmpty() {
    return this.users.size === 0;
  }
}

// API Routes
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    rooms: rooms.size,
    uptime: process.uptime()
  });
});

app.post('/api/rooms', (req, res) => {
  const roomId = uuidv4().substring(0, 8);
  const room = new Room(roomId);
  rooms.set(roomId, room);
  
  console.log(`Room created: ${roomId}`);
  
  res.status(201).json({
    success: true,
    roomId,
    message: 'Room created successfully'
  });
});

app.get('/api/rooms/:roomId', (req, res) => {
  const { roomId } = req.params;
  const room = rooms.get(roomId);
  
  if (!room) {
    return res.status(404).json({
      success: false,
      message: 'Room not found'
    });
  }
  
  res.json({
    success: true,
    room: {
      id: room.id,
      userCount: room.getUserCount(),
      users: room.getUsers(),
      createdAt: room.createdAt
    }
  });
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  socket.on('join-room', ({ roomId, username }) => {
    const room = rooms.get(roomId);
    
    if (!room) {
      socket.emit('error', { message: 'Room not found' });
      return;
    }

    // Leave any previous rooms
    socket.rooms.forEach((r) => {
      if (r !== socket.id) {
        socket.leave(r);
      }
    });

    socket.join(roomId);
    room.addUser(socket.id, username);
    socket.roomId = roomId;
    socket.username = username;

    console.log(`${username} joined room ${roomId}`);

    // Notify room
    socket.to(roomId).emit('user-joined', {
      userId: socket.id,
      username,
      users: room.getUsers()
    });

    // Send current users to the joining user
    socket.emit('room-joined', {
      roomId,
      users: room.getUsers()
    });
  });

  socket.on('offer', ({ offer, to }) => {
    console.log(`Offer from ${socket.id} to ${to}`);
    socket.to(to).emit('offer', {
      offer,
      from: socket.id,
      username: socket.username
    });
  });

  socket.on('answer', ({ answer, to }) => {
    console.log(`Answer from ${socket.id} to ${to}`);
    socket.to(to).emit('answer', {
      answer,
      from: socket.id
    });
  });

  socket.on('ice-candidate', ({ candidate, to }) => {
    socket.to(to).emit('ice-candidate', {
      candidate,
      from: socket.id
    });
  });

  socket.on('chat-message', ({ roomId, message }) => {
    const room = rooms.get(roomId);
    if (room) {
      io.to(roomId).emit('chat-message', {
        userId: socket.id,
        username: socket.username,
        message,
        timestamp: Date.now()
      });
    }
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
    
    if (socket.roomId) {
      const room = rooms.get(socket.roomId);
      
      if (room) {
        room.removeUser(socket.id);
        
        socket.to(socket.roomId).emit('user-left', {
          userId: socket.id,
          username: socket.username,
          users: room.getUsers()
        });

        // Clean up empty rooms after a delay
        if (room.isEmpty()) {
          setTimeout(() => {
            if (room.isEmpty()) {
              rooms.delete(socket.roomId);
              console.log(`Room ${socket.roomId} deleted (empty)`);
            }
          }, 60000); // 1 minute delay
        }
      }
    }
  });
});

// Clean up old empty rooms periodically
setInterval(() => {
  const now = Date.now();
  rooms.forEach((room, roomId) => {
    if (room.isEmpty() && now - room.createdAt > 3600000) {
      rooms.delete(roomId);
      console.log(`Room ${roomId} deleted (old and empty)`);
    }
  });
}, 300000); // Every 5 minutes

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT} in ${NODE_ENV} mode`);
  console.log(`Allowed origins: ${allowedOrigins.join(', ')}`);
});
