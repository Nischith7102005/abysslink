import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { randomBytes, createHash } from 'crypto';
import busboy from 'busboy';
import bcrypt from 'bcrypt';

// ============================================
// 1. ENVIRONMENT SETUP
// ============================================
dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const httpServer = http.createServer(app);

const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const BCRYPT_ROUNDS = 12;
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const ROOM_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

// Allowed origins
const allowedOrigins = [
  'https://abysslink.vercel.app',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:3000',
  'http://localhost:5173'
];

// ============================================
// 2. SECURITY MIDDLEWARE
// ============================================

// Trust proxy - MUST be before rate limiters (Render uses reverse proxy)
app.set('trust proxy', 1);

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.socket.io", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://i.ibb.co", "blob:"],
      connectSrc: ["'self'", "wss://abysslink.onrender.com", "https://abysslink.onrender.com", "ws://localhost:*", "http://localhost:*"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false, // Required for some external resources
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'no-referrer' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' }
}));

// Additional privacy headers
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Permissions-Policy', 'interest-cohort=(), geolocation=(), microphone=(), camera=()');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin) || NODE_ENV === 'development') {
      callback(null, true);
    } else {
      console.warn(`[CORS] Blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Body parser with size limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// ============================================
// 3. RATE LIMITING
// ============================================

// General API rate limiter
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/health'
});

// Strict limiter for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per 15 minutes
  message: { error: 'Too many authentication attempts, please try again in 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use IP + room ID combination for more granular limiting
    const ip = req.ip || req.connection.remoteAddress;
    const roomId = req.body?.roomId || 'unknown';
    return `${ip}:${roomId}`;
  }
});

// Room creation limiter
const createLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 rooms per hour per IP
  message: { error: 'Too many rooms created, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

// File upload limiter
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 uploads per hour
  message: { error: 'Upload limit reached, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', generalLimiter);

// ============================================
// 4. STORAGE & DATA STRUCTURES
// ============================================

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true, mode: 0o750 });
}

// Secure file serving with validation
app.use('/uploads', (req, res, next) => {
  // Only allow specific file patterns
  const filename = path.basename(req.path);
  if (!/^[a-zA-Z0-9_-]+\.bin$/.test(filename)) {
    return res.status(403).json({ error: 'Invalid file request' });
  }
  
  const filePath = path.join(uploadDir, filename);
  
  // Prevent directory traversal
  if (!filePath.startsWith(uploadDir)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Set secure headers for file downloads
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  next();
}, express.static(uploadDir, {
  dotfiles: 'deny',
  index: false,
  maxAge: '1h'
}));

// In-Memory Data Stores
const rooms = new Map();
const socketToRoom = new Map();
const socketAuth = new Map(); // Track authenticated sockets

// ============================================
// 5. UTILITY FUNCTIONS
// ============================================

/**
 * Generate cryptographically secure room ID
 */
function generateSecureRoomId() {
  return randomBytes(16).toString('base64url');
}

/**
 * Generate secure file ID
 */
function generateSecureFileId() {
  return randomBytes(12).toString('hex');
}

/**
 * Sanitize string input
 */
function sanitizeString(input, maxLength = 100) {
  if (typeof input !== 'string') return '';
  return input
    .trim()
    .substring(0, maxLength)
    .replace(/[<>\"\'&]/g, (char) => {
      const entities = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
      };
      return entities[char] || char;
    });
}

/**
 * Validate room ID format
 */
function isValidRoomId(roomId) {
  if (typeof roomId !== 'string') return false;
  // Base64url format, 16 bytes = ~22 chars
  return /^[A-Za-z0-9_-]{20,24}$/.test(roomId);
}

/**
 * Validate password strength
 */
function isValidPassword(password) {
  if (typeof password !== 'string') return false;
  return password.length >= 8 && password.length <= 128;
}

/**
 * Secure room cleanup
 */
function destroyRoom(roomId, reason = 'manual') {
  const room = rooms.get(roomId);
  if (!room) return false;
  
  // Delete all associated files
  room.files.forEach(file => {
    try {
      const filePath = path.join(uploadDir, path.basename(file.url));
      if (fs.existsSync(filePath) && filePath.startsWith(uploadDir)) {
        fs.unlinkSync(filePath);
      }
    } catch (err) {
      console.error(`[CLEANUP] File deletion error: ${err.message}`);
    }
  });
  
  // Clear room data
  room.messages = [];
  room.files = [];
  room.participants.clear();
  
  rooms.delete(roomId);
  console.log(`[ROOM DESTROYED] ${roomId} - Reason: ${reason}`);
  return true;
}

/**
 * Log security events (in production, send to SIEM)
 */
function securityLog(event, details) {
  const timestamp = new Date().toISOString();
  console.log(`[SECURITY] ${timestamp} - ${event}:`, JSON.stringify(details));
}

// ============================================
// 6. SOCKET.IO INITIALIZATION
// ============================================

const io = new Server(httpServer, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000,
  maxHttpBufferSize: 1e6, // 1MB max message size
  connectionStateRecovery: {
    maxDisconnectionDuration: 2 * 60 * 1000, // 2 minutes
    skipMiddlewares: true
  }
});

// Socket.IO rate limiting middleware
const socketRateLimits = new Map();

io.use((socket, next) => {
  const clientIp = socket.handshake.address;
  const now = Date.now();
  
  // Clean old entries
  for (const [ip, data] of socketRateLimits.entries()) {
    if (now - data.timestamp > 60000) {
      socketRateLimits.delete(ip);
    }
  }
  
  const clientData = socketRateLimits.get(clientIp) || { count: 0, timestamp: now };
  
  if (now - clientData.timestamp > 60000) {
    clientData.count = 0;
    clientData.timestamp = now;
  }
  
  clientData.count++;
  socketRateLimits.set(clientIp, clientData);
  
  // Max 30 connections per minute per IP
  if (clientData.count > 30) {
    securityLog('SOCKET_RATE_LIMIT', { ip: clientIp, count: clientData.count });
    return next(new Error('Rate limit exceeded'));
  }
  
  next();
});

// ============================================
// 7. API ROUTES
// ============================================

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'active',
    rooms: rooms.size,
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// Create Room
app.post('/api/rooms/create', createLimiter, async (req, res) => {
  try {
    const { topic, password } = req.body;
    
    // Validate inputs
    if (!topic || typeof topic !== 'string') {
      return res.status(400).json({ error: 'Topic is required' });
    }
    
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Password must be 8-128 characters' });
    }
    
    const sanitizedTopic = sanitizeString(topic, 100);
    if (sanitizedTopic.length < 1) {
      return res.status(400).json({ error: 'Invalid topic' });
    }
    
    const roomId = generateSecureRoomId();
    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const expiresAt = Date.now() + ROOM_EXPIRY_MS;
    
    // Generate room-specific encryption salt (for client-side key derivation)
    const encryptionSalt = randomBytes(32).toString('base64');
    
    rooms.set(roomId, {
      id: roomId,
      topic: sanitizedTopic,
      password: hashedPassword,
      encryptionSalt,
      expiresAt,
      createdAt: Date.now(),
      messages: [],
      files: [],
      participants: new Set(),
      messageCount: 0
    });
    
    securityLog('ROOM_CREATED', { roomId, topic: sanitizedTopic, ip: req.ip });
    
    res.status(201).json({
      roomId,
      expiresAt,
      topic: sanitizedTopic,
      encryptionSalt
    });
  } catch (err) {
    console.error('[CREATE ERROR]', err);
    res.status(500).json({ error: 'Failed to create room' });
  }
});

// Validate Room Access
app.post('/api/rooms/validate', authLimiter, async (req, res) => {
  try {
    const { roomId, password } = req.body;
    
    // Validate room ID format
    if (!roomId || !isValidRoomId(roomId.trim())) {
      securityLog('INVALID_ROOM_FORMAT', { roomId, ip: req.ip });
      return res.status(400).json({ error: 'Invalid room key format' });
    }
    
    const room = rooms.get(roomId.trim());
    
    if (!room) {
      securityLog('ROOM_NOT_FOUND', { roomId, ip: req.ip });
      // Use same error message to prevent room enumeration
      return res.status(401).json({ error: 'Invalid room key or password' });
    }
    
    // Check expiration
    if (room.expiresAt <= Date.now()) {
      destroyRoom(roomId, 'expired');
      return res.status(401).json({ error: 'Invalid room key or password' });
    }
    
    // Verify password with timing-safe comparison (bcrypt handles this)
    const isValid = await bcrypt.compare(password || '', room.password);
    
    if (!isValid) {
      securityLog('AUTH_FAILED', { roomId, ip: req.ip });
      return res.status(401).json({ error: 'Invalid room key or password' });
    }
    
    securityLog('AUTH_SUCCESS', { roomId, ip: req.ip });
    
    res.json({
      roomId: room.id,
      topic: room.topic,
      expiresAt: room.expiresAt,
      encryptionSalt: room.encryptionSalt
    });
  } catch (err) {
    console.error('[VALIDATE ERROR]', err);
    res.status(500).json({ error: 'Validation failed' });
  }
});

// Manual Vanish
app.post('/api/rooms/vanish', authLimiter, async (req, res) => {
  try {
    const { roomId, password } = req.body;
    
    if (!roomId || !isValidRoomId(roomId)) {
      return res.status(400).json({ error: 'Invalid room key' });
    }
    
    const room = rooms.get(roomId);
    
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    const isValid = await bcrypt.compare(password || '', room.password);
    
    if (!isValid) {
      securityLog('VANISH_AUTH_FAILED', { roomId, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Notify all participants
    io.to(roomId).emit('room_vanished', { reason: 'manual_destruction' });
    
    // Destroy room
    destroyRoom(roomId, 'manual_vanish');
    
    securityLog('ROOM_VANISHED', { roomId, ip: req.ip });
    
    res.json({ success: true });
  } catch (err) {
    console.error('[VANISH ERROR]', err);
    res.status(500).json({ error: 'Destruction failed' });
  }
});

// File Upload with Busboy (more secure than multer)
app.post('/api/rooms/:roomId/upload', uploadLimiter, (req, res) => {
  const { roomId } = req.params;
  
  if (!isValidRoomId(roomId)) {
    return res.status(400).json({ error: 'Invalid room key' });
  }
  
  const room = rooms.get(roomId);
  
  if (!room) {
    return res.status(404).json({ error: 'Room not found' });
  }
  
  // Check room expiration
  if (room.expiresAt <= Date.now()) {
    destroyRoom(roomId, 'expired');
    return res.status(404).json({ error: 'Room expired' });
  }
  
  const bb = busboy({
    headers: req.headers,
    limits: {
      fileSize: MAX_FILE_SIZE,
      files: 1,
      fields: 3
    }
  });
  
  let fileData = null;
  let encryptedName = null;
  let originalSize = 0;
  let fileWritten = false;
  
  bb.on('field', (name, val) => {
    if (name === 'encryptedName') {
      try {
        encryptedName = JSON.parse(val);
      } catch (e) {
        encryptedName = null;
      }
    } else if (name === 'originalSize') {
      originalSize = parseInt(val, 10) || 0;
    }
  });
  
  bb.on('file', (name, file, info) => {
    if (name !== 'encryptedFile') {
      file.resume();
      return;
    }
    
    const fileId = generateSecureFileId();
    const filename = `${fileId}-${Date.now()}.bin`;
    const filePath = path.join(uploadDir, filename);
    
    // Ensure path is within upload directory
    if (!filePath.startsWith(uploadDir)) {
      file.resume();
      return;
    }
    
    const writeStream = fs.createWriteStream(filePath, { mode: 0o640 });
    let bytesWritten = 0;
    
    file.on('data', (data) => {
      bytesWritten += data.length;
      if (bytesWritten > MAX_FILE_SIZE) {
        file.destroy();
        writeStream.destroy();
        fs.unlink(filePath, () => {});
      }
    });
    
    file.pipe(writeStream);
    
    writeStream.on('finish', () => {
      fileWritten = true;
      fileData = {
        id: fileId,
        url: `/uploads/${filename}`,
        uploadedAt: Date.now(),
        originalSize,
        encryptedName,
        expiresAt: room.expiresAt
      };
    });
    
    writeStream.on('error', (err) => {
      console.error('[UPLOAD ERROR]', err);
      fs.unlink(filePath, () => {});
    });
  });
  
  bb.on('finish', () => {
    if (!fileWritten || !fileData) {
      return res.status(400).json({ error: 'Upload failed' });
    }
    
    room.files.push(fileData);
    io.to(roomId).emit('file_uploaded', fileData);
    
    securityLog('FILE_UPLOADED', { roomId, fileId: fileData.id, size: originalSize });
    
    res.json(fileData);
  });
  
  bb.on('error', (err) => {
    console.error('[BUSBOY ERROR]', err);
    res.status(500).json({ error: 'Upload processing failed' });
  });
  
  req.pipe(bb);
});

// ============================================
// 8. SOCKET.IO EVENT HANDLERS
// ============================================

io.on('connection', (socket) => {
  const clientIp = socket.handshake.address;
  
  // Message rate limiting per socket
  let messageCount = 0;
  let lastMessageTime = Date.now();
  
  const checkMessageRate = () => {
    const now = Date.now();
    if (now - lastMessageTime > 60000) {
      messageCount = 0;
      lastMessageTime = now;
    }
    messageCount++;
    return messageCount <= 60; // Max 60 messages per minute
  };
  
  socket.on('join_room', async ({ roomId, password }) => {
    try {
      // Validate inputs
      if (!isValidRoomId(roomId)) {
        socket.emit('error_message', { error: 'Invalid room key' });
        return;
      }
      
      const room = rooms.get(roomId);
      
      if (!room) {
        socket.emit('error_message', { error: 'Room not found' });
        return;
      }
      
      // Check expiration
      if (room.expiresAt <= Date.now()) {
        destroyRoom(roomId, 'expired');
        socket.emit('error_message', { error: 'Room expired' });
        return;
      }
      
      // Verify password
      const isValid = await bcrypt.compare(password || '', room.password);
      
      if (!isValid) {
        securityLog('SOCKET_AUTH_FAILED', { roomId, ip: clientIp, socketId: socket.id });
        socket.emit('error_message', { error: 'Authentication failed' });
        return;
      }
      
      // Leave any previous room
      const previousRoom = socketToRoom.get(socket.id);
      if (previousRoom && previousRoom !== roomId) {
        socket.leave(previousRoom);
        const prevRoom = rooms.get(previousRoom);
        if (prevRoom) {
          prevRoom.participants.delete(socket.id);
          io.to(previousRoom).emit('participant_update', { count: prevRoom.participants.size });
        }
      }
      
      // Join new room
      socket.join(roomId);
      room.participants.add(socket.id);
      socketToRoom.set(socket.id, roomId);
      socketAuth.set(socket.id, { roomId, authenticatedAt: Date.now() });
      
      securityLog('SOCKET_JOINED', { roomId, ip: clientIp, socketId: socket.id });
      
      socket.emit('join_success', {
        expiresAt: room.expiresAt,
        topic: room.topic,
        participantCount: room.participants.size,
        encryptionSalt: room.encryptionSalt
      });
      
      io.to(roomId).emit('participant_update', { count: room.participants.size });
      
      // Notify others
      socket.to(roomId).emit('system_message', {
        id: randomBytes(8).toString('hex'),
        text: 'A participant has joined',
        timestamp: Date.now(),
        type: 'system'
      });
      
    } catch (err) {
      console.error('[JOIN ERROR]', err);
      socket.emit('error_message', { error: 'Join failed' });
    }
  });
  
  socket.on('send_message', ({ roomId, encrypted }) => {
    try {
      // Rate limiting
      if (!checkMessageRate()) {
        socket.emit('error_message', { error: 'Message rate limit exceeded' });
        return;
      }
      
      // Verify authentication
      const auth = socketAuth.get(socket.id);
      if (!auth || auth.roomId !== roomId) {
        socket.emit('error_message', { error: 'Not authenticated to this room' });
        return;
      }
      
      const room = rooms.get(roomId);
      if (!room) {
        socket.emit('error_message', { error: 'Room not found' });
        return;
      }
      
      // Validate encrypted message format
      if (!encrypted || typeof encrypted.iv !== 'string' || typeof encrypted.ciphertext !== 'string') {
        socket.emit('error_message', { error: 'Invalid message format' });
        return;
      }
      
      // Size limits for encrypted content
      if (encrypted.iv.length > 50 || encrypted.ciphertext.length > 100000) {
        socket.emit('error_message', { error: 'Message too large' });
        return;
      }
      
      const msg = {
        id: randomBytes(8).toString('hex'),
        encrypted,
        timestamp: Date.now(),
        sender: socket.id
      };
      
      room.messageCount++;
      
      // Broadcast to all participants including sender
      io.to(roomId).emit('new_message', msg);
      
    } catch (err) {
      console.error('[MESSAGE ERROR]', err);
      socket.emit('error_message', { error: 'Message delivery failed' });
    }
  });
  
  socket.on('typing_start', ({ roomId }) => {
    const auth = socketAuth.get(socket.id);
    if (auth && auth.roomId === roomId) {
      socket.to(roomId).emit('user_typing', { sender: socket.id });
    }
  });
  
  socket.on('typing_stop', ({ roomId }) => {
    const auth = socketAuth.get(socket.id);
    if (auth && auth.roomId === roomId) {
      socket.to(roomId).emit('user_stopped_typing', { sender: socket.id });
    }
  });
  
  socket.on('disconnect', (reason) => {
    const roomId = socketToRoom.get(socket.id);
    
    if (roomId) {
      const room = rooms.get(roomId);
      if (room) {
        room.participants.delete(socket.id);
        io.to(roomId).emit('participant_update', { count: room.participants.size });
        
        // Notify others
        socket.to(roomId).emit('system_message', {
          id: randomBytes(8).toString('hex'),
          text: 'A participant has left',
          timestamp: Date.now(),
          type: 'system'
        });
      }
    }
    
    socketToRoom.delete(socket.id);
    socketAuth.delete(socket.id);
  });
  
  socket.on('error', (err) => {
    console.error('[SOCKET ERROR]', err);
  });
});

// ============================================
// 9. CLEANUP TASK
// ============================================

const cleanupInterval = setInterval(() => {
  const now = Date.now();
  let cleanedRooms = 0;
  let cleanedFiles = 0;
  
  for (const [roomId, room] of rooms.entries()) {
    if (room.expiresAt <= now) {
      // Notify any remaining participants
      io.to(roomId).emit('room_vanished', { reason: 'expired' });
      
      // Clean up files
      cleanedFiles += room.files.length;
      destroyRoom(roomId, 'scheduled_cleanup');
      cleanedRooms++;
    }
  }
  
  // Also clean orphaned files (files without associated rooms)
  try {
    const files = fs.readdirSync(uploadDir);
    for (const file of files) {
      const filePath = path.join(uploadDir, file);
      const stats = fs.statSync(filePath);
      
      // Delete files older than 25 hours (buffer for room expiry)
      if (now - stats.mtimeMs > 25 * 60 * 60 * 1000) {
        fs.unlinkSync(filePath);
        cleanedFiles++;
      }
    }
  } catch (err) {
    console.error('[CLEANUP] File scan error:', err.message);
  }
  
  if (cleanedRooms > 0 || cleanedFiles > 0) {
    console.log(`[CLEANUP] Removed ${cleanedRooms} rooms, ${cleanedFiles} files`);
  }
}, CLEANUP_INTERVAL_MS);

// ============================================
// 10. ERROR HANDLING
// ============================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS policy violation' });
  }
  
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// 11. GRACEFUL SHUTDOWN
// ============================================

const shutdown = (signal) => {
  console.log(`\n[SHUTDOWN] Received ${signal}, cleaning up...`);
  
  clearInterval(cleanupInterval);
  
  // Notify all connected clients
  io.emit('server_shutdown', { message: 'Server is shutting down' });
  
  // Close all connections
  io.close(() => {
    console.log('[SHUTDOWN] Socket.IO closed');
  });
  
  httpServer.close(() => {
    console.log('[SHUTDOWN] HTTP server closed');
    
    // Clean up all rooms
    for (const roomId of rooms.keys()) {
      destroyRoom(roomId, 'server_shutdown');
    }
    
    console.log('[SHUTDOWN] Cleanup complete');
    process.exit(0);
  });
  
  // Force exit after 10 seconds
  setTimeout(() => {
    console.error('[SHUTDOWN] Forced exit');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// ============================================
// 12. START SERVER
// ============================================

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════╗
║           ABYSSLINK BACKEND v2.0          ║
╠═══════════════════════════════════════════╣
║  Status:    RUNNING                       ║
║  Port:      ${PORT}                          ║
║  Env:       ${NODE_ENV.padEnd(28)}║
║  Security:  ENHANCED                      ║
╚═══════════════════════════════════════════╝
  `);
});
