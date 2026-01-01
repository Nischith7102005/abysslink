import express from "express";
import http from "http";
import { Server } from "socket.io";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cors from "cors";
import Busboy from "busboy";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { v4 as uuid } from "uuid";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: ["https://yourdomain.com", "http://localhost:8080"],
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
    credentials: false
  }
});

/* -------------------------------------------------------
   Security Middleware
-------------------------------------------------------- */
app.use(helmet({
  crossOriginResourcePolicy: { policy: "same-origin" }
}));

app.use(express.json({ limit: "200kb" }));

// REST rate limit
app.use(
  rateLimit({
    windowMs: 10 * 1000,
    max: 20,
    message: "Rate limit exceeded"
  })
);

// Room store
const rooms = new Map();

// Folder prep
const uploadFolder = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder);

/* -------------------------------------------------------
   Create a room
-------------------------------------------------------- */
app.post("/create-room", (req, res) => {
  const roomId = uuid();
  rooms.set(roomId, {
    members: new Set(),
    files: []
  });

  res.json({ roomId });
});

/* -------------------------------------------------------
   Upload a file
-------------------------------------------------------- */
app.post("/upload/:roomId", (req, res) => {
  const roomId = req.params.roomId;

  if (!rooms.has(roomId)) {
    return res.status(404).json({ error: "Invalid room" });
  }

  const busboy = new Busboy({ headers: req.headers });
  let savedFile = null;

  busboy.on("file", (field, file, filename, encoding, mimetype) => {
    const safeName = uuid() + path.extname(filename);
    const savePath = path.join(uploadFolder, safeName);
    const stream = fs.createWriteStream(savePath);

    file.pipe(stream);
    savedFile = { safeName, mimetype };
    rooms.get(roomId).files.push(savedFile);

    stream.on("close", () => {});
  });

  busboy.on("finish", () => {
    res.json({ OK: true, file: savedFile.safeName });
  });

  req.pipe(busboy);
});

/* -------------------------------------------------------
   Socket.IO
-------------------------------------------------------- */
io.use((socket, next) => {
  const roomId = socket.handshake.auth?.roomId;
  if (!roomId || !rooms.has(roomId)) {
    return next(new Error("Invalid room"));
  }
  next();
});

io.on("connection", (socket) => {
  const roomId = socket.handshake.auth.roomId;
  const room = rooms.get(roomId);

  room.members.add(socket.id);
  socket.join(roomId);

  socket.on("msg", (msg) => {
    if (typeof msg !== "string" || msg.length > 2000) return;
    io.to(roomId).emit("msg", msg);
  });

  socket.on("requestFiles", () => {
    io.to(socket.id).emit("files", room.files.map(f => f.safeName));
  });

  socket.on("disconnect", () => {
    room.members.delete(socket.id);
    if (room.members.size === 0) {
      room.files.forEach(file => {
        const filePath = path.join(uploadFolder, file.safeName);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      });
      rooms.delete(roomId);
    }
  });
});

/* -------------------------------------------------------
   Server
-------------------------------------------------------- */
server.listen(3000, () => {
  console.log("Secure server running on port 3000");
});
