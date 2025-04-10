const express = require("express");
const path = require("path");
const nodemailer = require("nodemailer");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
require("dotenv").config();
const cors = require("cors");
const adminRoutes = require("./routes/adminRoutes");
const userRoutes = require("./routes/userRoutes");
const hospitalRoutes = require("./routes/hospitalRoutes");
const inventoryRouter = require("./routes/userRoutes");


const app = express();
const port = process.env.PORT || 5500;

const corsOptions = {
  origin: ['http://127.0.0.1:5502', 'http://localhost:5502'], // Allow both localhost and 127.0.0.1
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept-Language'],
  credentials: true,
  optionsSuccessStatus: 200 // For legacy browser support
};

// Apply CORS middleware
app.use(cors(corsOptions));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept-Language');
  next();
});

// Handle preflight requests
app.options('*', cors(corsOptions)); // Enable preflight for all routes

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use((req, res, next) => {
    res.setTimeout(5000, () => {
      console.error('Timeout reached for:', req.originalUrl);
      res.status(504).json({ error: 'Request timeout' });
    });
    next();
  });

  app.get('/ping', (req, res) => {
    res.status(200).send('Server is running');
  });
// Routes
app.use((req, res, next) => {
    console.log(`Incoming ${req.method} ${req.path}`);
    console.log('Headers:', req.headers);
    next();
  });
app.use("/blood-inventory", inventoryRouter);
app.use("/", userRoutes);
app.use("/", adminRoutes);
app.use("/", hospitalRoutes);
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "homepage.html"));
});

// Database Connection
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "BloodLink123",
  database: process.env.DB_NAME || "bloodlink123",
  port: 3306,
  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0,
  connectTimeout: 10000,         // 10 seconds connection timeout
  acquireTimeout: 10000,         // 10 seconds to get a connection
  timeout: 60000,                // 60 seconds query timeout
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000
});

app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      console.log(`${req.method} ${req.url} - ${Date.now() - start}ms`);
    });
    next();
  });

pool.on('error', (err) => {
    console.error('🆘 MySQL Pool Error:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.message === 'Pool is closed.') {
      console.log('🔁 Attempting to reconnect...');
      initializePool(); // Call your pool creation function
    }
  });
  
  function initializePool() {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      enableKeepAlive: true,
      keepAliveInitialDelay: 10000
    });
  }

// Test DB Connection
async function testDBConnection() {
  try {
    const connection = await pool.getConnection();
    console.log("✅ Connected to MySQL Database");
    connection.release();
  } catch (error) {
    console.error("❌ Database Connection Failed:", error);
  }
}
testDBConnection();

// Helper Functions
async function hashPassword(password) {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

async function findUserByEmail(email, connection) {
  try {
    const query = "SELECT * FROM users WHERE email = ?";
    const [rows] = await connection.query(query, [email]);
    return rows.length > 0 ? rows[0] : null;
  } catch (error) {
    console.error("❌ Error Finding User:", error);
    return null;
  }
}

// Add to your server initialization
const schedule = require('node-schedule');

// Run daily at 9 AM
schedule.scheduleJob('0 9 * * *', async () => {
    const [users] = await pool.query(
        `SELECT id, email FROM users 
         WHERE password_changed_at < DATE_SUB(NOW(), INTERVAL 80 DAY)`
    );
    
    users.forEach(user => {
        sendPasswordExpiryWarning(user.email);
    });
});

app.options('/api/users', cors(corsOptions)); // Explicit preflight handling

// API Endpoints
app.post("/api/users", async (req, res) => {
  const { name, phone, email, password, blood_type, location, role } = req.body;

  if (!name || !phone || !email || !password || !blood_type || !location || !role) {
    return res.status(400).json({ error: "❌ All fields are required." });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const existingUser = await findUserByEmail(email, connection);
    if (existingUser) {
      return res.status(409).json({ error: "❌ Email already in use." });
    }

    const hashedPassword = await hashPassword(password);
    const query = "INSERT INTO users (name, phone, email, password, blood_type, location, role) VALUES (?, ?, ?, ?, ?, ?, ?)";
    await connection.query(query, [name, phone, email, hashedPassword, blood_type, location, role]);
    res.status(201).json({ message: "✅ User created successfully!" });

  } catch (error) {
    console.error("🚨 Database error:", error);
    res.status(500).json({ error: "❌ Server error! Please try again later." });
  } finally {
    if (connection) connection.release();
  }
});

app.get('/api/test', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 + 1 AS solution');
    res.json({ message: 'MySQL connected!', solution: rows[0].solution });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/test', (req, res) => {
  res.json({ message: "CORS is working!" });
});

app.get("/test", (req, res) => {
  res.send("✅ Backend is working!");
});


// Server Initialization with proper fallback handling
const mainServer = app.listen(port, '0.0.0.0', () => {
  console.log(`✅ Server running on http://192.168.8.14:${port}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${port} is in use. Trying alternative port...`);
    const fallbackServer = app.listen(0, '0.0.0.0', () => {
      const fallbackPort = fallbackServer.address().port;
      console.log(`⚠️ Fallback server running on http://192.168.8.14:${fallbackPort}`);
    });
  }
});

// Export the pool for use in other files
module.exports = pool;
