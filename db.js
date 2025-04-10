require("dotenv").config();
const mysql = require("mysql2/promise");

// Create the connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "BloodLink123",
  database: process.env.DB_NAME || "bloodlink123",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,  // 👈 Prevents premature disconnections
  connectTimeout: 60000,
  idleTimeout: 60000,
  keepAliveInitialDelay: 0
});

pool.on('acquire', (connection) => {
  console.log('Connection %d acquired', connection.threadId);
});

pool.on('release', (connection) => {
  console.log('Connection %d released', connection.threadId);
});

pool.on('enqueue', () => {
  console.log('Waiting for available connection slot');
});

// Export the pool directly
module.exports = pool;