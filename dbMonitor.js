// dbMonitor.js
const pool = require('./db');
const cron = require('node-cron');

// Check pool health every 5 minutes
cron.schedule('*/5 * * * *', async () => {
    try {
        const [rows] = await pool.query('SELECT 1 AS test');
        if (rows[0].test !== 1) {
            throw new Error('Pool health check failed');
        }
    } catch (error) {
        console.error('Pool health check failed - attempting to reconnect...');
        try {
            await pool.end();
            // Reinitialize pool
            pool.config.connectionConfig = {
                ...pool.config.connectionConfig,
                connectTimeout: 5000
            };
            await pool.getConnection().then(conn => conn.release());
            console.log('Pool reconnected successfully');
        } catch (reconnectError) {
            console.error('Failed to reconnect pool:', reconnectError);
        }
    }
});

module.exports = pool;