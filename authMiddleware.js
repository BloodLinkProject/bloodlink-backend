const jwt = require('jsonwebtoken');
const pool = require("./db.js");
require('dotenv').config();


const authConfig = {
    secret: process.env.JWT_SECRET || 'mySuperSecretKey',
    tokenLife: '24h'
};

// ✅ Base token verification middleware
const verifyToken = (req, res, next) => {
  console.log('Received headers:', req.headers); // Debug log
  console.log('Auth header:', req.headers['authorization']); // Debug log
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  console.log('Extracted authHeader:', authHeader); // Debug log
    try {
      // 1. Get authorization header
      const authHeader = req.headers['authorization'] || req.headers['Authorization'];
      
      // 2. Validate header exists and is properly formatted
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ 
          success: false,
          error: 'Bearer token required' 
        });
      }
  
      // 3. Extract and verify token
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
      
      // 4. Attach user to request
      req.user = decoded;
      next();
      
    } catch (error) {
      console.error('Token verification error:', error);
      
      // Handle specific JWT errors
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          success: false,
          error: 'Session expired. Please login again.' 
        });
      }
      
      return res.status(401).json({ 
        success: false,
        error: 'Invalid authentication token' 
      });
    }
  };

// ✅ Admin verification middleware
const isAdmin = async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Admin access required'
            });
        }

        // Optional: Verify admin exists in database
        const [admin] = await pool.query(
            'SELECT id, email FROM admins WHERE id = ?', 
            [req.user.id]
        );

        if (!admin) {
            return res.status(403).json({
                success: false,
                error: 'Admin account not found'
            });
        }

        req.admin = admin; // Attach admin details
        next();

    } catch (error) {
        console.error('Admin verification error:', error);
        return res.status(500).json({
            success: false,
            error: 'Admin verification failed'
        });
    }
};

// ✅ Donor verification middleware
const isDonor = async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'donor') {
            return res.status(403).json({
                success: false,
                error: 'Donor access required'
            });
        }

        // Optional: Verify donor exists and is active
        const [donor] = await pool.query(
            `SELECT id, email, health_status 
             FROM users 
             WHERE id = ? AND role = 'donor' AND health_status = 'verified'`,
            [req.user.id]
        );

        if (!donor) {
            return res.status(403).json({
                success: false,
                error: 'Verified donor account required'
            });
        }

        req.donor = donor; // Attach donor details
        next();

    } catch (error) {
        console.error('Donor verification error:', error);
        return res.status(500).json({
            success: false,
            error: 'Donor verification failed'
        });
    }
};

function isHospital(req, res, next) {
    if (req.user && req.user.role === 'hospital') {
        next();
    } else {
        res.status(403).json({ error: "Access denied. Hospital only." });
    }
}


const passwordValidator = (req, res, next) => {
    const { password } = req.body;
    
    // Minimum 12 characters
    if (password.length < 12) {
        return res.status(400).json({ 
            error: "Password must be at least 12 characters long" 
        });
    }

    // Require uppercase, lowercase, number, and special character
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    
    if (!(hasUpper && hasLower && hasNumber && hasSpecial)) {
        return res.status(400).json({
            error: "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
        });
    }

    // Check against common passwords
    const commonPasswords = ['password', '1234567890', 'qwertyuiop'];
    if (commonPasswords.includes(password.toLowerCase())) {
        return res.status(400).json({
            error: "Password is too common. Please choose a more complex password"
        });
    }

    next();
};

async function checkPasswordExpiration(userId) {
    try {
        const [result] = await pool.query(
            `SELECT password_changed_at FROM users WHERE id = ?`,
            [userId]
        );
        
        if (result.length === 0) return true;
        
        const lastChanged = new Date(result[0].password_changed_at);
        const ninetyDaysAgo = new Date();
        ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
        
        return lastChanged < ninetyDaysAgo;
    } catch (error) {
        console.error('Password expiration check failed:', error);
        return false;
    }
}

const enforcePasswordRotation = async (req, res, next) => {
    if (!req.user) return next();
    
    const needsChange = await checkPasswordExpiration(req.user.id);
    if (needsChange) {
        return res.status(403).json({
            error: "Password expired. Please update your password",
            code: "PASSWORD_EXPIRED"
        });
    }
    
    next();
};

module.exports = {
    verifyToken,
    isAdmin,
    isDonor,
    isHospital,
    authConfig,
    passwordValidator,
    enforcePasswordRotation,
    checkPasswordExpiration
};