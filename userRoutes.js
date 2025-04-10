const express = require('express');
const router = express.Router();
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const bcrypt = require("bcrypt");    // Ensure bcrypt is imported
const inventoryRouter = express.Router(); // ✅ Define inventoryRouter
const { sendVerificationEmail } = require("../services/emailService"); // 
const userModel = require('../models/userModel'); 
const { getDonationHistory } = require('../models/userModel'); 
const { findUserByEmail } = require('../models/userModel'); 
const path = require('path');
const cors = require('cors');
const pool = require("../db");
const jwt = require("jsonwebtoken");  // ✅ Import JWT
const { verifyToken, isDonor, authConfig, passwordValidator, enforcePasswordRotation } = require('../authMiddleware'); // Updated import
const { getAllHospitals, getHospitalById } = require('../models/userModel');
const zxcvbn = require('zxcvbn');


// Add this route before module.exports
router.get('/users/check-status', async (req, res) => {
    try {
        const { email } = req.query;
        
        if (!email) {
            return res.status(400).json({ error: "Email parameter is required" });
        }

        const [user] = await pool.query(
            "SELECT id, email, verified FROM users WHERE email = ? LIMIT 1",
            [email]
        );

        res.json({
            exists: user.length > 0,
            verified: user.length > 0 ? user[0].verified : false
        });
    } catch (error) {
        console.error("Status check error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


router.get('/verify-email/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Update user as verified in database
        await pool.query(
            'UPDATE users SET verified = true WHERE id = ?',
            [decoded.userId]
        );

        res.send(`
            <html>
                <head>
                    <title>Email Verified</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .success { color: #4CAF50; font-size: 24px; margin-bottom: 20px; }
                        .login-btn { 
                            background-color: #4CAF50; color: white; padding: 12px 20px; 
                            text-decoration: none; border-radius: 5px; display: inline-block;
                        }
                    </style>
                </head>
                <body>
                    <div class="success">✓ Email Verified Successfully!</div>
                    <p>Your account has been successfully verified.</p>
                    <a href="/login" class="login-btn">Proceed to Login</a>
                </body>
            </html>
        `);

    } catch (error) {
        console.error('Verification error:', error);
        res.status(400).send(`
            <html>
                <body>
                    <h2>Verification Failed</h2>
                    <p>${error.name === 'TokenExpiredError' ? 
                        'Verification link has expired. Please request a new one.' : 
                        'Invalid verification link.'}
                    </p>
                </body>
            </html>
        `);
    }
});

router.post("/api/users", passwordValidator, async (req, res) => {
    const startTime = Date.now();
    let responseSent = false;
    let connection;

    // Set timeout and cleanup handlers
    req.setTimeout(60000, () => {
        if (!responseSent) {
            responseSent = true;
            res.status(504).json({ error: "Request timeout" });
        }
    });

    // Handle client disconnection
    req.on('close', () => {
        if (!responseSent) {
            console.warn(`Client disconnected - Email: ${req.body?.email || 'unknown'}`);
            if (connection) {
                connection.release().catch(err => 
                    console.error('Connection release error:', err)
                );
            }
        }
    });

    try {
        const userData = req.body;
        console.log(`Starting registration for: ${userData.email}`);
        
        // Input validation
        if (!userData.email?.includes('@')) {
            return res.status(400).json({ error: "Invalid email format" });
        }

        // Password strength check
        const pwStrength = zxcvbn(userData.password);
        if (pwStrength.score < 3) {
            return res.status(400).json({
                error: "Password too weak",
                suggestions: pwStrength.feedback.suggestions,
                score: pwStrength.score
            });
        }

        // Database operations
        connection = await pool.getConnection();
        await connection.beginTransaction();

        // Check existing user with lock
        const [existing] = await connection.query(
            "SELECT 1 FROM users WHERE email = ? FOR UPDATE", 
            [userData.email]
        );

        if (existing.length > 0) {
            await connection.rollback();
            return res.status(409).json({ error: "Email already registered" });
        }

        // Hash password
        userData.password = await bcrypt.hash(userData.password, 10);
        userData.created_at = new Date();
        userData.verified = false; // Add verification status

        // Create user
        const [result] = await connection.query(
            "INSERT INTO users SET ?", 
            [userData]
        );

        // Generate verification token
        const verificationToken = jwt.sign(
            { userId: result.insertId },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Create verification link
        const verificationLink = `${req.protocol}://${req.get('host')}/verify-email/${verificationToken}`;

        // Send verification email
        const msg = {
            to: userData.email,
            from: process.env.SENDGRID_FROM_EMAIL,
            subject: 'Verify Your BloodLink Account',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #b30000;">Welcome to BloodLink!</h2>
                    <p>Please verify your email address to complete your registration.</p>
                    <a href="${verificationLink}" 
                       style="display: inline-block; padding: 12px 24px; background-color: #b30000; 
                              color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">
                        Verify Email
                    </a>
                    <p>Or copy this link to your browser:</p>
                    <p style="word-break: break-all;">${verificationLink}</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </div>
            `,
            text: `Please verify your email by visiting this link: ${verificationLink}`
        };

        await sgMail.send(msg);
        console.log(`Verification email sent to ${userData.email}`);

        await connection.commit();

        // Send response
        responseSent = true;
        res.status(201).json({
            success: true,
            message: "Account created! Please check your email to verify your account.",
            userId: result.insertId,
            email: userData.email,
            requiresVerification: true
        });

        console.log(`Registration completed in ${Date.now() - startTime}ms`);

    } catch (error) {
        if (connection) await connection.rollback();
        
        if (!responseSent) {
            console.error("Registration error:", error);
            
            // Handle SendGrid errors specifically
            if (error.response?.body?.errors) {
                console.error('SendGrid errors:', error.response.body.errors);
                res.status(500).json({ 
                    error: "Could not send verification email",
                    details: process.env.NODE_ENV === 'development' ? error.response.body.errors : undefined
                });
            } else {
                res.status(500).json({ 
                    error: "Registration failed",
                    details: process.env.NODE_ENV === 'development' ? error.message : undefined
                });
            }
        }
    } finally {
        if (connection) {
            try {
                await connection.release();
            } catch (err) {
                console.error('Error releasing connection:', err);
            }
        }
    }
});

router.post("/login", async (req, res) => {
    const { email, password } = req.body;
    console.log("📩 Login Request Received:", email);

    let connection;
    try {
        // 1. Get connection with pool status check
        if (!pool || pool._closed) {
            console.warn("⚠️ Pool closed - attempting to recreate");
            await initializePool(); // Your pool initialization function
        }

        connection = await pool.getConnection();

        // 2. Find user by email
        console.log("🔍 Querying user...");
        const [users] = await connection.query(
            "SELECT * FROM users WHERE email = ?", 
            [email]
        );
        
        const user = users[0];
        console.log("🔍 Retrieved User:", user);

        if (!user) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        // 3. Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        console.log("✅ Password Valid:", isPasswordValid);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        // 4. Generate JWT token
        const jwtToken = jwt.sign(
            { 
                id: user.id, 
                role: user.role,
                email: user.email
            },
            process.env.JWT_SECRET || 'mySuperSecretKey',
            { expiresIn: "24h" }
        );

        console.log("🔑 Generated Token:", jwtToken);

        // 5. Send successful response along with the token
        res.status(200).json({
            message: "Login successful!",
            id: user.id,
            role: user.role,
            token: jwtToken
        });

    } catch (error) {
        console.error("🚨 Login Error:", error);
        
        // Handle pool errors specifically
        if (error.message.includes('Pool is closed')) {
            await initializePool();
            return res.status(503).json({ 
                error: "Database reconnecting - please try again" 
            });
        }

        res.status(500).json({ 
            error: "Internal Server Error",
            details: error.message 
        });
    } finally {
        // 7. Always release connection
        if (connection) {
            console.log("🔗 Releasing connection");
            await connection.release();
        }
    }
});

router.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "../public/login.html")); 
});

// In your route handler
router.post('/change-password', async (req, res) => {
    try {
        const { userId, newPassword } = req.body;
        const success = await updatePassword(userId, newPassword);
        
        if (success) {
            res.json({ message: "Password updated successfully" });
        } else {
            res.status(404).json({ error: "User not found" });
        }
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

router.get('/profile/:id', verifyToken, enforcePasswordRotation, async (req, res) => {
    try {
      console.time('ProfileQueryTime');
      
      const [user] = await pool.query(`
        SELECT 
          u.id, u.name, u.email, u.phone, u.blood_type,
          u.location, u.role, u.age, u.weight, u.health_status,
          DATE_FORMAT(u.created_at, '%Y-%m-%d') as created_at,
          DATE_FORMAT(u.last_donation, '%Y-%m-%d') as last_donation,
          (
            SELECT 
              CASE 
                WHEN COUNT(disease) > 0 THEN JSON_ARRAYAGG(disease)
                ELSE JSON_ARRAY()
              END
            FROM user_diseases 
            WHERE user_id = u.id
          ) as diseases,
          (
            SELECT 
              CASE 
                WHEN COUNT(medication) > 0 THEN JSON_ARRAYAGG(medication)
                ELSE JSON_ARRAY()
              END
            FROM user_medications 
            WHERE user_id = u.id
          ) as medications,
          (
            SELECT JSON_OBJECT(
              'is_eligible', is_eligible,
              'reason', reason,
              'check_date', DATE_FORMAT(check_date, '%Y-%m-%d %H:%i')
            )
            FROM donoreligibility
            WHERE user_id = u.id
            ORDER BY check_date DESC
            LIMIT 1
          ) as eligibility
        FROM users u
        WHERE u.id = ?`, 
        [req.params.id]
      );
      
      console.timeEnd('ProfileQueryTime');
  
      if (!user.length) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      const profile = user[0];
      
      // Parse with safety checks
      profile.diseases = safeParseJSON(profile.diseases) || [];
      profile.medications = safeParseJSON(profile.medications) || [];
      profile.eligibility = safeParseJSON(profile.eligibility) || {
        is_eligible: false,
        reason: 'Not checked',
        check_date: null
      };
  
      res.json(profile);
      
    } catch (err) {
      console.error('Profile endpoint error:', err);
      res.status(500).json({ 
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? err.message : undefined
      });
    }
  });
  
  function safeParseJSON(value) {
    if (typeof value !== 'string') return value;
    try {
      return JSON.parse(value);
    } catch (e) {
      console.warn('Failed to parse JSON:', value);
      return null;
    }
  }

// Update notifications
router.put('/profile/:id/notifications', verifyToken, async (req, res) => {
    try {
        const updated = await userModel.updateNotifications(
            req.params.id, 
            req.body.enabled
        );
        res.json({ success: updated });
    } catch (error) {
        res.status(500).json({ error: "Failed to update notifications" });
    }
});

// Route to record a donation
router.post('/users/:userId/donate', verifyToken, isDonor, async (req, res) => {
    const userId = parseInt(req.params.userId, 10);
    const { donationDate, blood_type, quantity } = req.body;

    if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(400).send({ error: 'Invalid userId.' });
    }

    try {
        const donation = await new Promise((resolve, reject) => {
            userModel.recordDonation(userId, donationDate, blood_type, quantity, (err, result) => {
                if (err) reject(err);
                else resolve(result);
            });
        });

        res.status(201).send(donation);
    } catch (error) {
        console.error('Error recording donation:', error);
        res.status(500).send(error.message);
    }
});

// Route to get donation history for a user
router.get('/users/:userId/donations', verifyToken, isDonor, async (req, res) => {
    const userId = parseInt(req.params.userId, 10);
    console.log("📡 Fetching donations for user:", userId);

    try {
        const [donations] = await pool.query(`
            SELECT 
                d.donation_id,
                DATE_FORMAT(d.donation_date, '%Y-%m-%d') AS donation_date,
                d.blood_type,
                d.quantity,
                DATE_FORMAT(d.created_at, '%Y-%m-%d %H:%i:%s') AS created_at,
                b.name AS location_name
            FROM Donations d
            LEFT JOIN blood_banks b ON d.blood_bank_id = b.blood_bank_id
            WHERE d.user_id = ?
            ORDER BY d.donation_date DESC
        `, [userId]);

        console.log("✅ Fetched donations:", donations);
        res.status(200).json(donations);

    } catch (error) {
        console.error("🚨 Error fetching donation history:", error);
        res.status(500).json({ 
            error: "Internal Server Error",
            details: error.message 
        });
    }
});



router.post('/appointments/schedule', verifyToken, async (req, res) => {
    try {
        const { name, date, time, blood_bank_id, location_name, notes } = req.body;
        const appointmentDateTime = new Date(`${date}T${time}`);

        // Check availability
        const [existing] = await pool.query(
            `SELECT 1 FROM appointments 
             WHERE blood_bank_id = ?
             AND appointment_date BETWEEN ? AND ?
             AND status = 'scheduled'
             LIMIT 1`,
            [
                blood_bank_id,
                new Date(appointmentDateTime.getTime() - 30 * 60000),
                new Date(appointmentDateTime.getTime() + 30 * 60000)
            ]
        );

        if (existing.length > 0) {
            return res.status(400).json({ error: 'Time slot already booked' });
        }

        // Schedule appointment
        const [result] = await pool.query(
            `INSERT INTO appointments 
             (user_id, donor_name, appointment_date, blood_bank_id, location_name, notes, status)
             VALUES (?, ?, ?, ?, ?, ?, 'scheduled')`,
            [req.user.id, name, appointmentDateTime, blood_bank_id, location_name, notes]
        );

        res.status(201).json({
            success: true,
            appointment: {
                appointmentId: result.insertId,  // MySQL returns insertId
                date: req.body.date,
                time: req.body.time,
                blood_bank_id: req.body.blood_bank_id
            }
        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: error.message });
    }
});

router.post('/appointments/check-availability', verifyToken, async (req, res) => {
    try {
        const { date, time, blood_bank_id } = req.body;
        const appointmentDateTime = new Date(`${date}T${time}`);
        
        const [existing] = await pool.query(
            `SELECT 1 FROM appointments 
             WHERE blood_bank_id = ?
             AND appointment_date BETWEEN ? AND ?
             AND status NOT IN ('canceled', 'completed')
             LIMIT 1`,
            [
                blood_bank_id,
                new Date(appointmentDateTime.getTime() - 30 * 60000), // 30 mins before
                new Date(appointmentDateTime.getTime() + 30 * 60000)  // 30 mins after
            ]
        );

        res.json({ available: existing.length === 0 });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.get('/appointments/user/:userId', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        
        // Verify the requesting user matches the userId
        if (req.user.id !== parseInt(userId)) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();

            // 1. First, find appointments that need to be marked as completed
            const [pastAppointments] = await connection.query(
                `SELECT appointment_id, user_id, appointment_date, blood_bank_id
                 FROM appointments
                 WHERE user_id = ?
                 AND status = 'scheduled'
                 AND appointment_date < NOW()`,
                [userId]
            );

            // 2. Process each past appointment
            for (const appointment of pastAppointments) {
                // Mark appointment as completed
                await connection.query(
                    `UPDATE appointments
                     SET status = 'completed'
                     WHERE appointment_id = ?`,
                    [appointment.appointment_id]
                );

                // Get user's blood type
                const [user] = await connection.query(
                    `SELECT blood_type FROM users WHERE id = ?`,
                    [appointment.user_id]
                );

                // Create donation record (standard 450ml donation)
                await connection.query(
                    `INSERT INTO Donations 
                     (user_id, donation_date, blood_type, quantity, blood_bank_id)
                     VALUES (?, ?, ?, 450, ?)`,
                    [
                        appointment.user_id,
                        appointment.appointment_date,
                        user[0].blood_type,
                        appointment.blood_bank_id
                    ]
                );

                // Update user's last donation date
                await connection.query(
                    `UPDATE Users SET last_donation = ? WHERE id = ?`,
                    [appointment.appointment_date, appointment.user_id]
                );
            }

            // 3. Now fetch all appointments (including newly completed ones)
            const [appointments] = await connection.query(
                `SELECT 
                    appointment_id,
                    donor_name,
                    blood_bank_id,
                    location_name,
                    appointment_date,
                    status,
                    notes
                 FROM appointments
                 WHERE user_id = ?
                 ORDER BY appointment_date ASC`,
                [userId]
            );

            await connection.commit();
            res.json(appointments);
            
        } catch (error) {
            await connection.rollback();
            console.error('Error in appointment processing:', error);
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

router.post('/appointments/:id/cancel', verifyToken, async (req, res) => {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        
        // First mark as cancelled
        await connection.query(
            `UPDATE appointments 
             SET status = 'canceled' 
             WHERE appointment_id = ?`,
            [req.params.id]
        );
        // Optional: Send notification about slot availability
        await notifySlotAvailable(req.params.id);
        
        await connection.commit();
        res.json({ success: true });
        
    } catch (error) {
        await connection.rollback();
        res.status(500).json({ error: error.message });
    } finally {
        connection.release();
    }
});
        
        // Optional: Send notification about slot availability
        async function notifySlotAvailable(appointmentId) {
            const [appointment] = await pool.query(
                `SELECT blood_bank_id, appointment_date 
                 FROM appointments 
                 WHERE appointment_id = ?`,
                [appointmentId]
            );
        
            if (appointment.length) {
                console.log(`✅ Slot available at blood_bank_id ${appointment[0].blood_bank_id} for ${appointment[0].appointment_date}`);
            }
        }

// Get all hospitals with pagination
router.get('/hospitals', verifyToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const hospitals = await getAllHospitals(parseInt(page), parseInt(limit));

        res.json({
            success: true,
            data: hospitals,
            pagination: {
                total: hospitals.length,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(hospitals.length / limit)
            }
        });

    } catch (error) {
        console.error("GET /hospitals error:", error);
        res.status(500).json({ 
            success: false,
            error: "Internal server error",
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get specific hospital with caching
router.get('/hospitals/:id', verifyToken, async (req, res) => {
    try {
        const hospital = await getHospitalById(req.params.id);
        
        res.json({
            success: true,
            data: hospital
        });

    } catch (error) {
        if (error.message === 'INVALID_HOSPITAL_ID') {
            return res.status(400).json({ 
                success: false,
                error: "Invalid hospital ID format" 
            });
        }
        
        if (error.message === 'HOSPITAL_NOT_FOUND') {
            return res.status(404).json({ 
                success: false,
                error: "Hospital not found" 
            });
        }
        
        console.error(`GET /hospitals/${req.params.id} error:`, error);
        res.status(500).json({
            success: false,
            error: "Internal server error",
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

const { getAllBloodBanks } = require('../models/userModel');

router.get('/blood-banks', async (req, res) => {
    try {
        const banks = await getAllBloodBanks();
        res.json({ success: true, data: banks });
    } catch (error) {
        console.error("GET /blood-banks error:", error);
        res.status(500).json({
            success: false,
            error: "Internal server error",
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

router.get('/blood-banks/:id', async (req, res) => {
    const { id } = req.params;
    try {
      const [result] = await pool.query('SELECT * FROM blood_banks WHERE blood_bank_id = ?', [id]);
      if (!result.length) return res.status(404).json({ error: 'Not found' });
      res.json(result[0]);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
  


// Route for email verification
router.get('/verify-email/:userId', async (req, res) => {
    const userId = req.params.userId;

    userModel.verifyUserEmail(userId, (err) => {
        if (err) {
            console.error('Error verifying email:', err);
            return res.status(500).send('Error verifying email.');
        }
        res.send('Email verified successfully! You can now log in.');
    });
});

// Route to request a password reset link
router.post('/request-password-reset', async (req, res) => {
    const { email } = req.body;
    userModel.sendPasswordResetEmail(email, (err) => {
        if (err) return res.status(400).send(err.message);
        res.status(200).send('Password reset link sent to your email.');
    });
});

// Route to update the password
router.post("/api/reset-password", async (req, res) => {
    const { userId, token, newPassword } = req.body;
    console.log("🔄 Password reset request received for user:", userId);

    try {
        // Validate the token
        const secret = process.env.JWT_SECRET || "your-secret-key";
        const decoded = jwt.verify(token, secret);

        if (decoded.userId !== parseInt(userId)) {
            console.log("❌ Token does not match user ID.");
            return res.status(400).json({ error: "Invalid token or user ID." });
        }

        // Update the password using async/await
        const result = await userModel.updatePassword(userId, newPassword);
        
        if (result) {
            console.log("✅ Password reset successful!");
            return res.status(200).json({ 
                success: true,
                message: "Password reset successfully" 
            });
        } else {
            return res.status(500).json({ error: "Failed to reset password." });
        }

    } catch (error) {
        console.error("🚨 Error in password reset:", error);
        
        if (error.name === 'TokenExpiredError') {
            return res.status(400).json({ error: "Token expired. Please request a new reset link." });
        }
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(400).json({ error: "Invalid token." });
        }
        
        return res.status(500).json({ 
            error: error.message || "Failed to reset password." 
        });
    }
});

// Serve password reset form
router.get("/reset-password/:userId", async (req, res) => {
    console.log(`📩 Password reset request received for userId: ${req.params.userId}`);

    res.sendFile(path.join(__dirname, "../public/reset-password.html"), (err) => {
        if (err) {
            console.error("🚨 Error sending reset-password.html:", err);
            res.status(err.status || 500).end();
        }
    });
});


// Serve request password reset form
router.post("/api/request-password-reset", async (req, res) => {
    const { email } = req.body;
    console.log("📩 Password reset request received for:", email);

    try {
        // Step 1: Check if user exists
        const user = await userModel.findUserByEmail(email);
        if (!user) {
            console.log("❌ User not found:", email);
            return res.status(404).json({ error: "User not found" });
        }

        // Step 2: Generate reset token
        console.log("🔑 Generating reset token...");
        const token = userModel.generateResetToken(user.id);
        if (!token) {
            console.error("🚨 Failed to generate token!");
            return res.status(500).json({ error: "Error generating reset token." });
        }
        console.log("✅ Token generated:", token);

        // Step 3: Create reset link
        const resetLink = `http://localhost:5500/reset-password.html?userId=${user.id}&token=${token}`;
        console.log("🔗 Reset link:", resetLink);

        // Step 4: Send reset email
        console.log("📧 Sending email...");
        const emailSent = await userModel.sendEmail(user.email, "Password Reset", `Click here to reset your password: ${resetLink}`);

        if (!emailSent) {
            console.error("🚨 Failed to send email.");
            return res.status(500).json({ error: "Error sending reset email." });
        }

        console.log("✅ Password reset email sent successfully to:", user.email);
        return res.status(200).json({ message: "Reset link sent to your email." });

    } catch (error) {
        console.error("🚨 Error in password reset:", error);
        return res.status(500).json({ error: "Failed to send reset link." });
    }
});

/*** ROUTES FOR MANAGE DONOR NOTIFICATIONS (UC-6) ***/

const notificationsRouter = express.Router();

notificationsRouter.get('/:id', verifyToken, isDonor, async (req, res) => {
    try {
        if (req.params.id !== req.donor.id.toString()) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        const notifications = await userModel.getDonorNotifications(req.params.id);
        res.json(notifications);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

notificationsRouter.post('/:id/update', verifyToken, isDonor, async (req, res) => {
    try {
        if (req.params.id !== req.donor.id.toString()) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        const result = await userModel.updateDonorNotifications(
            req.params.id,
            req.body.email,
            req.body.sms,
            req.body.urgentAlerts
        );
        res.json({ message: 'Preferences updated', result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// Register Routes
router.use('/inventory', inventoryRouter);
router.use('/donor/notifications', notificationsRouter);

// In userRoutes.js
const { checkEligibility } = require('../models/userModel');

// Single consolidated eligibility route
router.post('/profile/:id/eligibility', verifyToken, isDonor, async (req, res) => {
    try {
        const userId = req.params.id;
        const { age, weight, healthStatus, lastDonationDate, diseases, medications } = req.body;

        // Eligibility checking function
        function checkEligibility(data) {
            const { age, weight, healthStatus, lastDonationDate, diseases, medications } = data;

            const MIN_AGE = 18;
            const MAX_AGE = 65;
            const MIN_WEIGHT = 50;
            const DONATION_FREQUENCY = 56;
            const DISQUALIFYING_DISEASES = ['HIV', 'Hepatitis B', 'Hepatitis C', 'Malaria', 'Heart Disease'];
            const DISQUALIFYING_MEDICATIONS = ['Blood thinners', 'Immunosuppressants', 'Chemotherapy Drugs'];

            // Check each criteria
            const criteria = {
                age: age >= MIN_AGE && age <= MAX_AGE,
                weight: weight >= MIN_WEIGHT,
                healthStatus: healthStatus === 'good',
                diseases: !diseases.some(d => DISQUALIFYING_DISEASES.includes(d)),
                medications: !medications.some(m => DISQUALIFYING_MEDICATIONS.includes(m))
            };

            // Calculate days since last donation
            const today = new Date();
            const lastDonation = new Date(lastDonationDate);
            const daysSinceLastDonation = Math.floor((today - lastDonation) / (1000 * 60 * 60 * 24));
            criteria.donationFrequency = daysSinceLastDonation >= DONATION_FREQUENCY;

            // Check overall eligibility
            const eligible = Object.values(criteria).every(c => c);

            // Generate detailed reason if not eligible
            let reason = "You are eligible to donate blood!";
            if (!eligible) {
                const reasons = [];
                if (!criteria.age) reasons.push(age < MIN_AGE ? "Too young (minimum 18)" : "Too old (maximum 65)");
                if (!criteria.weight) reasons.push("Under minimum weight (50kg)");
                if (!criteria.healthStatus) reasons.push("Health status not good");
                if (!criteria.diseases) reasons.push("Has disqualifying diseases");
                if (!criteria.medications) reasons.push("Taking disqualifying medications");
                if (!criteria.donationFrequency) reasons.push(`Only ${daysSinceLastDonation} days since last donation (need 56)`);
                
                reason = `Not eligible: ${reasons.join(", ")}`;
            }

            return { 
                eligible,
                message: reason,
                criteria: {
                    age: { required: "18-65 years", actual: age, met: criteria.age },
                    weight: { required: "≥50 kg", actual: weight, met: criteria.weight },
                    healthStatus: { required: "Good", actual: healthStatus, met: criteria.healthStatus },
                    lastDonation: { required: "≥56 days", actual: `${daysSinceLastDonation} days`, met: criteria.donationFrequency },
                    diseases: { required: "None", actual: diseases.length > 0 ? diseases.join(", ") : "None", met: criteria.diseases },
                    medications: { required: "None", actual: medications.length > 0 ? medications.join(", ") : "None", met: criteria.medications }
                }
            };
        }

        // Update user's medical info
        await pool.query(
            `UPDATE users SET 
                age = ?, 
                weight = ?, 
                health_status = ?,
                last_donation = ? 
             WHERE id = ?`,
            [age, weight, healthStatus, lastDonationDate || null, userId]
        );

        // Insert or update diseases in user_diseases table
        for (const disease of diseases) {
            await pool.query(
                `INSERT INTO user_diseases (user_id, disease) 
                 VALUES (?, ?) 
                 ON DUPLICATE KEY UPDATE disease = ?`,
                [userId, disease, disease]
            );
        }

        // Insert or update medications in user_medications table
        for (const medication of medications) {
            await pool.query(
                `INSERT INTO user_medications (user_id, medication) 
                 VALUES (?, ?) 
                 ON DUPLICATE KEY UPDATE medication = ?`,
                [userId, medication, medication]
            );
        }

        // Check eligibility using the checkEligibility function
        const eligibilityResult = checkEligibility({
            age,
            weight,
            healthStatus,
            lastDonationDate,
            diseases,
            medications
        });

        // Save to donoreligibility table
        const [result] = await pool.query(
            `INSERT INTO donoreligibility 
                (user_id, is_eligible, reason, criteria_met) 
             VALUES (?, ?, ?, ?)`,
            [
                userId,
                eligibilityResult.eligible,
                eligibilityResult.message,
                JSON.stringify(eligibilityResult.criteria)
            ]
        );

        // Send eligibility response
        res.json({
            is_eligible: eligibilityResult.eligible,
            reason: eligibilityResult.message,
            criteria: eligibilityResult.criteria
        });

    } catch (error) {
        console.error("Error saving eligibility:", error);
        res.status(500).json({ 
            error: "Failed to save eligibility information",
            details: error.message 
        });
    }
});



router.get("/ping", (req, res) => {
    res.send("✅ Server is running fast!");
});

router.get('/debug/slot-availability', async (req, res) => {
    const { locationId, date, time } = req.query;
    const datetime = new Date(`${date}T${time}`);
    
    const [conflicts] = await pool.query(
        `SELECT * FROM appointments 
         WHERE location_id = ?
         AND appointment_date BETWEEN ? AND ?
         ORDER BY appointment_date`,
        [
            locationId,
            new Date(datetime.getTime() - 30 * 60000),
            new Date(datetime.getTime() + 30 * 60000)
        ]
    );
    
    res.json({
        requestedTime: datetime,
        searchWindow: [
            new Date(datetime.getTime() - 30 * 60000),
            new Date(datetime.getTime() + 30 * 60000)
        ],
        conflicts: conflicts
    });
});


module.exports = router;