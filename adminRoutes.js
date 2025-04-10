const express = require('express');
require('dotenv').config();
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require("../db");
const userModel = require('../models/userModel');
const { sendDonationReminder } = require("../services/notificationServices");
const { verifyToken, isAdmin, authConfig } = require('../authMiddleware');


// Admin login endpoint with server-side validation
// In your adminRoutes.js
router.post('/admin/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (typeof password !== 'string' || password.length < 1) {
        return res.status(400).json({ error: "Invalid password format" });
    }

    try {
        // 1. Find admin
        const [admins] = await pool.query(
            'SELECT * FROM admins WHERE email = ?', 
            [email]
        );

        if (admins.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const admin = admins[0];
        
        // 2. Verify hash format
        if (!admin.password_hash.startsWith('$2a$') && !admin.password_hash.startsWith('$2b$')) {
            console.error('Invalid hash format for:', email);
            return res.status(500).json({ error: "System error" });
        }

        // 3. Debug output
        console.log('Comparison details:', {
            inputPassword: password,
            inputLength: password.length,
            storedHashPrefix: admin.password_hash.substring(0, 10),
            storedHashLength: admin.password_hash.length
        });

        // 4. Verify password
        const passwordValid = await bcrypt.compare(password, admin.password_hash);
        
        if (!passwordValid) {
            // Test with known good password if in development
            if (process.env.NODE_ENV === 'development') {
                const testHash = await bcrypt.hash('SuperAdmin123', 10);
                const testCompare = await bcrypt.compare('SuperAdmin123', testHash);
                console.log('Dev test comparison:', testCompare);
            }
            
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // 4. Generate JWT token
        const token = jwt.sign(
            {
                id: admin.id,
                email: admin.email,
                role: admin.role,
                isSuperadmin: admin.is_superadmin
            },
            process.env.JWT_SECRET || 'mySuperSecretKey',
            { expiresIn: '8h' }
        );

        res.json({
            token,
            admin: {
                id: admin.id,
                name: admin.name,
                email: admin.email,
                role: admin.role,
                isSuperadmin: admin.is_superadmin
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Helper function to validate date format
function isValidDate(dateString) {
    const regEx = /^\d{4}-\d{2}-\d{2}$/;
    return dateString.match(regEx) !== null;
}

// Blood inventory management routes
router.get('/inventory', verifyToken, isAdmin, async (req, res) => {
    try {
        const results = await userModel.getInventory();
        res.status(200).json(results);
    } catch (error) {
        console.error("Error fetching inventory:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

router.post('/inventory/update', verifyToken, isAdmin, async (req, res) => {
    try {
        const { bloodType, quantity, expiration } = req.body;

        if (!bloodType || quantity === undefined) {
            return res.status(400).json({ error: "Blood type and quantity are required." });
        }

        await userModel.updateInventory(bloodType, quantity, expiration);
        res.status(200).json({ message: "Inventory updated successfully!" });

    } catch (error) {
        console.error("Error updating inventory:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

router.delete('/inventory/:id', verifyToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await userModel.deleteInventory(id);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "No record found to delete." });
        }
        res.status(200).json({ message: "Blood supply deleted successfully." });
    } catch (error) {
        console.error("Error deleting blood supply:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Add this route to adminRoutes.js
router.get('/inventory/expiring', verifyToken, isAdmin, async (req, res) => {
    try {
        const [inventory] = await pool.query(`
            SELECT * FROM inventory 
            WHERE expiration_date BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 7 DAY)
            ORDER BY expiration_date ASC
        `);

        console.log("Fetched expiring inventory:", inventory);  // Log fetched inventory

        if (inventory.length === 0) {
            return res.status(404).json({ message: "No expiring inventory found." });  // Return a message if no items found
        }

        res.json(inventory);
    } catch (error) {
        console.error("Error fetching expiring inventory:", error);
        res.status(500).json({ error: "Failed to fetch expiring inventory" });
    }
});


// Donor eligibility management
router.get('/donors/eligibility', verifyToken, isAdmin, async (req, res) => {
    try {
        const [donors] = await pool.query(`
            SELECT u.id, u.name, u.age, u.weight, e.is_eligible, e.reason,
                   GROUP_CONCAT(d.disease) AS diseases,
                   GROUP_CONCAT(m.medication) AS medications
            FROM users u
            JOIN donoreligibility e ON u.id = e.user_id
            LEFT JOIN user_diseases d ON u.id = d.user_id
            LEFT JOIN user_medications m ON u.id = m.user_id
            GROUP BY u.id, e.is_eligible, e.reason
        `);

        res.json(donors);
    } catch (error) {
        console.error("Error fetching donor eligibility:", error);
        res.status(500).json({ error: "Failed to retrieve donor eligibility data." });
    }
});

router.post('/reports/generate', verifyToken, isAdmin, async (req, res) => {
    const { reportType, startDate, endDate } = req.body;

    // Validate inputs
    if (!reportType || !startDate || !endDate) {
        return res.status(400).json({ error: "❌ Invalid report parameters. Please select all fields." });
    }

    // Validate date format
    if (!isValidDate(startDate) || !isValidDate(endDate)) {
        return res.status(400).json({ error: "❌ Invalid date format. Use YYYY-MM-DD." });
    }

    try {
        const reportData = await userModel.generateReport(reportType, startDate, endDate);

        if (!reportData || reportData.length === 0) {
            return res.status(404).json({ message: "No data found for the selected parameters." });
        }

        res.status(200).json(reportData);
    } catch (error) {
        console.error("🚨 Error generating report:", error);
        res.status(500).json({ error: "❌ Server error while generating report. Please try again." });
    }
});

router.post('/donation/request', verifyToken, isAdmin, async (req, res) => {
    const { bloodType, quantity, isUrgent, hospitalId } = req.body;

    if (!bloodType || !quantity || !hospitalId) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    try {
        const [hospitalResult] = await pool.query(
            "SELECT * FROM hospitals WHERE hospital_id = ?", 
            [hospitalId]
        );
        const hospital = hospitalResult[0];

        if (!hospital) {
            return res.status(404).json({ error: "Hospital not found." });
        }

        // ✅ Insert donation request and get inserted ID
        const [result] = await pool.query(
            `INSERT INTO donationrequests 
                (user_id, blood_type, quantity, is_urgent, request_date, status, hospital_id) 
             VALUES (?, ?, ?, ?, NOW(), 'pending', ?)`,
            [req.user.id, bloodType, quantity, isUrgent ? 1 : 0, hospitalId]
        );

        const requestId = result.insertId;
        const donors = await userModel.findEligibleDonors(bloodType);

        if (donors.length === 0) {
            return res.status(200).json({ 
                message: "No eligible donors found.", 
                notified: [] 
            });
        }

        const sentTo = [];

        for (const donor of donors) {
            const success = await userModel.sendUrgentNotification(
                req.user.id,
                donor.email,
                donor.phone,
                bloodType,
                quantity,
                hospital
            );

            if (success) {
                sentTo.push({ email: donor.email, phone: donor.phone });
            }
        }

        // ✅ Update status to 'notified' and mark as 'sent' only if notifications went out
        await pool.query(
            "UPDATE donationrequests SET notification_status = 'sent', status = 'notified' WHERE id = ?",
            [requestId]
        );

        res.status(201).json({
            message: "Urgent donation request sent successfully!",
            notified: sentTo
        });

    } catch (error) {
        console.error("Error processing urgent request:", error);
        res.status(500).json({ error: "Failed to process urgent request." });
    }
});


router.get('/admin/hospital-requests', verifyToken, isAdmin, async (req, res) => {
    try {
      const [requests] = await pool.query(`
        SELECT R.*, H.name AS hospital_name, H.location 
        FROM donationrequests R
        JOIN hospitals H ON R.hospital_id = H.hospital_id
        WHERE R.status = 'pending'
        ORDER BY R.request_date DESC
      `);
  
      res.json({ success: true, requests });
    } catch (error) {
      console.error("Error loading hospital requests:", error);
      res.status(500).json({ error: "Failed to fetch hospital requests." });
    }
  });  

// Hospital management
router.get('/hospitals', verifyToken, async (req, res) => {
    console.log("✅ Calling getAllHospitals...");
    try {
        const hospitals = await userModel.getAllHospitals();
        if (!hospitals || hospitals.length === 0) {
            return res.status(404).json({ message: "No hospitals found" });
        }
        res.json(hospitals);
    } catch (error) {
        console.error("GET /hospitals error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

router.get('/hospitals/:id', verifyToken, async (req, res) => {
    try {
        const hospital = await userModel.getHospitalById(req.params.id);
        if (!hospital) {
            return res.status(404).json({ message: "Hospital not found" });
        }
        res.json(hospital);
    } catch (error) {
        console.error(`GET /hospitals/${req.params.id} error:`, error);
        res.status(500).json({ error: "Internal server error" });
    }
});

router.get('/blood-supply', verifyToken, isAdmin, async (req, res) => {
    try {
      const [inventory] = await pool.query(`
        SELECT * FROM inventory 
        ORDER BY expiration_date ASC
      `);
      res.status(200).json(inventory);
    } catch (error) {
      console.error("Error fetching inventory:", error);
      res.status(500).json({ 
        error: "Internal server error",
        details: error.message 
      });
    }
  });

  router.post('/blood-supply', verifyToken, isAdmin, async (req, res) => {
    const { type, quantity, expiration } = req.body;

    if (!type || quantity == null || !expiration) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    try {
        await userModel.addInventory(type, quantity, expiration);
        res.status(201).json({ message: "Blood supply added successfully!" });
    } catch (error) {
        console.error("Error adding blood supply:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});


  router.put('/blood-supply/:id', verifyToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { type, quantity, expiration } = req.body;
    
    try {
        await userModel.updateInventory(type, quantity, expiration, id);
        res.status(200).json({ message: "Blood supply updated successfully!" });
    } catch (error) {
        console.error("Error updating blood supply:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});



// DELETE needs to be a separate route since it has a parameter
router.delete("/blood-supply/:id", verifyToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await userModel.deleteInventory(id);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "No record found to delete." });
        }
        res.status(200).json({ message: "Blood supply deleted successfully." });
    } catch (error) {
        console.error("Error deleting blood supply:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

async function sendEmail(to, subject, text) {
  try {
    const msg = {
      to,
      from: process.env.SENDGRID_FROM_EMAIL,
      subject,
      text
    };
    await sgMail.send(msg);
    console.log("✅ Email sent to", to);
    return true;
  } catch (error) {
    console.error("🚨 Send error:", error.response?.body || error.message);
    throw new Error('Failed to send email');
  }
}


router.post('/send-email', verifyToken, isAdmin, async (req, res) => {
    const { to, subject, text } = req.body;
  
    try {
      // Lookup the user by email
      const [users] = await pool.query("SELECT id FROM users WHERE email = ?", [to]);
      if (users.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      const userId = users[0].id;
  
      // Send the email
      await sendEmail(to, subject, text);
  
      // Log the notification
      await pool.query(
        `INSERT INTO notifications (user_id, message) VALUES (?, ?)`,
        [userId, text]
      );
  
      res.status(200).json({ success: true });
    } catch (error) {
      console.error("🚨 Send error:", error);
      res.status(500).json({ error: "Failed to send email" });
    }
  });
  
  

  router.get('/notifications-logs', verifyToken, isAdmin, async (req, res) => {
    try {
      const [logs] = await pool.query(`
        SELECT user_id, message, sent_at
        FROM notifications
        ORDER BY sent_at DESC
      `);
  
      res.json(logs);
    } catch (error) {
      console.error("🚨 Error fetching notifications:", error);
      res.status(500).json({ error: "Failed to load logs" });
    }
  });
  
  


module.exports = router;
