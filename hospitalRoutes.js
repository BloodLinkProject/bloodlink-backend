const express = require('express');
require('dotenv').config();
const router = express.Router();
const jwt = require('jsonwebtoken');
const pool = require("../db");
const userModel = require('../models/userModel');
const { verifyToken, isHospital, authConfig } = require('../authMiddleware');
const bcrypt = require('bcrypt');


router.post('/hospital/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [rows] = await pool.query("SELECT * FROM HospitalAccounts WHERE email = ?", [email]);

        if (rows.length === 0) return res.status(404).json({ error: "Hospital account not found." });

        const hospitalAccount = rows[0];
        const valid = await bcrypt.compare(password, hospitalAccount.password_hash);

        if (!valid) return res.status(401).json({ error: "Invalid credentials." });

        const token = jwt.sign(
            { id: hospitalAccount.id, role: 'hospital', hospital_id: hospitalAccount.hospital_id },
            process.env.JWT_SECRET,
            { expiresIn: '2h' }
        );

        res.json({ token, hospitalId: hospitalAccount.hospital_id });
    } catch (err) {
        console.error("Hospital login error:", err);
        res.status(500).json({ error: "Login failed." });
    }
});

  
  
  // GET /hospital/profile
router.get('/hospital/profile', verifyToken, isHospital, async (req, res) => {
    try {
        const [results] = await pool.query(
            "SELECT H.name, H.location, H.address, A.email FROM Hospitals H JOIN HospitalAccounts A ON H.hospital_id = A.hospital_id WHERE A.id = ?",
            [req.user.id]
        );

        if (results.length === 0) return res.status(404).json({ error: "Hospital not found." });

        res.json(results[0]);
    } catch (err) {
        console.error("Failed to fetch hospital profile:", err);
        res.status(500).json({ error: "Could not load profile." });
    }
});


router.get('/hospital/requests', verifyToken, isHospital, async (req, res) => {
    try {
        const hospitalId = req.user.hospital_id;
        const [requests] = await pool.query(
            "SELECT * FROM donationrequests WHERE hospital_id = ? ORDER BY request_date DESC",
            [hospitalId]
        );

        res.json({ success: true, requests });
    } catch (error) {
        console.error("Error fetching hospital requests:", error);
        res.status(500).json({ error: "Failed to fetch requests." });
    }
});

router.post('/hospital/send-request', verifyToken, isHospital, async (req, res) => {
    const { bloodType, quantity, isUrgent } = req.body;
    const hospitalId = req.user.hospital_id;
  
    if (!bloodType || !quantity) {
      return res.status(400).json({ error: "Missing required fields." });
    }
  
    try {
      // Insert donation request
      await pool.query(
        `INSERT INTO donationrequests 
         (user_id, blood_type, quantity, is_urgent, request_date, status, hospital_id)
         VALUES (?, ?, ?, ?, NOW(), 'pending', ?)`,
        [0, bloodType, quantity, isUrgent ? 1 : 0, hospitalId]
      );
  
      // ✅ Fetch full hospital details (put this here!)
      const [hospitalDetails] = await pool.query(
        "SELECT name, location, address,  latitude, longitude FROM Hospitals WHERE hospital_id = ?",
        [hospitalId]
      );
  
      const hospital = hospitalDetails[0];
      const googleMapsLink = `https://www.google.com/maps?q=${hospital.latitude},${hospital.longitude}`;

  
      // ✅ Send email to admin
      await sgMail.send({
        to: 'suppbloodlink@gmail.com',
        from: 'suppbloodlink@gmail.com',
        subject: `🚨 New Blood Request from ${hospital.name}`,
        html: `
          <h3>🩺 ${hospital.name}</h3>
          <p><strong>Location:</strong> ${hospital.location}</p>
          <p><strong>Address:</strong> ${hospital.address}</p>
          <p><strong>Blood Type:</strong> ${bloodType}</p>
          <p><strong>Quantity:</strong> ${quantity} units</p>
          <p><strong>Urgent:</strong> ${isUrgent ? 'Yes' : 'No'}</p>
          <p><strong>Map Location:</strong> <a href="${googleMapsLink}" target="_blank">View on Google Maps</a></p>
          <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
        `
      });
  
      res.status(201).json({ message: "Request submitted and admin notified." });
  
    } catch (error) {
      console.error("Error sending hospital request:", error);
      res.status(500).json({ error: "Failed to process hospital request." });
    }
  });
  
  

module.exports = router;