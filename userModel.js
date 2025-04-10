const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const sgMail = require("@sendgrid/mail");

// Create a pool of connections to the database
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root', 
    password: process.env.DB_PASSWORD || 'BloodLink123', 
    database: process.env.DB_NAME || 'bloodlink123', 
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

// Set API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Function to find a user by email
async function findUserByEmail(email) {
    try {
        console.log("🔍 Searching for user with email:", email); // ✅ Debugging
        const [rows] = await pool.query("SELECT * FROM Users WHERE email = ?", [email]);  // ✅ No need for `.promise()`
        console.log("📜 Query Result:", rows); // ✅ Debugging - shows what MySQL returns

        return rows.length > 0 ? rows[0] : null;
    } catch (error) {
        console.error("🚨 Database Query Error:", error);
        return null; // ✅ Prevents crashes
    }
}

// Helper function to validate date format
function isValidDate(dateString) {
    const regEx = /^\d{4}-\d{2}-\d{2}$/;
    return dateString.match(regEx) !== null;
}


// Test function for findUserByEmail
async function testFindUser(email) {
    try {
        const user = await findUserByEmail(email);
        console.log("🔍 Test - Retrieved User:", user);
    } catch (error) {
        console.error("🚨 Error in testFindUser:", error);
    }
}

testFindUser("tarajohnsonx101@gmail.com");
async function createUser(userData) {
    const { name, email, password, phone, blood_type, location, role, gender } = userData;
    
    try {
        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();
            
            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);
            
            // Insert user including gender
            const [result] = await connection.query(
                `INSERT INTO Users 
                 (name, email, password, phone, blood_type, location, role, gender) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [name, email, hashedPassword, phone, blood_type, location, role, gender]
            );
            
            await connection.commit();
            return { 
                id: result.insertId, 
                name, phone, email, blood_type, location, role, gender
            };
            
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error("Error in createUser:", error);
        throw error;
    }
}


async function getAllBloodBanks() {
    const query = `
        SELECT 
            blood_bank_id,
            name,
            location,
            address,
            contact_info,
            operating_hours,
            latitude,
            longitude
        FROM blood_banks
        ORDER BY name ASC
    `;
    const [rows] = await pool.query(query);
    return rows;
}


async function updatePassword(userId, newPassword) {
    try {
        // 1. Check if password was used before
        if (await isPasswordUsedBefore(userId, newPassword)) {
            throw new Error("Cannot reuse one of your last 5 passwords");
        }

        // 2. Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 12);

        // 3. Update password in database
        const [result] = await pool.query(
            `UPDATE users SET 
             password = ?,
             password_changed_at = NOW()
             WHERE id = ?`,
            [hashedPassword, userId]
        );

        // 4. Add to password history
        await pool.query(
            `INSERT INTO password_history (user_id, password_hash)
             VALUES (?, ?)`,
            [userId, hashedPassword]
        );

        return result.affectedRows > 0;
    } catch (error) {
        console.error("Password update failed:", error);
        throw error;
    }
}

const loginAdmin = async (email, password) => {
    try {
        // 1. Find admin by email
        const [adminRows] = await pool.query(
            'SELECT * FROM admins WHERE email = ?', 
            [email]
        );

        if (adminRows.length === 0) {
            throw new Error('Admin not found');
        }

        const admin = adminRows[0];

        // 2. Verify password - handle both hashed and legacy plain text
        let passwordValid;
        if (admin.password_hash.startsWith('$2b$')) {
            // Bcrypt hashed password
            passwordValid = await bcrypt.compare(password, admin.password_hash);
        } else {
            // Legacy plain text (temporary during migration)
            passwordValid = (password === admin.password_hash);
            
            // Auto-upgrade to hashed password if using legacy
            if (passwordValid) {
                const hashed = await bcrypt.hash(password, 10);
                await pool.query(
                    'UPDATE admins SET password_hash = ? WHERE id = ?',
                    [hashed, admin.id]
                );
            }
        }

        if (!passwordValid) {
            throw new Error('Invalid credentials');
        }

        // 3. Generate token and return admin data
        const token = jwt.sign(
            { id: admin.id, role: admin.role, isSuperadmin: admin.is_superadmin },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        return { 
            token,
            admin: {
                id: admin.id,
                name: admin.name,
                email: admin.email,
                role: admin.role,
                isSuperadmin: admin.is_superadmin
            }
        };

    } catch (error) {
        console.error('Login error:', error);
        throw error;
    }
};

async function scheduleAppointment(appointmentData) {
    const { userId, date, time, locationId, locationName, notes } = appointmentData;
    const appointmentDateTime = new Date(`${date}T${time}`);
    
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();

        // Check for existing non-canceled appointments on this date
        const [existing] = await connection.query(
            `SELECT 1 FROM appointments 
             WHERE user_id = ?
             AND appointment_date_date = DATE(?)
             AND status != 'canceled'
             LIMIT 1`,
            [userId, appointmentDateTime]
        );

        if (existing.length > 0) {
            throw new Error('You already have an active appointment on this date');
        }

        // Insert new appointment
        const [result] = await connection.query(
            `INSERT INTO appointments 
             (user_id, donor_name, appointment_date, appointment_date_date, 
              location_id, location_name, notes, status)
             VALUES (?, ?, ?, DATE(?), ?, ?, ?, 'scheduled')`,
            [userId, appointmentData.name, appointmentDateTime, appointmentDateTime, 
             locationId, locationName, notes]
        );

        await connection.commit();
        return result;

    } catch (error) {
        await connection.rollback();
        
        // Handle duplicate entry error specifically
        if (error.code === 'ER_DUP_ENTRY') {
            throw new Error('Appointment scheduling conflict. Please choose another date.');
        }
        throw error;
    } finally {
        connection.release();
    }
}

async function activateUser(userId) {
    // Check if the user exists and is not already verified
    const query = 'SELECT * FROM users WHERE id = ?';
    const user = await db.query(query, [userId]);

    if (user && user.length > 0) {
        const userRecord = user[0];

        // Check if the user is already verified
        if (userRecord.isVerified) {
            throw new Error('User already verified');
        }

        // Update the user to mark as verified
        const updateQuery = 'UPDATE users SET isVerified = ? WHERE id = ?';
        await db.query(updateQuery, [true, userId]);

        return userRecord;
    }

    return null;  // User not found or invalid
}

// Function to record a donation
const recordDonation = (userId, donationDate, bloodType, quantity, callback) => {
    if (!Number.isInteger(userId)) {
        return callback(new Error('Invalid userId.'));
    }

    checkUserExists(userId, (err, exists) => {
        if (err) return callback(err);
        if (!exists) return callback(new Error('User not found.'));

        // Start a transaction
        pool.getConnection((err, connection) => {
            if (err) return callback(err);
            
            connection.beginTransaction(async (err) => {
                if (err) {
                    connection.release();
                    return callback(err);
                }

                try {
                    // 1. Record the donation
                    const [donationResult] = await connection.query(
                        'INSERT INTO Donations (user_id, donation_date, blood_type, quantity) VALUES (?, ?, ?, ?)',
                        [userId, donationDate, bloodType, quantity]
                    );

                    // 2. Update user's last_donation field
                    const [updateResult] = await connection.query(
                        'UPDATE Users SET last_donation = ? WHERE id = ?',
                        [donationDate, userId]
                    );

                    // Commit the transaction
                    await connection.commit();
                    connection.release();

                    callback(null, { 
                        donation_id: donationResult.insertId, 
                        userId, 
                        donationDate, 
                        bloodType, 
                        quantity 
                    });
                } catch (error) {
                    // Rollback on error
                    await connection.rollback();
                    connection.release();
                    callback(error);
                }
            });
        });
    });
};

// Function to log in a user
const loginUser = (email, password, callback) => {
    const sql = 'SELECT * FROM Users WHERE email = ?';
    pool.query(sql, [email], (err, results) => {
        if (err) return callback(err);
        if (results.length === 0) {
            console.log("🚨 User not found:", email);
            return callback(new Error('User not found.'));
        }

        const user = results[0];
        console.log("🔑 Checking password for:", user.email);

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return callback(err);
            if (!isMatch) {
                console.log("🚨 Invalid password for:", user.email);
                return callback(new Error('Invalid password.'));
            }
            
            console.log("✅ Login successful for:", user.email);
            callback(null, { 
                id: user.id, 
                name: user.name, 
                email: user.email, 
                blood_type: user.blood_type, 
                location: user.location, 
                role: user.role 
            });
        });
    });
};

async function updatePasswordHistory(userId, newHash) {
    // Get current history or initialize empty array
    const [result] = await pool.query(
        `SELECT password_history FROM users WHERE id = ?`,
        [userId]
    );
    
    const history = result[0].password_history || [];
    
    // Add new hash and limit to last 5 passwords
    const updatedHistory = [newHash, ...history].slice(0, 5);
    
    await pool.query(
        `UPDATE users SET password_history = ? WHERE id = ?`,
        [JSON.stringify(updatedHistory), userId]
    );
}

// Function to check if a user exists
const checkUserExists = (userId, callback) => {
    const sql = 'SELECT * FROM Users WHERE id = ?';
    pool.query(sql, [userId], (err, results) => {
        if (err) return callback(err);
        callback(null, results.length > 0); // Returns true if user exists
    });
};

async function getUserById(userId) {
    try {
        const [rows] = await pool.query("SELECT id, role FROM Users WHERE id = ?", [userId]);
        return rows.length > 0 ? rows[0] : null;
    } catch (error) {
        console.error("🚨 Database Error (getUserById):", error);
        throw error;
    }
}


// Function to verify user email
const verifyUserEmail = (userId, callback) => {
    const sql = 'UPDATE Users SET is_verified = ? WHERE id = ?';
    pool.query(sql, [true, userId], (err, result) => {
        if (err) return callback(err);
        if (result.affectedRows === 0) return callback(new Error('User not found.'));
        callback(null);
    });
};

// Function to fetch donation history for a user
async function getDonationHistory(userId) {
    try {
        const [rows] = await pool.query(`
            SELECT 
                donation_id,
                DATE_FORMAT(donation_date, '%Y-%m-%d') as donation_date,
                blood_type,
                quantity,
                DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
            FROM Donations 
            WHERE user_id = ?
            ORDER BY donation_date DESC
        `, [userId]);

        // Ensure numeric fields are numbers (not strings)
        return rows.map(row => ({
            ...row,
            donation_id: Number(row.donation_id),
            quantity: Number(row.quantity)
        }));
        
    } catch (error) {
        console.error("Database error:", error);
        throw error;
    }
}

async function getUserProfile(userId) {
    try {
        // Validate userId
        if (!userId || isNaN(userId)) {
            throw new Error('Invalid user ID');
        }

        // Use a transaction for atomic operations
        const connection = await pool.getConnection();
        await connection.beginTransaction();

        try {
            // Get basic profile info with a single query
            const [profileRows] = await connection.query(`
                SELECT 
                    id, name, email, phone, blood_type,
                    location, role, age, weight, health_status,
                    DATE_FORMAT(created_at, '%Y-%m-%d') as created_at,
                    DATE_FORMAT(last_donation, '%Y-%m-%d') as last_donation,
                    (
                        SELECT JSON_OBJECT(
                            'is_eligible', is_eligible,
                            'reason', reason,
                            'check_date', DATE_FORMAT(check_date, '%Y-%m-%d %H:%i')
                        )
                        FROM donoreligibility
                        WHERE user_id = users.id
                        ORDER BY check_date DESC
                        LIMIT 1
                    ) as eligibility,
                    (
                        SELECT JSON_ARRAYAGG(disease)
                        FROM user_diseases
                        WHERE user_id = users.id
                    ) as diseases,
                    (
                        SELECT JSON_ARRAYAGG(medication)
                        FROM user_medications
                        WHERE user_id = users.id
                    ) as medications
                FROM users 
                WHERE id = ?`, 
                [userId]
            );

            if (profileRows.length === 0) {
                await connection.rollback();
                return null;
            }

            const profile = profileRows[0];

            // Parse JSON fields
            if (profile.eligibility) {
                profile.eligibility = JSON.parse(profile.eligibility);
            } else {
                profile.eligibility = {
                    is_eligible: false,
                    reason: 'No eligibility check performed',
                    check_date: null
                };
            }

            profile.diseases = profile.diseases ? JSON.parse(profile.diseases) : [];
            profile.medications = profile.medications ? JSON.parse(profile.medications) : [];

            await connection.commit();
            return profile;

        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }

    } catch (error) {
        console.error("Database Error (getUserProfile):", error);
        
        // Return a consistent error structure
        throw {
            type: 'DATABASE_ERROR',
            message: 'Failed to fetch user profile',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        };
    }
}

// Update user profile
async function updateProfile(userId, { name, phone, blood_type, location }) {
    const [result] = await pool.query(`
        UPDATE users 
        SET name = ?, phone = ?, blood_type = ?, location = ?
        WHERE id = ?`,
        [name, phone, blood_type, location, userId]
    );
    return result.affectedRows > 0;
}

// Update notification preferences
async function updateNotifications(userId, enabled) {
    const [result] = await pool.query(`
        UPDATE users 
        SET notifications_enabled = ?
        WHERE id = ?`,
        [enabled, userId]
    );
    return result.affectedRows > 0;
}


async function fetchWithTimeout(url, options, timeout = 7000) {
    return Promise.race([
        fetch(url, options),
        new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Request timed out')), timeout)
        )
    ]);
}


async function requestDonation(userId, bloodType, quantity, isUrgent, hospitalName) {
    try {
        const [result] = await pool.query(
            "INSERT INTO donationrequests (user_id, blood_type, request_date, quantity, status, is_urgent, hospital_name) VALUES (?, ?, NOW(), ?, 'pending', ?, ?)",
            [userId, bloodType, quantity, isUrgent ? 1 : 0, hospitalName]
        );
        return result;
    } catch (error) {
        console.error("🚨 Database Error (requestDonation):", error);
        throw error;
    }
}


async function findEligibleDonors(bloodType) {
    console.log(`🔍 Searching for donors with blood type: ${bloodType}`);
    try {
        // ✅ No need for `.promise()` when using `mysql2/promise`
        const [donors] = await pool.query(
            "SELECT email, phone FROM users WHERE blood_type = ?",
            [bloodType]
        );

        if (donors.length === 0) {
            console.log("⚠ No eligible donors found.");
        }

        return donors;
    } catch (error) {
        console.error("🚨 Error finding donors:", error);
        throw error;
    }
}


async function sendUrgentNotification(userId, email, phone, bloodType, quantity, hospital) {
    try {
        const googleMapsUrl = `https://www.google.com/maps?q=${hospital.latitude},${hospital.longitude}`;

        await sgMail.send({
            to: email,
            from: process.env.SENDGRID_FROM_EMAIL,
            subject: "🚨 Urgent Blood Donation Request",
            html: `
                <h2>🚨 Urgent Blood Needed</h2>
                <p><strong>Blood Type:</strong> ${bloodType}</p>
                <p><strong>Quantity:</strong> ${quantity} units</p>
                <p><strong>Hospital:</strong> ${hospital.name}, ${hospital.location}</p>
                <p><strong>Address:</strong> ${hospital.address}</p>
                <p><strong>Map Location:</strong> <a href="${googleMapsUrl}" target="_blank">View on Google Maps</a></p>
                <p>Please head to the above hospital if you’re eligible to donate. Every drop counts ❤️</p>
            `
        });

        console.log("✅ Email sent to", email);
                // Log the email into the database
                await pool.query(
                    "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
                    [userId, `Urgent request for blood type ${bloodType} with quantity ${quantity} sent to ${email}`]
                );        
        return true;

    } catch (err) {
        console.error("❌ Failed to send email to", email, err.message);
        return false;
    }
}




async function getAllHospitals() {
    const query = `
        SELECT 
            hospital_id,
            name,
            location,
            address,
            latitude,
            longitude,
            hours,
            contact_info,
            DATE_FORMAT(created_at, '%Y-%m-%d') as created_at
        FROM hospitals
        ORDER BY name ASC
    `;

    let connection;

    try {
        console.time('getAllHospitalsQuery');
        
        // Get a connection from the pool
        connection = await pool.getConnection();
        const [rows] = await connection.query(query);
        
        if (!rows || rows.length === 0) {
            return [];
        }
        

        return rows;
    } catch (error) {
        console.error("Database error in getAllHospitals:", error);
        throw error;
    } finally {
        // Always release the connection back to the pool
        if (connection) connection.release();
        console.timeEnd('getAllHospitalsQuery');
    }
}




async function getHospitalById(id) {
    const hospitalId = parseInt(id, 10);
    if (isNaN(hospitalId)) {
        throw new Error('INVALID_HOSPITAL_ID');
    }

    const query = `
        SELECT 
            hospital_id,
            name,
            location,
            address,
            latitude,
            longitude,
            hours,
            contact_info,
            DATE_FORMAT(created_at, '%Y-%m-%d') as created_at
        FROM Hospitals 
        WHERE hospital_id = ?
        LIMIT 1
    `;

    console.time('getHospitalByIdQuery');
    try {
        const [rows] = await pool.query(query, [hospitalId]);

        if (rows.length === 0) {
            throw new Error('HOSPITAL_NOT_FOUND');
        }
        return rows[0];
    } catch (error) {
        console.error("Database error in getHospitalById:", error);
        throw error;
    } finally {
        console.timeEnd('getHospitalByIdQuery');
    }
}


// Function to send password reset email
const sendPasswordResetEmail = (email, callback) => {
    const sql = 'SELECT * FROM Users WHERE email = ?';
    pool.query(sql, [email], (err, results) => {
        if (err) return callback(err);
        if (results.length === 0) return callback(new Error('User not found.'));

        const userId = results[0].id;
        const resetLink = `http://192.168.8.14:5500/reset-password/${userId}`; // Adjust as necessary

        const transporter = nodemailer.createTransport({
            service: 'gmail', // Use your email service
            auth: {
                user: process.env.EMAIL_USER || 'your-email@gmail.com',
                pass: process.env.EMAIL_PASS || 'your-email-password'
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER || 'your-email@gmail.com',
            to: email,
            subject: 'Password Reset Request',
            text: `Please click the following link to reset your password: ${resetLink}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) return callback(error);
            console.log('Password reset email sent: ' + info.response);
            callback(null);
        });
    });
};

// Function to generate a password reset token
function generateResetToken(userId) {
    try {
        console.log("🔑 Creating reset token for user:", userId);
        const secret = process.env.JWT_SECRET || "your-secret-key";  // Use a secure secret!
        const token = jwt.sign({ userId }, secret, { expiresIn: "1h" });

        console.log("✅ Reset token created:", token);
        return token;
    } catch (error) {
        console.error("🚨 Error generating reset token:", error);
        return null;
    }
}


// Function to send an email
async function sendEmail(to, subject, text) {
    try {
        console.log("📨 Sending email via SendGrid to:", to);

        const msg = {
            to,
            from: process.env.SENDGRID_FROM_EMAIL,  // Must be a verified email
            subject,
            text
        };

        const response = await sgMail.send(msg);
        console.log("✅ Email sent successfully!", response);
        return true;
    } catch (error) {
        console.error("🚨 Error sending email:", error.response ? error.response.body : error);
        return false;
    }
}

// Get all blood inventory
async function getInventory() {
    try {
        const [rows] = await pool.query("SELECT * FROM inventory");
        return rows;
    } catch (error) {
        console.error("❌ Error fetching inventory:", error);
        throw error;
    }
}

// Update blood inventory
async function updateInventory(bloodType, quantity, expirationDate = null) {
    try {
        const [result] = await pool.query(
            `INSERT INTO inventory (blood_type, quantity, expiration_date)
             VALUES (?, ?, ?)
             ON DUPLICATE KEY UPDATE
                quantity = VALUES(quantity),
                expiration_date = VALUES(expiration_date)`,
            [bloodType, quantity, expirationDate]
        );
        return result;
    } catch (error) {
        console.error("❌ Error updating inventory:", error);
        throw error;
    }
}

// Get expiring inventory
async function getExpiringInventory() {
    try {
        const [results] = await pool.query(
            `SELECT blood_type, quantity, expiration_date
             FROM inventory
             WHERE expiration_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)`
        );
        return results; // This should return an array of objects with blood_type, quantity, and expiration_date
    } catch (error) {
        console.error("❌ Error fetching expiring inventory:", error);
        throw error;
    }
}


// ✅ Edit (update) blood inventory details
async function editInventory(inventoryId, bloodType, quantity, expirationDate = null) {
    return new Promise((resolve, reject) => {
        const query = `
            UPDATE inventory
            SET blood_type = ?, quantity = ?, expiration_date = ?, last_updated = CURRENT_TIMESTAMP
            WHERE inventory_id = ?
        `;
        pool.query(query, [bloodType, quantity, expirationDate, inventoryId], (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

// ✅ Delete blood inventory item
async function deleteInventory(inventoryId) {
    return new Promise((resolve, reject) => {
        const query = "DELETE FROM inventory WHERE inventory_id = ?";
        pool.query(query, [inventoryId], (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

// ✅ Add new blood inventory
async function addInventory(bloodType, quantity, expirationDate = null) {
    try {
        const [result] = await pool.query(
            `INSERT INTO inventory (blood_type, quantity, expiration_date)
             VALUES (?, ?, ?)`,
            [bloodType, quantity, expirationDate]
        );
        return result;
    } catch (error) {
        console.error("❌ Error adding inventory:", error);
        throw error;
    }
}



/*** FUNCTIONS FOR MANAGE DONOR NOTIFICATIONS (UC-6) ***/

function getDonorNotifications(id, callback) {
    pool.query('SELECT * FROM notifications WHERE donor_id = ?', [id], callback);
}

function updateDonorNotifications(id, email, sms, urgentAlerts, callback) {
    if (!email && !sms && !urgentAlerts) return callback(new Error('No changes made'));
    pool.query('UPDATE donors SET email_notifications = ?, sms_notifications = ?, urgent_alerts = ? WHERE id = ?',
        [email, sms, urgentAlerts, id], callback);
}

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

// Function to generate reports based on type and date range
async function generateReport(reportType, startDate, endDate) {
    try {
        // Validate dates
        if (!isValidDate(startDate) || !isValidDate(endDate)) {
            throw new Error("Invalid date format");
        }

        let query = "";
        let queryParams = [];

        switch (reportType) {
            case "bloodDonations":
                query = `
                SELECT
                d.donation_id,
                u.name as donor_name,
                d.blood_type,
                d.quantity,
                DATE_FORMAT(d.donation_date, '%Y-%m-%d') as donation_date
            FROM Donations d
            JOIN Users u ON d.user_id = u.id
            WHERE d.donation_date BETWEEN ? AND ?
            ORDER BY d.donation_date DESC`;
                queryParams = [startDate, endDate];
                break;
                
            case "inventoryLevels":
                query = `
                    SELECT 
                        blood_type, 
                        COALESCE(SUM(quantity), 0) as total_units,
                        MIN(expiration_date) as earliest_expiry,
                        MAX(expiration_date) as latest_expiry,
                        COALESCE(SUM(CASE WHEN expiration_date < CURDATE() THEN quantity ELSE 0 END), 0) as expired_units
                    FROM inventory 
                    WHERE (? IS NULL OR last_updated >= ?)
                    AND (? IS NULL OR last_updated <= ?)
                    GROUP BY blood_type
                `;
                queryParams = [startDate, startDate, endDate, endDate];
                break;
                case "donorDemographics": 
                query = `
                SELECT 
                id AS user_id,
                name,
                email,
                gender,
                blood_type,
                location,
                age,
                weight,
                health_status,
                created_at
                FROM Users
                WHERE role = 'donor' AND created_at BETWEEN ? AND ?
                ORDER BY created_at DESC;
                `;
                queryParams = [startDate, endDate];
                break;
            case "expiringSoon":
                query = `
                    SELECT * FROM inventory 
                    WHERE expiration_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)
                    AND quantity > 0
                    ORDER BY expiration_date
                `;
                // No parameters needed for this query
                break;
                
            default:
                throw new Error("Invalid report type selected.");
        }

        console.log("📡 Executing Query:", query, queryParams);

        // Execute query with proper parameters
        const [results] = await pool.query(query, queryParams); // Note the [results] destructuring

        console.log(`✅ Query successful, returned ${results.length} rows`);
        
        // Format dates for better readability
        const formattedResults = results.map(item => {
            const formattedItem = {...item};
            
            // Format date fields if they exist
            ['expiration_date', 'donation_date', 'created_at', 'last_updated'].forEach(field => {
                if (item[field]) {
                    formattedItem[field] = new Date(item[field]).toISOString().split('T')[0];
                }
            });
            
            return formattedItem;
        });

        console.log("📊 Formatted Results:", formattedResults);
        return formattedResults;
        
    } catch (error) {
        console.error("🚨 Database Query Error:", error);
        throw error;
    }
}

async function getAllDonorEligibility() {
    const [donors] = await pool.query(`
        SELECT u.id, u.name, u.age, u.weight, e.is_eligible, e.reason
        FROM users u
        JOIN donoreligibility e ON u.id = e.user_id
    `);
    return donors;
}

async function isPasswordUsedBefore(userId, newPassword) {
    const [history] = await pool.query(
        `SELECT password_hash FROM password_history 
         WHERE user_id = ? ORDER BY created_at DESC LIMIT 5`,
        [userId]
    );
    
    for (const record of history) {
        if (await bcrypt.compare(newPassword, record.password_hash)) {
            return true;
        }
    }
    return false;
}

async function isPasswordUsedBefore(userId, newPassword) {
    try {
        // Check against password_history table
        const [history] = await pool.query(
            `SELECT password_hash FROM password_history 
             WHERE user_id = ? 
             ORDER BY created_at DESC 
             LIMIT 5`,
            [userId]
        );
        
        // Compare against each historical hash
        for (const record of history) {
            if (await bcrypt.compare(newPassword, record.password_hash)) {
                return true; // Password was used before
            }
        }
        return false; // Password is new
    } catch (error) {
        console.error("Error checking password history:", error);
        throw error;
    }
}

module.exports = { checkEligibility, getAllDonorEligibility };

// Export the model functions
module.exports = {
    createUser,
    loginUser,
    getUserById,
    recordDonation,
    requestDonation,
    scheduleAppointment,
    checkUserExists,
    verifyUserEmail,
    getDonationHistory,
    sendPasswordResetEmail,
    updatePassword,
    findUserByEmail,
    generateResetToken,
    sendEmail,
    getInventory,
    updateInventory,
    getExpiringInventory,
    getDonorNotifications,
    updateDonorNotifications,
    checkEligibility,
    generateReport,
    editInventory,
    deleteInventory,
    findEligibleDonors,
    sendUrgentNotification,
    fetchWithTimeout,
    getUserProfile,
    updateProfile,
    updateNotifications,
    getHospitalById,
    getAllHospitals,
    getAllDonorEligibility,
    loginAdmin,
    addInventory,
    activateUser,
    updatePasswordHistory,
    isPasswordUsedBefore,
    getAllBloodBanks
};