require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const xlsx = require('xlsx');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
// const nodemailer = require('nodemailer');
// const crypto = require('crypto');
const app = express();


const PORT = process.env.PORT || 3000;
// Middleware
// app.use(cors({
//     origin: 'http://1.2.7', // Replace with your frontend URL 
//     methods: ['GET', 'POST'],
//     credentials: true
// }));
app.use(cors({
    origin: '*', // Or specify allowed origin(s)
    // origin: 'https://admin-graba2z.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors()); // Handle preflight

// ✅ Body parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));


const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DATABASE_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'ecommerce',
    waitForConnections: true, // Will wait for a free connection 
    connectionLimit: 10, // Maximum number of connections to create at once
    queueLimit: 0 // Unlimited request queue
});
// const db = mysql.createPool({       
//     host: process.env.DB_HOST || 'srv1377.hstgr.io' ,  
//     user: process.env.DATABASE_USER || 'u998585094_grabatoznode' ,
//     password: process.env.DB_PASSWORD || `Grabatoznode@112233` ,
//     database: process.env.DB_NAME || `u998585094_grabatoznode`,
//     waitForConnections: true, // Will wait for a free connection 
//     connectionLimit: 10, // Maximum number of connections to create at once
//     queueLimit: 0 // Unlimited request queue
// });

// Function to test connection (optional)
(async () => {
    try {
        const connection = await db.getConnection();
        console.log(`MySQL Connected at ${process.env.DB_HOST}...`);
        connection.release(); // Release connection back to pool

        //   Call the function to clear and insert dummy data
        //   await clearAndInsertDummyData2();
    } catch (err) {
        console.error('Error connecting to MySQL:', err.message);
    }
})();

// Multer storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'Uploads/'); // Specify the directory to save uploaded files
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Append timestamp to the filename
    }
});

// Reusable multer instance
const upload = multer({
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // 5MB limit
});
app.get('/api/db-name', (req, res) => {
    const dbName = process.env.DB_NAME;
    res.json({ success: true, dbName });
});

app.post('/signup', async (req, res) => {
    const { name, email, password, role } = req.body;

    // Basic validation
    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'Name, email, password, and role are required.' });
    }

    if (!['admin', 'customer'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role. Allowed values are "admin" or "customer".' });
    }

    try {
        // Check if user already exists
        const [existingUser] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'User already exists with this email.' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 8);

        // Insert new user into the database
        await db.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)', [name, email, hashedPassword, role]);

        res.status(201).json({ message: 'User registered successfully!' });
    } catch (err) {
        console.error('Error during signup:', err.message);
        res.status(500).json({ error: 'Server error during signup' });
    }
});

// 1. GET Endpoint to fetch user data (add this to your backend)
// 1. GET Endpoint to fetch user data
app.get('/user', authenticate, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT id, name, email FROM users WHERE id = ?', [req.userId]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching user:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// 2. UPDATE Endpoint
app.put('/update-user', authenticate, async (req, res) => {
    const { name, email } = req.body;

    if (!name || !email) {
        return res.status(400).json({ message: 'Name and email are required' });
    }

    try {
        // Check if email is already taken by another user
        const [emailCheck] = await db.query(
            'SELECT id FROM users WHERE email = ? AND id != ?',
            [email, req.userId]
        );

        if (emailCheck.length > 0) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        // Update user
        await db.query(
            'UPDATE users SET name = ?, email = ? WHERE id = ?',
            [name, email, req.userId]
        );

        res.status(200).json({ message: 'User updated successfully' });
    } catch (err) {
        console.error('Error updating user:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// app.post('/signup', async (req, res) => {
//     // console.log('Received request:', req.body);
//     const { name, email, password } = req.body;

//     if (!name || !email || !password) {
//         return res.status(400).json({ message: 'Name, email, and password are required.' });
//     }

//     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//     if (!emailRegex.test(email)) {
//         return res.status(400).json({ message: 'Invalid email format.' });
//     }

//     try {
//         // Check if user already exists
//         const [existingUser] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
//         if (existingUser.length > 0) {
//             return res.status(400).json({ message: 'User already exists with this email.' });
//         }

//         // Generate verification code
//         const verificationCode = crypto.randomInt(100000, 999999).toString();

//         // Hash password
//         const hashedPassword = await bcrypt.hash(password, 8);

//         // Insert new user with verification code
//         await db.query(
//             'INSERT INTO users (name, email, password, verification_code) VALUES (?, ?, ?, ?)', 
//             [name, email, hashedPassword, verificationCode]
//         );

//         // Send email with verification code
//         const transporter = nodemailer.createTransport({
//             service: 'Gmail',
//             auth: {
//                 user: 'your-email@gmail.com', // Replace with your email
//                 pass: 'your-email-password', // Replace with your email password or app password
//             },
//         });

//         await transporter.sendMail({
//             from: 'your-email@gmail.com',
//             to: email,
//             subject: 'Verify Your Email',
//             text: `Your verification code is: ${verificationCode}`,
//         });

//         res.status(201).json({ message: 'User registered successfully! Please verify your email.' });
//     } catch (err) {
//         console.error('Error during signup:', err.message);
//         res.status(500).json({ error: 'Server error during signup' });
//     }
// });

app.post('/verify-email', async (req, res) => {
    const { email, verificationCode } = req.body;

    if (!email || !verificationCode) {
        return res.status(400).json({ message: 'Email and verification code are required.' });
    }

    try {
        // Check if the user exists and has the correct verification code
        const [user] = await db.query('SELECT * FROM users WHERE email = ? AND verification_code = ?', [email, verificationCode]);

        if (user.length === 0) {
            return res.status(400).json({ message: 'Invalid email or verification code.' });
        }

        // Mark the user as verified
        await db.query('UPDATE users SET is_verified = TRUE, verification_code = NULL WHERE email = ?', [email]);

        res.status(200).json({ message: 'Email verified successfully!' });
    } catch (err) {
        console.error('Error during email verification:', err.message);
        res.status(500).json({ error: 'Server error during email verification' });
    }
});


// Login API   
// app.post('/login', async (req, res) => {
//     const { email, password } = req.body; 

//     // Basic validation
//     if (!email || !password) {
//         return res.status(400).json({ message: 'Email and password are required.' });
//     }

//     try {
//         // Check if the user exists
//         const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

//         if (rows.length === 0) {
//             return res.status(404).json({ message: 'User not found.' });
//         }

//         const user = rows[0];

//         // Compare passwords
//         const isPasswordValid = await bcrypt.compare(password, user.password);
//         if (!isPasswordValid) {
//             return res.status(401).json({ accessToken: null, message: 'Invalid password.' });
//         }

//         // Generate a JWT token
//         const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || '04d063ae4d2932d2f0eb6fe569328eebdea5be494db648b1fb28048267c858ef', { expiresIn: 86400 }); // 24 hours

//         res.status(200).json({
//             id: user.id,
//             name: user.name,
//             email: user.email,
//             accessToken: token 
//         });
//     } catch (err) {
//         console.error('Error during login:', err.message);
//         res.status(500).json({ error: 'Server error during login' });
//     }
// });

function authorizeAdmin(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ message: 'No token provided. Please log in.' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized. Invalid token.' });
        }

        if (decoded.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden. Admins only.' });
        }

        req.userId = decoded.id; // Attach user ID for further use
        next();
    });
}

app.get('/admin-only', authenticate, authorizeAdmin, (req, res) => {
    res.status(200).json({ message: 'Welcome Admin!' });
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const user = rows[0];

        // Compare passwords
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ accessToken: null, message: 'Invalid password.' });
        }

        // Generate a JWT token with user role
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: 86400 }); // 24 hours

        res.status(200).json({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,  // Return role as part of the response
            accessToken: token
        });
    } catch (err) {
        console.error('Error during login:', err.message);
        res.status(500).json({ error: 'Server error during login' });
    }
});



// API Endpoint to fetch supplier data
app.get('/api/suppliers', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM suppliers'); // Promise-based query
        res.json(results); // Send results as JSON
    } catch (err) {
        console.error('Error fetching suppliers:', err);
        res.status(500).json({ error: 'Failed to fetch suppliers data' });
    }
});
// API Endpoint to get supplier by ID
app.get('/api/suppliers/getSupplierById', async (req, res) => {
    const supplierId = req.query.id;

    if (!supplierId) {
        return res.status(400).json({ error: 'Supplier ID is required' });
    }

    try {
        const [results] = await db.query('SELECT * FROM suppliers WHERE id = ?', [supplierId]);
        if (results.length === 0) {
            return res.status(404).json({ error: 'Supplier not found' });
        }
        res.json(results[0]); // Return the single supplier object
    } catch (err) {
        console.error('Error fetching supplier by ID:', err);
        res.status(500).json({ error: 'Failed to fetch supplier details' });
    }
});

// API Endpoint to update supplier by ID
app.put('/api/suppliers/updateSupplier/:id', async (req, res) => {
    const supplierId = req.params.id;
    const {
        name,
        email,
        phone,
        company,
        address,
        country,
        state,
        city,
        zip_code,
    } = req.body;

    // Check if all fields are provided
    if (!supplierId || !name || !email || !phone || !company || !address || !country || !state || !city || !zip_code) {
        return res.status(400).json({ error: 'All fields are required for updating the supplier.' });
    }

    try {
        // Update query
        const query = `
        UPDATE suppliers 
        SET 
          name = ?,
          email = ?,
          phone = ?,
          company = ?,
          address = ?,
          country = ?,
          state = ?,
          city = ?,
          zip_code = ?
        WHERE id = ?`;

        // Execute the query
        const [result] = await db.query(query, [
            name,
            email,
            phone,
            company,
            address,
            country,
            state,
            city,
            zip_code,
            supplierId,
        ]);

        // Check if any row was updated
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: `Supplier with ID ${supplierId} not found.` });
        }

        res.json({ message: `Supplier with ID ${supplierId} updated successfully.` });
    } catch (error) {
        console.error('Error updating supplier:', error);
        res.status(500).json({ error: 'Failed to update supplier. Please try again later.' });
    }
});


// API Endpoint to delete supplier by ID
app.delete('/api/suppliers/:id', async (req, res) => {
    const supplierId = req.params.id;

    if (!supplierId) {
        return res.status(400).json({ error: 'Supplier ID is required.' });
    }

    try {
        // Delete supplier from the database
        const query = 'DELETE FROM suppliers WHERE id = ?';
        const [result] = await db.query(query, [supplierId]);

        // Check if a supplier was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: `Supplier with ID ${supplierId} not found.` });
        }

        res.json({ message: `Supplier with ID ${supplierId} deleted successfully.` });
    } catch (error) {
        console.error('Error deleting supplier:', error);
        res.status(500).json({ error: 'Failed to delete supplier. Please try again later.' });
    }
});


function authenticate(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ message: 'No token provided. Please log in.' });
    }

    jwt.verify(token, process.env.JWT_SECRET || ' 04d063ae4d2932d2f0eb6fe569328eebdea5be494db648b1fb28048267c858ef', (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized. Invalid token.' });
        }
        req.userId = decoded.id;
        next();
    });
}

app.post('/validate-token', authenticate, (req, res) => {
    res.status(200).json({ message: 'Token is valid.' });
});


// const storage = multer.diskStorage({
//     destination: (req, file, cb) => {
//         cb(null, 'uploads/'); // Specify the directory to save uploaded files
//     },
//     filename: (req, file, cb) => {
//         cb(null, Date.now() + path.extname(file.originalname)); // Append timestamp to the filename
//     }
// });

// // Initialize multer
// const upload = multer({ storage: storage }); 

app.post('/api/theme', upload.fields([
    { name: 'logo', maxCount: 1 },
    { name: 'favicon', maxCount: 1 },
    { name: 'footerLogo', maxCount: 1 },
]), async (req, res) => {
    try {
        const files = req.files;
        if (!files || !files.logo || !files.favicon || !files.footerLogo) {
            return res.status(400).json({ message: 'All files (logo, favicon, footerLogo) are required.' });
        }

        const logoPath = files.logo[0].filename;
        const faviconPath = files.favicon[0].filename;
        const footerLogoPath = files.footerLogo[0].filename;

        const sql = `
        INSERT INTO theme_config (logo, favicon, footerLogo)
        VALUES (?, ?, ?)
      `;
        const [result] = await db.query(sql, [logoPath, faviconPath, footerLogoPath]);

        res.status(201).json({
            message: 'Theme configuration saved successfully!',
            themeId: result.insertId,
            data: { logo: logoPath, favicon: faviconPath, footerLogo: footerLogoPath },
        });
    } catch (err) {
        console.error('Error saving theme configuration:', err.message);
        res.status(500).json({ message: 'Error saving theme configuration.', error: err.message });
    }
});

// Purchases
app.post('/api/purchases', authenticate, upload.single('file'), async (req, res) => {
    const { date, reference_no, status, supplier, description, items: rawItems } = req.body;

    // Validate required fields
    if (!supplier || !date || !reference_no || !status) {
        return res.status(400).json({ message: 'All fields are required except description' });
    }

    // Parse and validate items
    const items = Array.isArray(rawItems) ? rawItems : JSON.parse(rawItems || '[]');
    if (!items.length) {
        return res.status(400).json({ message: 'Items must be a non-empty array' });
    }

    const file = req.file;

    const connection = await db.getConnection(); // Get a database connection
    try {
        await connection.beginTransaction(); // Start a transaction

        // Insert purchase data with `null` as default total
        const purchaseSql = `
            INSERT INTO purchases (date, reference_no, status, supplier, file_path, description, total)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const [purchaseResult] = await connection.query(purchaseSql, [
            date,
            reference_no,
            status,
            supplier,
            file ? file.path : null,
            description || null,
            null // Default total is null
        ]);
        const purchase_id = purchaseResult.insertId;

        // Calculate the total for the entire purchase (sum of all item subtotals, taxes, and discounts)
        const total = items.reduce((sum, item) => {
            const itemTotal = (item.subtotal || 0) + (item.taxes || 0) - (item.discount || 0);
            return sum + itemTotal;
        }, 0);

        // Prepare the item details array for batch insert
        const purchaseItems = items.map((item) => [
            purchase_id,
            item.product,
            item.quantity,
            item.discount || 0,
            item.taxes || 0,
            item.subtotal || 0
        ]);

        // Insert purchase items into the database
        const itemsSql = `
            INSERT INTO purchase_items (purchase_id, product, quantity, discount, taxes, subtotal)
            VALUES ?
        `;
        await connection.query(itemsSql, [purchaseItems]);

        // Update the total in the purchases table
        const updateTotalSql = `
            UPDATE purchases 
            SET total = ? 
            WHERE id = ?
        `;
        await connection.query(updateTotalSql, [total, purchase_id]);

        await connection.commit(); // Commit the transaction

        // Return the response with total outside of the items array
        res.status(201).json({
            message: 'Purchase and items saved successfully',
            purchase_id,
            date,
            reference_no,
            status,
            supplier,
            file_path: file ? file.path : null,
            description: description || null,
            total, // Include total outside of the items array
            items: items.map((item) => ({
                ...item,
                total: undefined // Exclude item-level total from the response
            })),
        });
    } catch (err) {
        await connection.rollback(); // Rollback the transaction in case of an error
        console.error('Error saving purchase:', err.message);
        res.status(500).json({ message: 'Error saving purchase, please try again', error: err.message });
    } finally {
        connection.release(); // Release the database connection
    }
});

app.get('/api/purchases', authenticate, async (req, res) => {
    try {
        // Query to fetch required fields
        const sql = `
            SELECT 
                id,
                supplier,
                date,
                reference_no,
                status,
                total
                
            FROM purchases
        `;

        // Execute the query
        const [rows] = await db.query(sql);

        // console.log('Fetched purchases:', rows); // Debug log

        // Return the rows
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching purchases:', err.message); // Debug the error
        res.status(500).json({ message: 'Error fetching purchases, please try again' });
    }
});

// UPDATE EXISTING PURCHASE
// app.put('/api/purchases/:id', authenticate, upload.single('file'), async (req, res) => {
//     const { id } = req.params;
//     const { supplier, date, reference_no, status, total, payment_status } = req.body;

//     // Validate required fields
//     if (!supplier || !date || !reference_no || !status || !total || !payment_status) {
//         return res.status(400).json({ message: 'All fields are required' });
//     }

//     // Get the uploaded file information
//     const file = req.file; // Access the uploaded file
//     const filePath = file ? file.path : null; // Get the file path if a new file is uploaded

//     try {
//         // Update the purchase, including the file_path if provided
//         const query = `UPDATE purchases
//                        SET supplier = ?, date = ?, reference_no = ?, status = ?, total = ?, payment_status = ?, file_path = ?
//                        WHERE id = ?`;

//         const [result] = await db.query(query, [supplier, date, reference_no, status, total, payment_status, filePath, id]);

//         if (result.affectedRows === 0) {
//             return res.status(404).json({ message: 'Purchase not found' });
//         }

//         res.json({ message: 'Purchase updated successfully' });
//     } catch (err) {
//         console.error('Error updating purchase:', err.message);
//         res.status(500).json({ message: 'Internal Server Error' });
//     }
// });
// app.put('/api/purchases/:id', authenticate, upload.single('file'), async (req, res) => {
//     const { id } = req.params;
//     const { date, reference_no, status, supplier, description, items: rawItems } = req.body;

//     if (!supplier || !date || !reference_no || !status) {
//         return res.status(400).json({ message: 'All fields are required except description' });
//     }

//     const items = Array.isArray(rawItems) ? rawItems : JSON.parse(rawItems || '[]');
//     if (!items.length) {
//         return res.status(400).json({ message: 'Items must be a non-empty array' });
//     }

//     const file = req.file;

//     const connection = await db.getConnection();
//     try {
//         await connection.beginTransaction();

//         // Update purchase details
//         const updatePurchaseSql = `
//             UPDATE purchases
//             SET date = ?, reference_no = ?, status = ?, supplier = ?, file_path = ?, description = ?
//             WHERE id = ?
//         `;
//         await connection.query(updatePurchaseSql, [
//             date,
//             reference_no,
//             status,
//             supplier,
//             file ? file.path : null,
//             description || null,
//             id,
//         ]);

//         // Delete existing items
//         const deleteItemsSql = `DELETE FROM purchase_items WHERE purchase_id = ?`;
//         await connection.query(deleteItemsSql, [id]);

//         // Calculate new total
//         const total = items.reduce((sum, item) => {
//             const itemTotal = (item.subtotal || 0) + (item.taxes || 0) - (item.discount || 0);
//             return sum + itemTotal;
//         }, 0);

//         // Insert updated items
//         const newItems = items.map((item) => [
//             id,
//             item.product,
//             item.quantity,
//             item.discount || 0,
//             item.taxes || 0,
//             item.subtotal || 0,
//         ]);
//         const insertItemsSql = `
//             INSERT INTO purchase_items (purchase_id, product, quantity, discount, taxes, subtotal)
//             VALUES ?
//         `;
//         await connection.query(insertItemsSql, [newItems]);

//         // Update total
//         const updateTotalSql = `
//             UPDATE purchases 
//             SET total = ?
//             WHERE id = ?
//         `;
//         await connection.query(updateTotalSql, [total, id]);

//         await connection.commit();
//         res.status(200).json({ message: 'Purchase updated successfully', id, total });
//     } catch (err) {
//         await connection.rollback();
//         console.error('Error updating purchase:', err.message);
//         res.status(500).json({ message: 'Failed to update purchase', error: err.message });
//     } finally {
//         connection.release();
//     }
// });


// app.get('/api/purchases/:id', authenticate, async (req, res) => {
//     const { id } = req.params;

//     try {
//         // Fetch purchase details
//         const purchaseSql = `
//             SELECT id, date, reference_no, status, supplier, file_path, description, total
//             FROM purchases 
//             WHERE id = ?
//         `;
//         const [purchaseResult] = await db.query(purchaseSql, [id]);
//         if (purchaseResult.length === 0) {
//             return res.status(404).json({ message: 'Purchase not found' });
//         }
//         const purchase = purchaseResult[0];

//         // Fetch associated items
//         const itemsSql = `
//             SELECT id, product, quantity, discount, taxes, subtotal
//             FROM purchase_items 
//             WHERE purchase_id = ?
//         `;
//         const [items] = await db.query(itemsSql, [id]);
//         purchase.items = items;

//         res.status(200).json(purchase);
//     } catch (err) {
//         console.error('Error fetching purchase:', err.message);
//         res.status(500).json({ message: 'Failed to fetch purchase', error: err.message });
//     }
// });


// Get single purchase endpoint
app.get('/api/purchases/:id', authenticate, async (req, res) => {
    try {
        const [purchase] = await db.query(`
            SELECT p.*, 
                   GROUP_CONCAT(pi.product) as products,
                   GROUP_CONCAT(pi.quantity) as quantities,
                   GROUP_CONCAT(pi.unit_cost) as unit_costs,
                   GROUP_CONCAT(pi.taxes) as taxes,
                   GROUP_CONCAT(pi.discount) as discounts
            FROM purchases p
            LEFT JOIN purchase_items pi ON p.id = pi.purchase_id
            WHERE p.id = ?
            GROUP BY p.id
        `, [req.params.id]);

        if (!purchase.length) {
            return res.status(404).json({ message: 'Purchase not found' });
        }

        res.status(200).json(purchase[0]);
    } catch (error) {
        console.error('Error fetching purchase:', error);
        res.status(500).json({ message: 'Failed to fetch purchase', error: error.message });
    }
});

// Update purchase endpoint
app.put('/api/purchases/:id', authenticate, upload.single('file'), async (req, res) => {
    const purchaseId = req.params.id;
    const { date, reference_no, status, supplier, description, items: rawItems } = req.body;

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        // Update main purchase data
        await connection.query(`
            UPDATE purchases SET
                date = ?,
                reference_no = ?,
                status = ?,
                supplier = ?,
                description = ?,
                file_path = COALESCE(?, file_path)
            WHERE id = ?
        `, [
            date,
            reference_no,
            status,
            supplier,
            description || null,
            req.file?.path,
            purchaseId
        ]);

        // Handle items
        const items = JSON.parse(rawItems);
        await connection.query('DELETE FROM purchase_items WHERE purchase_id = ?', [purchaseId]);

        const itemsValues = items.map(item => [
            purchaseId,
            item.product,
            item.quantity,
            item.discount,
            item.taxes,
            item.unitCost,
            item.subtotal
        ]);

        if (itemsValues.length > 0) {
            await connection.query(`
                INSERT INTO purchase_items 
                (purchase_id, product, quantity, discount, taxes, unit_cost, subtotal)
                VALUES ?
            `, [itemsValues]);
        }

        // Recalculate total
        const [totalResult] = await connection.query(`
            SELECT SUM(subtotal) as total 
            FROM purchase_items 
            WHERE purchase_id = ?
        `, [purchaseId]);

        await connection.query(`
            UPDATE purchases SET total = ?
            WHERE id = ?
        `, [totalResult[0].total || 0, purchaseId]);

        await connection.commit();
        res.status(200).json({ message: 'Purchase updated successfully' });
    } catch (error) {
        await connection.rollback();
        console.error('Error updating purchase:', error);
        res.status(500).json({ message: 'Failed to update purchase', error: error.message });
    } finally {
        connection.release();
    }
});



app.delete('/api/purchases/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete a purchase by ID
        const sql =
            'DELETE FROM purchases WHERE id = ?';

        const [result] = await db.query(sql, [id]);

        // Check if a purchase was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Purchase not found' });
        }

        // Send success response
        res.status(200).json({ message: 'Purchase deleted successfully' });
    } catch (err) {
        console.error('Error deleting purchase record:', err.message);
        res.status(500).json({ message: 'Error deleting purchase record' });
    }
});


app.post('/api/payments', upload.single('image'), async (req, res) => {
    const { date, reference, amount, payment_method } = req.body;
    const imagePath = req.file ? req.file.path : null;

    // Log incoming data for debugging
    // console.log('Received Data:', { date, reference, amount, payment_method, imagePath });

    try {
        const [result] = await db.query(
            `INSERT INTO payments (date, reference, amount, payment_method, image) VALUES (?, ?, ?, ?, ?)`,
            [date, reference, amount, payment_method, imagePath]
        );
        // console.log('Payment saved successfully with ID:', result.insertId);
        res.status(201).json({ message: 'Payment added successfully', id: result.insertId });
    } catch (error) {
        console.error('Error saving payment:', error);
        res.status(500).json({ message: 'Failed to save payment', error: error.message });
    }
});

app.get('/api/payments', async (req, res) => {
    try {
        const [payments] = await db.query(`SELECT * FROM payments ORDER BY date DESC`);
        // console.log('Fetched payments:', payments);
        res.json(payments); // Send payments to the frontend
    } catch (error) {
        console.error('Error fetching payments:', error);
        res.status(500).json({ message: 'Failed to fetch payments', error: error.message });
    }
});

// NEW PURCHASE RETURN
app.post('/api/purchase-returns', authenticate, async (req, res) => {
    const {
        supplier,
        date,
        reference_no,
        payment_status,
        reason
    } = req.body;

    // Validate required fields
    if (!supplier || !date || !reference_no || !payment_status || !reason) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // SQL query to insert new purchase return
        const sql = `
            INSERT INTO purchase_returns (supplier, date, reference_no, payment_status, reason)
            VALUES (?, ?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [supplier, date, reference_no, payment_status, reason]);

        // Send response with new purchase return details
        res.status(201).json({
            id: result.insertId,
            supplier,
            date,
            reference_no,
            payment_status,
            reason
        });
    } catch (err) {
        console.error('Error inserting purchase return:', err.message);
        res.status(500).json({ message: 'Error saving purchase return' });
    }
});

app.get('/api/purchase-returns', authenticate, async (req, res) => {
    try {
        // SQL query to fetch all purchase returns
        const sql = 'SELECT * FROM purchase_returns';
        const [results] = await db.query(sql);

        // Return all the fetched purchase returns
        res.status(200).json(results);
    } catch (err) {
        console.error('Error fetching purchase returns:', err.message);
        res.status(500).json({ message: 'Error fetching purchase returns' });
    }
});

app.put('/api/purchase-returns/:id', authenticate, async (req, res) => {
    const { supplier, date, reference_no, payment_status, reason } = req.body;
    const { id } = req.params;

    if (!supplier || !date || !reference_no || !payment_status || !reason) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const sql = `
            UPDATE purchase_returns 
            SET supplier = ?, date = ?, reference_no = ?, payment_status = ?, reason = ?
            WHERE id = ?
        `;
        const [result] = await db.query(sql, [supplier, date, reference_no, payment_status, reason, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Purchase return not found' });
        }

        res.status(200).json({
            id,
            supplier,
            date,
            reference_no,
            payment_status,
            reason
        });
    } catch (err) {
        console.error('Error updating purchase return:', err.message);
        res.status(500).json({ message: 'Error updating purchase return' });
    }
});

// ADD NEW PURCHASE REPORT
app.post('/api/purchase-report', authenticate, async (req, res) => {
    const { reference_no, paid_on, amount, supplier, payment_method, purchase } = req.body;

    // Validate required fields
    if (!reference_no || !paid_on || !amount || !supplier || !payment_method) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // SQL query to insert new purchase report
        const sql = `
            INSERT INTO purchase_reports (reference_no, paid_on, amount, supplier, payment_method, purchase)
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [reference_no, paid_on, amount, supplier, payment_method, purchase]);

        // Send response with new report details
        res.status(201).json({
            id: result.insertId,
            reference_no,
            paid_on,
            amount,
            supplier,
            payment_method,
            purchase
        });
    } catch (err) {
        console.error('Error inserting purchase report:', err.message);
        res.status(500).json({ message: 'Error saving purchase report' });
    }
});


// Get All Purchase Reports
app.get('/api/purchase-report', authenticate, async (req, res) => {
    try {
        const sql = `SELECT * FROM purchase_reports`;
        const [purchaseReports] = await db.query(sql);

        res.status(200).json({
            message: 'Purchase reports retrieved successfully',
            data: purchaseReports
        });
    } catch (err) {
        console.error('Error fetching purchase reports:', err.message);
        res.status(500).json({ message: 'Error fetching purchase reports' });
    }
});

// Add Sell Payment Report
app.post('/api/sell-payment-report', authenticate, async (req, res) => {
    const { reference_no, paid_on, amount, customer, customer_group, payment_method, sell } = req.body;

    // Validate required fields
    if (!reference_no || !paid_on || !amount || !customer || !customer_group || !payment_method) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // SQL query to insert new sell payment report with customer_group
        const sql = `
            INSERT INTO sell_reports (reference_no, paid_on, amount, customer, customer_group, payment_method, sell)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [reference_no, paid_on, amount, customer, customer_group, payment_method, sell]);

        // Send response with new report details
        res.status(201).json({
            id: result.insertId,
            reference_no,
            paid_on,
            amount,
            customer,
            customer_group,
            payment_method,
            sell
        });
    } catch (err) {
        console.error('Error inserting sell payment report:', err.message);
        res.status(500).json({ message: 'Error saving sell payment report' });
    }
});

// Get All Sell Payment Reports
app.get('/api/sell-payment-report', authenticate, async (req, res) => {
    try {
        const sql = `SELECT * FROM sell_reports`;
        const [sellReports] = await db.query(sql);

        res.status(200).json({
            message: 'Sell reports retrieved successfully',
            data: sellReports
        });
    } catch (err) {
        console.error('Error fetching sell reports:', err.message);
        res.status(500).json({ message: 'Error fetching sell reports' });
    }
});


// Utility function to generate a unique invoice number
function generateInvoiceNo() {
    return 'INV-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
}

// Add Sell Return Report
app.post('/api/list-sell-return', authenticate, async (req, res) => {
    const { date, parent_sale, customer_name, location, payment_status, total_amount, payment_due } = req.body;

    if (!date || !parent_sale || !customer_name || !payment_status || !total_amount) {
        return res.status(400).json({ message: 'Required fields are missing' });
    }

    const invoice_no = generateInvoiceNo();

    try {
        const sql = `
            INSERT INTO list_sell_return (date, invoice_no, parent_sale, customer_name, location, payment_status, total_amount, payment_due)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [date, invoice_no, parent_sale, customer_name, location, payment_status, total_amount, payment_due]);

        res.status(201).json({
            id: result.insertId,
            date,
            invoice_no,
            parent_sale,
            customer_name,
            location,
            payment_status,
            total_amount,
            payment_due
        });
    } catch (err) {
        console.error('Error saving list sell return:', err.message);
        res.status(500).json({ message: 'Error saving list sell return' });
    }
});

// Get All Sell Return Reports
app.get('/api/list-sell-return', authenticate, async (req, res) => {
    try {
        const sql = `SELECT * FROM list_sell_return`;
        const [sellReturnReports] = await db.query(sql);

        res.status(200).json({
            message: 'List sell return retrieved successfully',
            data: sellReturnReports
        });
    } catch (err) {
        console.error('Error fetching list sell return:', err.message);
        res.status(500).json({ message: 'Error fetching sell return reports' });
    }
});

// coupons
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));

// // console.log('Serving static files from:', path.join(__dirname, 'uploads')); 
app.post('/api/coupons', authenticate, upload.single('image'), async (req, res) => {
    const {
        name,
        code,
        discount,
        discount_type,
        start_date,
        end_date,
        min_order_amount,
        max_discount,
        limit_per_user,
        description = 'NA'
    } = req.body;

    // Validate required fields
    if (!name || !code || !discount || !discount_type || !start_date || !end_date || !min_order_amount || !max_discount || !limit_per_user) {
        return res.status(400).json({ message: 'All fields except description are required' });
    }

    // Get the file path from the uploaded file
    const imagePath = req.file ? req.file.path : null;

    // const imagePath = req.file ? `${API_ADMINGRAB_URL}/uploads/${req.file.filename}` : null;

    try {
        // SQL query to insert new coupon with image path
        const sql = `
            INSERT INTO coupons (name, code, discount, discount_type, start_date, end_date, min_order_amount, max_discount, limit_per_user, image_path, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [name, code, discount, discount_type, start_date, end_date, min_order_amount, max_discount, limit_per_user, imagePath, description]);

        // Send response with new coupon details
        res.status(201).json({
            id: result.insertId,
            name,
            code,
            discount,
            discount_type,
            start_date,
            end_date,
            min_order_amount,
            max_discount,
            limit_per_user,
            image: imagePath,
            description
        });
    } catch (err) {
        console.error('Error inserting coupon:', err.message);
        res.status(500).json({ message: 'Error saving coupon' });
    }
});

app.put('/api/coupons/:id', authenticate, upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const {
        name,
        code,
        discount,
        discount_type,
        start_date,
        end_date,
        min_order_amount,
        max_discount,
        limit_per_user,
        description = 'NA'
    } = req.body;

    // Get the new image file path if provided
    const newImagePath = req.file ? req.file.path : null;

    try {
        // Check if the coupon exists in the database
        const checkSql = 'SELECT * FROM coupons WHERE id = ?';
        const [checkResult] = await db.query(checkSql, [id]);

        if (checkResult.length === 0) {
            return res.status(404).json({ message: 'Coupon not found' });
        }

        const existingCoupon = checkResult[0];
        const imagePath = newImagePath || existingCoupon.image_path;

        // SQL query to update the coupon details
        const updateSql = `
            UPDATE coupons 
            SET name = ?, code = ?, discount = ?, discount_type = ?, start_date = ?, end_date = ?, 
                min_order_amount = ?, max_discount = ?, limit_per_user = ?, image_path = ?, description = ?
            WHERE id = ?
        `;

        await db.query(updateSql, [
            name || existingCoupon.name,
            code || existingCoupon.code,
            discount || existingCoupon.discount,
            discount_type || existingCoupon.discount_type,
            start_date || existingCoupon.start_date,
            end_date || existingCoupon.end_date,
            min_order_amount || existingCoupon.min_order_amount,
            max_discount || existingCoupon.max_discount,
            limit_per_user || existingCoupon.limit_per_user,
            imagePath,
            description || existingCoupon.description,
            id
        ]);

        // Send response with updated coupon details
        res.status(200).json({
            id,
            name,
            code,
            discount,
            discount_type,
            start_date,
            end_date,
            min_order_amount,
            max_discount,
            limit_per_user,
            image: imagePath,
            description
        });
    } catch (err) {
        console.error('Error updating coupon:', err.message);
        res.status(500).json({ message: 'Error updating coupon details' });
    }
});


// coupons
app.get('/api/coupons', authenticate, async (req, res) => {
    try {
        // SQL query to select only the required fields
        const sql = `
            SELECT id, name, code, discount, discount_type, start_date, end_date 
            FROM coupons
        `;
        const [rows] = await db.query(sql);

        // Send the results as JSON response
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching coupons:', err.message);
        res.status(500).json({ message: 'Error retrieving coupons' });
    }
});

app.get('/api/coupons/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const sql = `
            SELECT * FROM coupons WHERE id = ?
        `;
        const [rows] = await db.query(sql, [id]);

        const coupon = rows[0];

        // Construct the full image URL
        // coupon.image = coupon.image_path ? `${API_ADMINGRAB_URL}/${coupon.image_path}` : null;

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Coupon not found' });
        }



        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching coupon:', err.message);
        res.status(500).json({ message: 'Error fetching coupon details' });
    }
});

app.delete('/api/coupons/:id', authenticate, async (req, res) => {
    const { id } = req.params; // Get the coupon ID from the URL parameters 

    try {
        // Check if the coupon exists in the database
        const checkSql = 'SELECT * FROM coupons WHERE id = ?';
        const [checkResult] = await db.query(checkSql, [id]);

        if (checkResult.length === 0) {
            return res.status(404).json({ message: 'Coupon not found' });
        }

        // Delete the coupon from the database  
        const deleteSql = 'DELETE FROM coupons WHERE id = ?';
        await db.query(deleteSql, [id]);

        res.status(200).json({ message: 'Coupon deleted successfully' });
    } catch (err) {
        console.error('Error deleting coupon:', err.message);
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/coupons/exportXLS', authenticate, async (req, res) => {
    try {
        // Fetch data from the 'coupons' table
        const results = await db.query('SELECT * FROM coupons');

        // Create a new workbook and worksheet
        const workbook = xlsx.utils.book_new();
        const worksheet = xlsx.utils.json_to_sheet(results);

        // Add worksheet to the workbook
        xlsx.utils.book_append_sheet(workbook, worksheet, 'Coupons');

        // Save the workbook to a temporary file
        const tempFilePath = path.join(__dirname, 'coupons.xlsx');
        xlsx.writeFile(workbook, tempFilePath);

        // Send the file to the client
        res.download(tempFilePath, 'coupons.xlsx', (err) => {
            if (err) {
                console.error('Error downloading file:', err);
            }

            // Delete the temporary file after sending it
            fs.unlink(tempFilePath, (err) => {
                if (err) {
                    console.error('Error deleting temporary file:', err);
                }
            });
        });
    } catch (err) {
        console.error('Error:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});


app.post('/api/damages', authenticate, upload.single('image'), async (req, res) => {
    const {
        date,
        reference_no,
        total,
        note = 'NA'
    } = req.body;

    // Validate required fields
    if (!date || !reference_no || !total) {
        return res.status(400).json({ message: 'Date, Reference No, and Total are required fields' });
    }

    // Get the file path from the uploaded file
    const imagePath = req.file ? req.file.path : null;

    try {
        // SQL query to insert new damage record
        const sql = `
            INSERT INTO damages (date, reference_no, total, image_path, note)
            VALUES (?, ?, ?, ?, ?) 
        `;
        const [result] = await db.query(sql, [date, reference_no, total, imagePath, note]);

        // Send response with new damage record details
        res.status(201).json({
            id: result.insertId,
            date,
            reference_no,
            total,
            image: imagePath,
            note
        });
    } catch (err) {
        console.error('Error inserting damage record:', err.message);
        res.status(500).json({ message: 'Error saving damage record' });
    }
});

app.get('/api/damages', authenticate, async (req, res) => {
    try {
        // SQL query to fetch only the required fields
        const sql = `
            SELECT id, date, reference_no, total, note
            FROM damages
        `;
        const [results] = await db.query(sql);

        // Send the filtered data as the response
        res.status(200).json(results);
    } catch (error) {
        console.error('Error fetching damages data:', error.message);
        res.status(500).json({ message: 'Error fetching damages data' });
    }
});

app.delete('/api/damages/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete the damage record by id
        const sql = `DELETE FROM damages WHERE id = ?`;
        const [result] = await db.query(sql, [id]);

        // Check if the record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Damage record not found' });
        }

        res.status(200).json({ message: 'Damage record deleted successfully' });
    } catch (err) {
        console.error('Error deleting damage record:', err.message);
        res.status(500).json({ message: 'Error deleting damage record' });
    }
});

app.put('/api/damages/:id', authenticate, upload.single('image'), async (req, res) => {
    const { id } = req.params;  // Get the ID from the URL parameter
    const { date, reference_no, total, note = 'NA' } = req.body;

    // Validate required fields
    if (!date || !reference_no || !total) {
        return res.status(400).json({ message: 'Date, Reference No, and Total are required fields' });
    }

    // Get the file path from the uploaded file if a new image is uploaded
    const imagePath = req.file ? req.file.path : null;

    // Build the update query
    let sql = `
        UPDATE damages
        SET date = ?, reference_no = ?, total = ?, note = ?
    `;

    // If a new image is uploaded, include the image path in the query
    if (imagePath) {
        sql += `, image_path = ?`;
    }

    sql += ` WHERE id = ?`;

    try {
        // Prepare the values to update the damage record
        const values = [date, reference_no, total, note];
        if (imagePath) {
            values.push(imagePath);
        }
        values.push(id);  // Add the ID for the WHERE clause 

        // Execute the update query
        const [result] = await db.query(sql, values);

        // Check if the record exists
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Damage record not found' });
        }
        res.status(200).json({
            id,
            date,
            reference_no,
            total,
            image: imagePath || null,
            note
        });

    } catch (err) {
        console.error('Error updating damage record:', err.message);
        res.status(500).json({ message: 'Error updating damage record' });
    }
});

app.get('/api/damages/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        const sql = `SELECT * FROM damages WHERE id = ?`;
        const [rows] = await db.query(sql, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Damage record not found' });
        }

        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching damage record:', error.message);
        res.status(500).json({ message: 'Error fetching damage record' });
    }
});

app.get('/api/damages/exportXLS', authenticate, async (req, res) => {
    try {
        // Fetch data from the 'damages' table
        const results = await db.query('SELECT * FROM damages');

        // Create a new workbook and worksheet
        const workbook = xlsx.utils.book_new();
        const worksheet = xlsx.utils.json_to_sheet(results);

        // Add worksheet to the workbook
        xlsx.utils.book_append_sheet(workbook, worksheet, 'Damages');

        // Save the workbook to a temporary file
        const tempFilePath = path.join(__dirname, 'damages.xlsx');
        xlsx.writeFile(workbook, tempFilePath);

        // Send the file to the client
        res.download(tempFilePath, 'damages.xlsx', (err) => {
            if (err) {
                console.error('Error downloading file:', err);
            }

            // Delete the temporary file after sending it
            fs.unlink(tempFilePath, (err) => {
                if (err) {
                    console.error('Error deleting temporary file:', err);
                }
            });
        });
    } catch (err) {
        console.error('Error:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

app.put('/api/orders/:id/status', async (req, res) => {
    const { status } = req.body;
    const { id } = req.params;

    try {
        const [result] = await db.query(`UPDATE onlineorders SET status = ? WHERE id = ?`, [status, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }

        res.status(200).json({ message: 'Order status updated successfully' });
    } catch (error) {
        console.error('Error updating order status:', error);
        res.status(500).json({ message: 'Failed to update order status', error: error.message });
    }
});
app.get('/api/onlineorders', authenticate, async (req, res) => {
    try {
        const [orders] = await db.query(`SELECT * FROM onlineorders`);
        // console.log("Fetched orders from database:", orders);

        const formattedOrders = orders.map(order => {
            try {
                const parsed = JSON.parse(order.shipping_address);

                // ✅ Build clean formatted address string
                order.shipping_address = [
                    parsed.address,
                    parsed.city,
                    parsed.state,
                    parsed.country,
                    parsed.zip || parsed.zip_code || ""
                ].filter(Boolean).join(', ');

            } catch (err) {
                console.error('❌ Failed to parse address for order:', order.order_id, err);
                order.shipping_address = 'Invalid Address Data';
            }

            order.display_id = order.customer_id || order.guest_id || 'N/A';

            return order;
        });

        res.status(200).json(formattedOrders);
    } catch (error) {
        console.error('❌ Failed to fetch orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders', error: error.message });
    }
});
// Public route: Get order by ID for tracking (no authentication required)
app.get('/api/onlineordertrack/:orderId', async (req, res) => {
    const orderId = req.params.orderId;

    try {
        const [orders] = await db.query(`SELECT * FROM onlineorders WHERE order_id = ?`, [orderId]);

        if (!orders.length) {
            return res.status(404).json({ message: 'Order not found' });
        }

        const order = orders[0];

        try {
            const parsed = JSON.parse(order.shipping_address);

            order.shipping_address = [
                parsed.address,
                parsed.city,
                parsed.state,
                parsed.country,
                parsed.zip || parsed.zip_code || ""
            ].filter(Boolean).join(', ');

        } catch (err) {
            console.error('❌ Failed to parse address for order:', order.order_id, err);
            order.shipping_address = 'Invalid Address Data';
        }

        order.display_id = order.customer_id || order.guest_id || 'N/A';

        res.status(200).json(order);

    } catch (error) {
        console.error('❌ Failed to fetch order:', error);
        res.status(500).json({ message: 'Failed to fetch order', error: error.message });
    }
});
// ali apis tackorder 
app.get('/api/online-order-track-by-email-id', async (req, res) => {
  const { orderId, email } = req.query;

  if (!orderId || !email) {
    return res.status(400).json({ message: 'Both orderId and email are required' });
  }

  try {
    const query = `
      SELECT * FROM onlineorders 
      WHERE order_id = ? 
        AND JSON_UNQUOTE(JSON_EXTRACT(shippingInfo, '$.email')) = ?
    `;
    const [orders] = await db.query(query, [orderId, email]);

    if (!orders.length) {
      return res.status(404).json({ message: 'Order not found' });
    }

    const order = orders[0];

    try {
      const parsed = JSON.parse(order.shipping_address);

      order.shipping_address = [
        parsed.address,
        parsed.city,
        parsed.state,
        parsed.country,
        parsed.zip || parsed.zip_code || ""
      ].filter(Boolean).join(', ');
    } catch (err) {
      console.error('❌ Failed to parse address for order:', order.order_id, err);
      order.shipping_address = 'Invalid Address Data';
    }

    order.display_id = order.customer_id || order.guest_id || 'N/A';

    res.status(200).json(order);

  } catch (error) {
    console.error('❌ Failed to fetch order:', error);
    res.status(500).json({ message: 'Failed to fetch order', error: error.message });
  }
});
// Update order status API
// app.put('/api/onlineorders/:order_id/status', authenticate, async (req, res) => {
//     const { order_id } = req.params;
//     const { order_status } = req.body;

//     const allowedStatuses = [
//         "Received Order",
//         "Inprogress Order",
//         "Ready for Shipment",
//         "On the Way",
//         "Delivered",
//         "On Hold",
//         "Rejected"
//     ];

//     if (!allowedStatuses.includes(order_status)) {
//         return res.status(400).json({ message: "Invalid order status provided." });
//     }

//     try {
//         const [result] = await db.query(
//             "UPDATE onlineorders SET order_status = ? WHERE order_id = ?",
//             [order_status, order_id]
//         );

//         if (result.affectedRows === 0) {
//             return res.status(404).json({ message: "Order not found." });
//         }

//         res.status(200).json({ message: "Order status updated successfully." });
//     } catch (error) {
//         console.error("Error updating status:", error);
//         res.status(500).json({ message: "Failed to update status.", error: error.message });
//     }
// });
app.put('/api/onlineorders/:order_id/status', authenticate, async (req, res) => {
    const { order_id } = req.params;
    const { order_status, rejection_comment } = req.body;

    const allowedStatuses = [
        "Received Order", "Inprogress Order", "Ready for Shipment",
        "On the Way", "Delivered", "On Hold", "Rejected"
    ];

    if (!allowedStatuses.includes(order_status)) {
        return res.status(400).json({ message: "Invalid order status provided." });
    }

    try {
        let query = "";
        let params = [];

        if (order_status === "Rejected") {
            query = "UPDATE onlineorders SET order_status = ?, rejection_comment = ? WHERE order_id = ?";
            params = [order_status, rejection_comment || "Order rejected without comment", order_id];
        } else {
            query = "UPDATE onlineorders SET order_status = ?, rejection_comment = NULL WHERE order_id = ?";
            params = [order_status, order_id];
        }

        // console.log("Running query:", query, "with params:", params); // DEBUG LOG

        const [result] = await db.query(query, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Order not found." });
        }

        res.status(200).json({ message: "Order status updated successfully." });
    } catch (error) {
        console.error("❌ Error updating status:", error);
        res.status(500).json({ message: "Failed to update status.", error: error.message });
    }
});
const allowedPaymentTypes = ['COD', 'Card', 'Bank Transfer'];
app.put('/api/onlineorders/:id/payment-type', async (req, res) => {
    const orderId = req.params.id;
    const { payment_type } = req.body;

    if (!payment_type || !allowedPaymentTypes.includes(payment_type)) {
        return res.status(400).json({ message: 'Invalid payment type' });
    }

    try {
        const [result] = await db.query(
            'UPDATE onlineorders SET payment_type = ? WHERE order_id = ?',
            [payment_type, orderId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }

        res.json({ message: '✅ Payment type updated successfully' });
    } catch (error) {
        console.error('❌ Database Error:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});
// by received orders status apis
app.get('/api/onlineorders/received', authenticate, async (req, res) => {
    try {
        const [orders] = await db.query(`SELECT * FROM onlineorders WHERE order_status = 'Received Order'`);

        const formattedOrders = orders.map(order => {
            try {
                const parsed = JSON.parse(order.shipping_address);
                order.shipping_address = [
                    parsed.address,
                    parsed.city,
                    parsed.state,
                    parsed.country,
                    parsed.zip || parsed.zip_code || ""
                ].filter(Boolean).join(', ');
            } catch (err) {
                console.error('❌ Address parse error for order:', order.order_id, err);
                order.shipping_address = 'Invalid Address Data';
            }

            order.display_id = order.customer_id || order.guest_id || 'N/A';
            return order;
        });

        res.status(200).json(formattedOrders);
    } catch (error) {
        console.error('❌ Error fetching received orders:', error);
        res.status(500).json({ message: 'Failed to fetch received orders', error: error.message });
    }
});
// app.put('/api/onlineorders/update-received-status', authenticate, async (req, res) => {
//     const { new_status } = req.body;

//     const allowedStatuses = [
//         "Received Order",
//         "Inprogress Order",
//         "Ready for Shipment",
//         "On the Way",
//         "Delivered",
//         "On Hold",
//         "Rejected"
//     ];

//     if (!allowedStatuses.includes(new_status)) {
//         return res.status(400).json({ message: "Invalid new status provided." });
//     }

//     try {
//         const [result] = await db.query(
//             "UPDATE onlineorders SET order_status = ? WHERE order_status = 'Received Order'",
//             [new_status]
//         );

//         res.status(200).json({
//             message: `Updated ${result.affectedRows} order(s) from 'Received Order' to '${new_status}'`,
//             updatedCount: result.affectedRows
//         });
//     } catch (error) {
//         console.error("❌ Error updating statuses:", error);
//         res.status(500).json({ message: "Failed to update statuses.", error: error.message });
//     }
// });
// by inprogress orders status apis
app.put('/api/onlineorders/update-received-status', authenticate, async (req, res) => {
    const { new_status, rejection_comment } = req.body;

    const allowedStatuses = [
        "Received Order",
        "Inprogress Order",
        "Ready for Shipment",
        "On the Way",
        "Delivered",
        "On Hold",
        "Rejected"
    ];

    if (!allowedStatuses.includes(new_status)) {
        return res.status(400).json({ message: "Invalid new status provided." });
    }

    try {
        let query = "";
        let params = [];

        if (new_status === "Rejected") {
            query = `
                UPDATE onlineorders 
                SET order_status = ?, 
                    rejection_comment = ?
                WHERE order_status = 'Received Order'
            `;
            params = [new_status, rejection_comment || "Order rejected without comment"];
        } else {
            query = `
                UPDATE onlineorders 
                SET order_status = ?, 
                    rejection_comment = NULL 
                WHERE order_status = 'Received Order'
            `;
            params = [new_status];
        }

        const [result] = await db.query(query, params);

        res.status(200).json({
            message: `Updated ${result.affectedRows} order(s) from 'Received Order' to '${new_status}'`,
            updatedCount: result.affectedRows
        });
    } catch (error) {
        console.error("❌ Error updating statuses:", error);
        res.status(500).json({ message: "Failed to update statuses.", error: error.message });
    }
});
// by inprogress orders status apis 
app.get('/api/onlineorders/inprogress', authenticate, async (req, res) => {
    try {
        const [orders] = await db.query(`SELECT * FROM onlineorders WHERE order_status = 'Inprogress Order'`);

        const formattedOrders = orders.map(order => {
            try {
                const parsed = JSON.parse(order.shipping_address);
                order.shipping_address = [
                    parsed.address,
                    parsed.city,
                    parsed.state,
                    parsed.country,
                    parsed.zip || parsed.zip_code || ""
                ].filter(Boolean).join(', ');
            } catch (err) {
                console.error('❌ Address parse error for order:', order.order_id, err);
                order.shipping_address = 'Invalid Address Data';
            }

            order.display_id = order.customer_id || order.guest_id || 'N/A';
            return order;
        });

        res.status(200).json(formattedOrders);
    } catch (error) {
        console.error('❌ Error fetching inprogress orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders', error: error.message });
    }
});
app.put('/api/onlineorders/update-inprogress-status', authenticate, async (req, res) => {
    const { new_status } = req.body;

    const allowedStatuses = [
        "Received Order",
        "Inprogress Order",
        "Ready for Shipment",
        "On the Way",
        "Delivered",
        "On Hold",
        "Rejected"
    ];

    if (!allowedStatuses.includes(new_status)) {
        return res.status(400).json({ message: "Invalid new status provided." });
    }

    try {
        const [result] = await db.query(
            "UPDATE onlineorders SET order_status = ? WHERE order_status = 'Inprogress Order'",
            [new_status]
        );

        res.status(200).json({
            message: `Updated ${result.affectedRows} order(s) from 'Inprogress Order' to '${new_status}'`,
            updatedCount: result.affectedRows
        });
    } catch (error) {
        console.error("❌ Error updating statuses:", error);
        res.status(500).json({ message: "Failed to update statuses.", error: error.message });
    }
});
// by ready-for-shipment orders status apis 
app.get('/api/onlineorders/ready-for-shipment', authenticate, async (req, res) => {
    try {
        const [orders] = await db.query(`SELECT * FROM onlineorders WHERE order_status = 'Ready for Shipment'`);

        const formattedOrders = orders.map(order => {
            try {
                const parsed = JSON.parse(order.shipping_address);
                order.shipping_address = [
                    parsed.address,
                    parsed.city,
                    parsed.state,
                    parsed.country,
                    parsed.zip || parsed.zip_code || ""
                ].filter(Boolean).join(', ');
            } catch (err) {
                console.error('❌ Address parse error for order:', order.order_id, err);
                order.shipping_address = 'Invalid Address Data';
            }

            order.display_id = order.customer_id || order.guest_id || 'N/A';
            return order;
        });

        res.status(200).json(formattedOrders);
    } catch (error) {
        console.error('❌ Error fetching orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders', error: error.message });
    }
});
app.put('/api/onlineorders/update-ready-status', authenticate, async (req, res) => {
    const { new_status } = req.body;

    const allowedStatuses = [
        "Received Order",
        "Inprogress Order",
        "Ready for Shipment",
        "On the Way",
        "Delivered",
        "On Hold",
        "Rejected"
    ];

    if (!allowedStatuses.includes(new_status)) {
        return res.status(400).json({ message: "Invalid new status provided." });
    }

    try {
        const [result] = await db.query(
            "UPDATE onlineorders SET order_status = ? WHERE order_status = 'Ready for Shipment'",
            [new_status]
        );

        res.status(200).json({
            message: `Updated ${result.affectedRows} order(s) from 'Ready for Shipment' to '${new_status}'`,
            updatedCount: result.affectedRows
        });
    } catch (error) {
        console.error("❌ Error updating statuses:", error);
        res.status(500).json({ message: "Failed to update statuses.", error: error.message });
    }
});
// by On the Way orders status apis 
app.get('/api/onlineorders/on-the-way', authenticate, async (req, res) => {
    try {
        const [orders] = await db.query(`SELECT * FROM onlineorders WHERE order_status = 'On the Way'`);

        const formattedOrders = orders.map(order => {
            try {
                const parsed = JSON.parse(order.shipping_address);
                order.shipping_address = [
                    parsed.address,
                    parsed.city,
                    parsed.state,
                    parsed.country,
                    parsed.zip || parsed.zip_code || ""
                ].filter(Boolean).join(', ');
            } catch (err) {
                console.error('❌ Address parse error for order:', order.order_id, err);
                order.shipping_address = 'Invalid Address Data';
            }

            order.display_id = order.customer_id || order.guest_id || 'N/A';
            return order;
        });

        res.status(200).json(formattedOrders);
    } catch (error) {
        console.error('❌ Failed to fetch "On the Way" orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders', error: error.message });
    }
});
app.put('/api/onlineorders/update-on-the-way-status', authenticate, async (req, res) => {
    const { new_status } = req.body;

    const allowedStatuses = [
        "Received Order",
        "Inprogress Order",
        "Ready for Shipment",
        "On the Way",
        "Delivered",
        "On Hold",
        "Rejected"
    ];

    if (!allowedStatuses.includes(new_status)) {
        return res.status(400).json({ message: "Invalid new status provided." });
    }

    try {
        const [result] = await db.query(
            "UPDATE onlineorders SET order_status = ? WHERE order_status = 'On the Way'",
            [new_status]
        );

        res.status(200).json({
            message: `Updated ${result.affectedRows} order(s) from 'On the Way' to '${new_status}'`,
            updatedCount: result.affectedRows
        });
    } catch (error) {
        console.error("❌ Error updating 'On the Way' statuses:", error);
        res.status(500).json({ message: "Failed to update statuses.", error: error.message });
    }
});
// by Delevered orders status apis 
app.get('/api/onlineorders/delevered', authenticate, async (req, res) => {
    try {
        const [orders] = await db.query(`SELECT * FROM onlineorders WHERE order_status = 'Delivered'`);

        const formattedOrders = orders.map(order => {
            try {
                const parsed = JSON.parse(order.shipping_address);
                order.shipping_address = [
                    parsed.address,
                    parsed.city,
                    parsed.state,
                    parsed.country,
                    parsed.zip || parsed.zip_code || ""
                ].filter(Boolean).join(', ');
            } catch (err) {
                console.error('❌ Address parse error for order:', order.order_id, err);
                order.shipping_address = 'Invalid Address Data';
            }

            order.display_id = order.customer_id || order.guest_id || 'N/A';
            return order;
        });

        res.status(200).json(formattedOrders);
    } catch (error) {
        console.error('❌ Failed to fetch "Delivered" orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders', error: error.message });
    }
});
app.put('/api/onlineorders/update-delevered-status', authenticate, async (req, res) => {
    const { new_status } = req.body;

    const allowedStatuses = [
        "Received Order",
        "Inprogress Order",
        "Ready for Shipment",
        "On the Way",
        "Delivered",
        "On Hold",
        "Rejected"
    ];

    if (!allowedStatuses.includes(new_status)) {
        return res.status(400).json({ message: "Invalid new status provided." });
    }

    try {
        const [result] = await db.query(
            "UPDATE onlineorders SET order_status = ? WHERE order_status = 'Delivered'",
            [new_status]
        );

        res.status(200).json({
            message: `Updated ${result.affectedRows} order(s) from 'Delivered' to '${new_status}'`,
            updatedCount: result.affectedRows
        });
    } catch (error) {
        console.error("❌ Error updating 'Delivered' statuses:", error);
        res.status(500).json({ message: "Failed to update statuses.", error: error.message });
    }
});
// by on-hold orders status apis 
app.get('/api/onlineorders/on-hold', authenticate, async (req, res) => {
    try {
        const [orders] = await db.query(`SELECT * FROM onlineorders WHERE order_status = 'On Hold'`);

        const formattedOrders = orders.map(order => {
            try {
                const parsed = JSON.parse(order.shipping_address);
                order.shipping_address = [
                    parsed.address,
                    parsed.city,
                    parsed.state,
                    parsed.country,
                    parsed.zip || parsed.zip_code || ""
                ].filter(Boolean).join(', ');
            } catch (err) {
                console.error('❌ Address parse error for order:', order.order_id, err);
                order.shipping_address = 'Invalid Address Data';
            }

            order.display_id = order.customer_id || order.guest_id || 'N/A';
            return order;
        });

        res.status(200).json(formattedOrders);
    } catch (error) {
        console.error('❌ Failed to fetch "On Hold" orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders', error: error.message });
    }
});
app.put('/api/onlineorders/update-on-hold-status', authenticate, async (req, res) => {
    const { new_status } = req.body;

    const allowedStatuses = [
        "Received Order",
        "Inprogress Order",
        "Ready for Shipment",
        "On the Way",
        "Delivered",
        "On Hold",
        "Rejected"
    ];

    if (!allowedStatuses.includes(new_status)) {
        return res.status(400).json({ message: "Invalid new status provided." });
    }

    try {
        const [result] = await db.query(
            "UPDATE onlineorders SET order_status = ? WHERE order_status = 'On Hold'",
            [new_status]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "No orders with 'On Hold' status found." });
        }

        res.status(200).json({
            message: `Updated ${result.affectedRows} order(s) from 'On Hold' to '${new_status}'`,
            updatedCount: result.affectedRows
        });
    } catch (error) {
        console.error("❌ Error updating 'On Hold' statuses:", error);
        res.status(500).json({ message: "Failed to update statuses.", error: error.message });
    }
});
// by Rejected orders status apis
app.get('/api/onlineorders/rejected', authenticate, async (req, res) => {
    try {
        const [orders] = await db.query(`SELECT * FROM onlineorders WHERE order_status = 'Rejected'`);

        const formattedOrders = orders.map(order => {
            try {
                const parsed = JSON.parse(order.shipping_address);
                order.shipping_address = [
                    parsed.address,
                    parsed.city,
                    parsed.state,
                    parsed.country,
                    parsed.zip || parsed.zip_code || ""
                ].filter(Boolean).join(', ');
            } catch (err) {
                order.shipping_address = 'Invalid Address Data';
            }

            order.display_id = order.customer_id || order.guest_id || 'N/A';
            return order;
        });

        res.status(200).json(formattedOrders);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch rejected orders', error: error.message });
    }
});
app.put('/api/onlineorders/update-rejected-status', authenticate, async (req, res) => {
    const { new_status } = req.body;

    const allowedStatuses = [
        "Received Order",
        "Inprogress Order",
        "Ready for Shipment",
        "On the Way",
        "Delivered",
        "On Hold",
        "Rejected"
    ];

    if (!allowedStatuses.includes(new_status)) {
        return res.status(400).json({ message: "Invalid status provided." });
    }

    try {
        const [result] = await db.query(
            "UPDATE onlineorders SET order_status = ? WHERE order_status = 'Rejected'",
            [new_status]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "No orders with status 'Rejected' found." });
        }

        res.status(200).json({
            message: `Updated ${result.affectedRows} order(s) from 'Rejected' to '${new_status}'`,
            updatedCount: result.affectedRows
        });
    } catch (error) {
        res.status(500).json({ message: "Failed to update statuses", error: error.message });
    }
});


// Update Order Status
// app.put('/api/online-orders/:order_id/status', authenticate, async (req, res) => {
//     const { status } = req.body;
//     const { order_id } = req.params;

//     try {
//         // Validate status value
//         const validStatuses = ['Pending', 'Confirmed', 'On the Way', 'Delivered'];
//         if (!validStatuses.includes(status)) {
//             return res.status(400).json({ message: 'Invalid status value' });
//         }

//         const [result] = await db.query(
//             `UPDATE onlineorders 
//              SET status = ? 
//              WHERE order_id = ?`,
//             [status, order_id]
//         );

//         if (result.affectedRows === 0) {
//             return res.status(404).json({ message: 'Order not found' });
//         }

//         res.status(200).json({ 
//             message: 'Order status updated successfully',
//             order_id,
//             new_status: status
//         });
//     } catch (error) {
//         console.error('Error updating order status:', error);
//         res.status(500).json({ 
//             message: 'Failed to update order status',
//             error: error.message 
//         });
//     }
// });

// // Get All Online Orders
// app.get('/api/online-orders', authenticate, async (req, res) => {
//     try {
//         const [orders] = await db.query(`
//             SELECT 
//                 order_id,
//                 guest_id,

//                 total_amount,
//                 status,
//                 payment_type,
//                 shipping_address,
//                 created_at,

//             FROM onlineorders
//             ORDER BY created_at DESC
//         `);

//         res.status(200).json(orders);
//     } catch (error) {
//         console.error('Error fetching online orders:', error);
//         res.status(500).json({ 
//             message: 'Failed to fetch online orders',
//             error: error.message 
//         });
//     }
// });
// app.get('/api/orders/items', authenticate, async (req, res) => {
//     try {
//         const [orders] = await db.query(`SELECT * FROM order_items`);
//         res.status(200).json(orders);
//     } catch (error) {
//         console.error('Error fetching orders:', error);
//         res.status(500).json({ message: 'Failed to fetch orders', error: error.message });
//     }
// });

// app.get('/api/orders/:id', async (req, res) => {
//     const { id } = req.params;

//     try {
//         // Fetch order details
//         const [order] = await db.query('SELECT * FROM orders WHERE id = ?', [id]);
//         if (!order.length) return res.status(404).json({ message: 'Order not found' });

//         // Fetch order items
//         const [orderItems] = await db.query('SELECT * FROM order_items WHERE order_id = ?', [id]);

//         res.json({ order: order[0], items: orderItems });
//     } catch (error) {
//         console.error('Error fetching order details:', error);
//         res.status(500).json({ message: 'Error fetching order details', error: error.message });
//     }
// });

// // Update Order Status API
// app.put('/api/orders/:id/status', async (req, res) => {
//     const { id } = req.params;
//     const { status } = req.body;
//     const validStatuses = ['Pending', 'Confirmed', 'On the way', 'Delivered', 'Cancelled'];

// //     if (!validStatuses.includes(status)) {
// //         return res.status(400).json({ message: 'Invalid status value' });
// //     }

// //     try {
// //         await db.query('UPDATE orders SET status = ? WHERE id = ?', [status, id]);
// //         res.json({ message: `Order status updated to ${status}` });
// //     } catch (error) {
// //         console.error('Error updating order status:', error);
// //         res.status(500).json({ message: 'Error updating order status', error: error.message });
// //     }
// // });
// if (!status || !validStatuses.includes(status)) {
//     return res.status(400).json({ message: 'Invalid status value' });
// }

// try {
//     await db.query('UPDATE orders SET status = ? WHERE id = ?', [status, id]);
//     res.json({ message: `Order status updated to ${status}` });
// } catch (error) {
//     console.error('Error updating order status:', error);
//     res.status(500).json({ message: 'Error updating order status', error: error.message });
// }

// });

// Get single order endpoint
app.get('/api/orders/:id', authenticate, async (req, res) => {
    try {
        const [order] = await db.query(`
            SELECT o.*, 
                   GROUP_CONCAT(oi.product_name) as items,
                   GROUP_CONCAT(oi.quantity) as quantities,
                   GROUP_CONCAT(oi.selling_price) as prices
            FROM orders o
            LEFT JOIN orderitems oi ON o.id = oi.order_id
            WHERE o.id = ?
            GROUP BY o.id
        `, [req.params.id]);

        if (order.length === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }

        res.status(200).json(order[0]);
    } catch (error) {
        console.error('Error fetching order:', error);
        res.status(500).json({ message: 'Failed to fetch order', error: error.message });
    }
});
// Update order status endpoint
app.put('/api/orders/:id/status', authenticate, async (req, res) => {
    const { status } = req.body;
    const validStatuses = ['Pending', 'Accepted', 'Cancelled', 'Confirmed', 'On the Way', 'Delivered'];

    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: 'Invalid status value' });
    }

    try {
        await db.query('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);
        res.status(200).json({ message: 'Order status updated successfully' });
    } catch (error) {
        console.error('Error updating order status:', error);
        res.status(500).json({ message: 'Failed to update order status', error: error.message });
    }
});
app.post('/api/products', authenticate, upload.array('images', 4), async (req, res) => {
    try {
        const {
            name,
            slug,
            sku,
            category,
            barcode,
            buying_price,
            selling_price,
            tax,
            brand,
            status,
            can_purchasable,
            show_stock_out,
            refundable,
            max_purchase_quantity,
            low_stock_warning,
            unit,
            weight,
            tags,
            short_description,  // Newly added field
            description,
            offer_price,
            discount,
            specifications,
            details
        } = req.body;

        if (!name || !sku || !buying_price || !selling_price || !category) {
            return res.status(400).json({ error: 'Name, SKU, Buying Price, Selling Price, and Category are required.' });
        }

        const parsedBuyingPrice = parseFloat(buying_price);
        const parsedSellingPrice = parseFloat(selling_price);
        const parsedOfferPrice = offer_price ? parseFloat(offer_price) : null;
        const parsedMaxPurchaseQty = max_purchase_quantity ? parseInt(max_purchase_quantity, 10) : null;
        const parsedLowStockWarning = low_stock_warning ? parseInt(low_stock_warning, 10) : null;

        if (isNaN(parsedBuyingPrice) || isNaN(parsedSellingPrice)) {
            return res.status(400).json({ error: 'Buying Price and Selling Price must be valid numbers.' });
        }

        const categoryId = parseInt(category, 10);
        const [categoryCheck] = await db.query('SELECT id FROM product_categories WHERE id = ?', [categoryId]);
        if (categoryCheck.length === 0) {
            return res.status(400).json({ error: `Category with ID ${categoryId} does not exist.` });
        }

        let brandId;
        if (isNaN(parseInt(brand))) {
            const [brandCheck] = await db.query('SELECT id FROM product_brands WHERE name = ?', [brand]);
            if (brandCheck.length === 0) {
                return res.status(400).json({ error: `Brand ${brand} does not exist.` });
            }
            brandId = brandCheck[0].id;
        } else {
            brandId = parseInt(brand, 10);
            const [brandCheck] = await db.query('SELECT id FROM product_brands WHERE id = ?', [brandId]);
            if (brandCheck.length === 0) {
                return res.status(400).json({ error: `Brand with ID ${brandId} does not exist.` });
            }
        }

        const specString = Array.isArray(specifications) ? JSON.stringify(specifications) : specifications || '';
        const detailsString = Array.isArray(details) ? JSON.stringify(details) : details || '';
        const image_paths = req.files ? req.files.map(file => file.path.replace(/\\/g, '/')) : [];
        const primaryImage = image_paths.length > 0 ? image_paths[0] : null;
        const imagePathsString = JSON.stringify(image_paths);

        const sql = `
            INSERT INTO products (
                name, slug, sku, category, barcode, buying_price,
                selling_price, offer_price, tax, brand, status,
                can_purchasable, show_stock_out, refundable,
                max_purchase_quantity, low_stock_warning, unit,
                weight, tags, short_description, description, image_path, image_paths,
                discount, specifications, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            name, slug || null, sku, categoryId, barcode || null, parsedBuyingPrice,
            parsedSellingPrice, parsedOfferPrice, tax || null, brandId, status || 'Active',
            can_purchasable || 'Yes', show_stock_out || 'Enable', refundable || 'Yes',
            parsedMaxPurchaseQty, parsedLowStockWarning, unit || null,
            weight || null, tags || null, short_description || null, description || null,
            primaryImage, imagePathsString, discount || null, specString, detailsString
        ];

        const [result] = await db.query(sql, values);

        res.status(201).json({ message: 'Product added successfully', productId: result.insertId });
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({ error: 'Failed to add product', details: err.message });
    }
});
app.get('/api/products', async (req, res) => {
    try {
        const sql = `
            SELECT 
                p.id, 
                p.name, 
                p.slug, 
                pc.name AS category_name, 
                pb.name AS brand_name, 
                p.buying_price + 0 AS buying_price, 
                p.selling_price + 0 AS selling_price, 
                p.image_path, 
                p.image_paths,
                p.status ,
                p.short_description
            FROM products p
            LEFT JOIN product_categories pc ON p.category = pc.id
            LEFT JOIN product_brands pb ON p.brand = pb.id
        `;

        const [rows] = await db.query(sql);
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ message: 'Error retrieving products' });
    }
});
// GET - Single Product
// app.get('/api/products/:id', async (req, res) => {
//     const { id } = req.params;

//     try {
//         const [rows] = await db.query('SELECT * FROM products WHERE id = ?', [id]);

//         if (rows.length === 0) {
//             return res.status(404).json({ message: 'Product not found' });
//         }

//         // Parse image_paths if it exists
//         const product = rows[0];
//         if (product.image_paths) {
//             try {
//                 product.image_paths = JSON.parse(product.image_paths);
//             } catch (e) {
//                 // If parsing fails, keep as is (might be comma-separated)
//             }
//         }

//         res.json({ product });
//     } catch (error) {
//         console.error('Error fetching product:', error);
//         res.status(500).json({ message: 'Server error' });
//     }
// });
app.get('/api/products/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await db.query(`
        SELECT 
          p.*, 
          c.name AS category_name, 
          b.name AS brand_name
        FROM products p
        LEFT JOIN product_categories c ON p.category = c.id
        LEFT JOIN product_brands b ON p.brand = b.id
        WHERE p.id = ?
      `, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }

        const product = rows[0];

        // Parse image_paths
        try {
            product.image_paths = product.image_paths ? JSON.parse(product.image_paths) : [];
        } catch {
            product.image_paths = product.image_paths?.split(',') || [];
        }

        // Parse specifications
        try {
            product.specifications = product.specifications ? JSON.parse(product.specifications) : [];
        } catch {
            product.specifications = [];
        }

        // Parse details
        try {
            product.details = product.details ? JSON.parse(product.details) : [];
        } catch {
            product.details = [];
        }

        res.json({ product });

    } catch (error) {
        console.error('Error fetching product:', error);
        res.status(500).json({ message: 'Server error' });
    }
});
// app.put('/api/products/:id', authenticate, upload.single('image'), async (req, res) => {
//     const { id } = req.params;
//     const {
//         name, slug, sku, category, barcode, buying_price, selling_price, tax, brand, status,
//         can_purchasable, show_stock_out, refundable, max_purchase_quantity,
//         low_stock_warning, unit, weight, tags, short_description, description
//     } = req.body;

//     // Validate required fields
//     if (!name || !sku || !buying_price || !selling_price || !category || !brand) {
//         return res.status(400).json({
//             message: 'Name, SKU, Buying Price, Selling Price, Category, and Brand are required fields'
//         });
//     }

//     try {
//         // Convert category and brand to integers to prevent injection
//         const categoryId = parseInt(category, 10);
//         const brandId = parseInt(brand, 10);

//         if (isNaN(categoryId) || isNaN(brandId)) {
//             return res.status(400).json({ message: 'Category and Brand must be valid IDs' });
//         }

//         // Validate category exists
//         const [categoryCheck] = await db.query(`SELECT id FROM product_categories WHERE id = ?`, [categoryId]);
//         if (categoryCheck.length === 0) {
//             return res.status(400).json({ message: 'Invalid category ID' });
//         }

//         // Validate brand exists
//         const [brandCheck] = await db.query(`SELECT id FROM product_brands WHERE id = ?`, [brandId]);
//         if (brandCheck.length === 0) {
//             return res.status(400).json({ message: 'Invalid brand ID' });
//         }

//         // Fetch existing product details
//         const [existingProduct] = await db.query(`SELECT * FROM products WHERE id = ?`, [id]);
//         if (existingProduct.length === 0) {
//             return res.status(404).json({ message: 'Product not found' });
//         }

//         let imagePath = existingProduct[0].image_path;

//         // Handle file upload
//         if (req.file) {
//             if (imagePath && await fs.access(imagePath).then(() => true).catch(() => false)) {
//                 await fs.unlink(imagePath);
//             }
//             imagePath = `uploads/${req.file.filename}`;
//         }

//         // Build the update query
//         let sql = `
//             UPDATE products 
//             SET 
//                 name = ?, 
//                 slug = ?, 
//                 sku = ?, 
//                 category = ?, 
//                 barcode = ?, 
//                 buying_price = ?, 
//                 selling_price = ?, 
//                 tax = ?, 
//                 brand = ?, 
//                 status = ?, 
//                 can_purchasable = ?, 
//                 show_stock_out = ?, 
//                 refundable = ?, 
//                 max_purchase_quantity = ?, 
//                 low_stock_warning = ?, 
//                 unit = ?, 
//                 weight = ?, 
//                 tags = ?, 
//                 short_description = ?,
//                 description = ?
//         `;

//         const values = [
//             name || null,
//             slug || null,
//             sku,
//             categoryId,
//             barcode || null,
//             parseFloat(buying_price) || 0,
//             parseFloat(selling_price) || 0,
//             tax || null,
//             brandId,
//             status || 'Active',
//             can_purchasable || 'Yes',
//             show_stock_out || 'Enable',
//             refundable || 'Yes',
//             parseInt(max_purchase_quantity, 10) || null,
//             parseInt(low_stock_warning, 10) || null,
//             unit || null,
//             weight || null,
//             tags || null,
//             description || null,
//             short_description || null
//         ];

//         if (req.file) {
//             sql += `, image_path = ?`;
//             values.push(imagePath);
//         }

//         sql += ` WHERE id = ?`;
//         values.push(parseInt(id, 10));

//         const [result] = await db.query(sql, values);

//         if (result.affectedRows === 0) {
//             return res.status(404).json({ message: 'Product not found' });
//         }

//         // Fetch updated product for response
//         const [updatedProduct] = await db.query(`SELECT * FROM products WHERE id = ?`, [id]);

//         res.status(200).json({
//             success: true,
//             message: 'Product updated successfully',
//             updatedProduct: updatedProduct[0]
//         });

//     } catch (err) {
//         console.error('Error updating product:', err.message);
//         res.status(500).json({ message: 'Error updating product', error: err.message });
//     }
// });

app.put('/api/products/:id', authenticate, upload.array('images', 4), async (req, res) => {
    const { id } = req.params;
    const {
        name, slug, sku, category, barcode, buying_price, selling_price, tax, brand, status,
        can_purchasable, show_stock_out, refundable, max_purchase_quantity,
        low_stock_warning, unit, weight, tags, short_description, description
    } = req.body;

    if (!name || !sku || !buying_price || !selling_price || !category || !brand) {
        return res.status(400).json({
            message: 'Name, SKU, Buying Price, Selling Price, Category, and Brand are required fields'
        });
    }

    try {
        const categoryId = parseInt(category, 10);
        const brandId = parseInt(brand, 10);

        if (isNaN(categoryId) || isNaN(brandId)) {
            return res.status(400).json({ message: 'Category and Brand must be valid IDs' });
        }

        const [categoryCheck] = await db.query(`SELECT id FROM product_categories WHERE id = ?`, [categoryId]);
        if (categoryCheck.length === 0) {
            return res.status(400).json({ message: 'Invalid category ID' });
        }

        const [brandCheck] = await db.query(`SELECT id FROM product_brands WHERE id = ?`, [brandId]);
        if (brandCheck.length === 0) {
            return res.status(400).json({ message: 'Invalid brand ID' });
        }

        const [existingProduct] = await db.query(`SELECT * FROM products WHERE id = ?`, [id]);
        if (existingProduct.length === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }

        let imagePath = existingProduct[0].image_path;
        let imagePathsArray = [];

        // If new images are uploaded:
        if (req.files && req.files.length > 0) {
            // Optional: delete old images if needed (your choice!)
            // For now: replace with new images

            imagePathsArray = req.files.map(file => file.path.replace(/\\/g, '/'));
            imagePath = imagePathsArray.length > 0 ? imagePathsArray[0] : imagePath;  // first image = primary image
        } else {
            // No new images uploaded → keep existing image_paths
            try {
                imagePathsArray = JSON.parse(existingProduct[0].image_paths || '[]');
            } catch (err) {
                imagePathsArray = [];
            }
        }

        const imagePathsString = JSON.stringify(imagePathsArray);

        // Build SQL query
        const sql = `
            UPDATE products 
            SET 
                name = ?, 
                slug = ?, 
                sku = ?, 
                category = ?, 
                barcode = ?, 
                buying_price = ?, 
                selling_price = ?, 
                tax = ?, 
                brand = ?, 
                status = ?, 
                can_purchasable = ?, 
                show_stock_out = ?, 
                refundable = ?, 
                max_purchase_quantity = ?, 
                low_stock_warning = ?, 
                unit = ?, 
                weight = ?, 
                tags = ?, 
                short_description = ?, 
                description = ?, 
                image_path = ?, 
                image_paths = ?
            WHERE id = ?
        `;

        const values = [
            name || null,
            slug || null,
            sku,
            categoryId,
            barcode || null,
            parseFloat(buying_price) || 0,
            parseFloat(selling_price) || 0,
            tax || null,
            brandId,
            status || 'Active',
            can_purchasable || 'Yes',
            show_stock_out || 'Enable',
            refundable || 'Yes',
            parseInt(max_purchase_quantity, 10) || null,
            parseInt(low_stock_warning, 10) || null,
            unit || null,
            weight || null,
            tags || null,
            short_description || null,
            description || null,
            imagePath,             // primary image
            imagePathsString,      // gallery images array
            parseInt(id, 10)
        ];

        const [result] = await db.query(sql, values);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }

        const [updatedProduct] = await db.query(`SELECT * FROM products WHERE id = ?`, [id]);

        res.status(200).json({
            success: true,
            message: 'Product updated successfully',
            updatedProduct: updatedProduct[0]
        });

    } catch (err) {
        console.error('Error updating product:', err.message);
        res.status(500).json({ message: 'Error updating product', error: err.message });
    }
});
// rating products 
// API to Submit User Rating
app.post('/api/ratings', async (req, res) => {
    const { slug, name, email, rating, review } = req.body;

    try {
        const [productRows] = await db.query('SELECT id FROM products WHERE slug = ?', [slug]);
        if (productRows.length === 0) return res.status(404).json({ message: 'Product not found' });

        const productId = productRows[0].id;
        await db.query(
            `INSERT INTO product_ratings (product_id, name, email, rating, review) VALUES (?, ?, ?, ?, ?)`,
            [productId, name, email, rating, review]
        );

        res.json({ success: true, message: 'Review submitted, pending approval' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error submitting review' });
    }
});

// app.post('/api/ratings', async (req, res) => {
//   const { slug, name, email, rating, review, client_time } = req.body;

//   try {
//     const [productRows] = await db.query('SELECT id FROM products WHERE slug = ?', [slug]);
//     if (productRows.length === 0)
//       return res.status(404).json({ message: 'Product not found' });

//     const productId = productRows[0].id;

//     await db.query(
//       `INSERT INTO product_ratings (product_id, name, email, rating, review, created_at)
//        VALUES (?, ?, ?, ?, ?, ?)`,
//       [productId, name, email, rating, review, client_time]
//     );

//     res.json({ success: true, message: 'Review submitted successfully' });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: 'Error submitting review' });
//   }
// });
//  API to Approve/Reject Rating (Admin) 
app.put('/api/ratings/:id/approve', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body; // 'approved' or 'rejected'

    try {
        await db.query(`UPDATE product_ratings SET approved = ? WHERE id = ?`, [status, id]);
        res.json({ success: true, message: `Review ${status}` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating review status' });
    }
});
// API to Get Approved Ratings by Slug 
app.get('/api/ratings/:slug', async (req, res) => {
    const { slug } = req.params;

    try {
        const [productRows] = await db.query('SELECT id FROM products WHERE slug = ?', [slug]);
        if (productRows.length === 0) return res.status(404).json({ message: 'Product not found' });

        const productId = productRows[0].id;

        const [reviews] = await db.query(
            `SELECT name, rating, review, created_at FROM product_ratings 
             WHERE product_id = ? AND approved = 'approved' 
             ORDER BY created_at DESC`,
            [productId]
        );

        res.json({ success: true, reviews });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching reviews' });
    }
});
// Admin Adds Dummy Rating with All User Information 
app.post('/api/ratings/dummy', async (req, res) => {
    const { slug, name, email, rating, review } = req.body;

    try {
        // Check if the product exists based on the slug
        const [productRows] = await db.query('SELECT id FROM products WHERE slug = ?', [slug]);
        if (productRows.length === 0) return res.status(404).json({ message: 'Product not found' });

        const productId = productRows[0].id;

        // Insert the dummy rating as if it came from an admin but allow full information
        await db.query(
            `INSERT INTO product_ratings (product_id, name, email, rating, review, approved)
             VALUES (?, ?, ?, ?, ?, 'approved')`,
            [productId, name, email, rating, review]
        );

        res.json({ success: true, message: 'Rating added successfully.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error adding dummy rating' });
    }
});
// PUT API to Update Rating
app.put('/api/ratings/:id', async (req, res) => {
    const { id } = req.params;
    const {
        slug,
        name,
        email,
        rating,
        review,
        approved
    } = req.body;

    try {
        // Check if the product exists
        const [productRows] = await db.query('SELECT id FROM products WHERE slug = ?', [slug]);
        if (productRows.length === 0) return res.status(404).json({ message: 'Product not found' });

        const productId = productRows[0].id;

        // Check if the rating exists
        const [ratingRows] = await db.query('SELECT * FROM product_ratings WHERE id = ?', [id]);
        if (ratingRows.length === 0) return res.status(404).json({ message: 'Rating not found' });

        // Update the rating in the database
        await db.query(
            `UPDATE product_ratings
             SET name = ?, email = ?, rating = ?, review = ?, approved = ?, product_id = ?
             WHERE id = ?`,
            [name, email, rating, review, approved, productId, id]
        );

        res.json({ success: true, message: 'Rating updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating rating' });
    }
});
// DELETE API to Delete Rating 
app.delete('/api/ratings/:id', async (req, res) => {
    const { id } = req.params;

    try {
        // Check if the rating exists
        const [ratingRows] = await db.query('SELECT * FROM product_ratings WHERE id = ?', [id]);
        if (ratingRows.length === 0) return res.status(404).json({ message: 'Rating not found' });

        // Delete the rating
        await db.query('DELETE FROM product_ratings WHERE id = ?', [id]);

        res.json({ success: true, message: 'Rating deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error deleting rating' });
    }
});
// GET API to Get All Ratings for a Product 
app.get('/api/ratings/:slug', async (req, res) => {
    const { slug } = req.params;

    try {
        // Check if the product exists
        const [productRows] = await db.query('SELECT id FROM products WHERE slug = ?', [slug]);
        if (productRows.length === 0) return res.status(404).json({ message: 'Product not found' });

        const productId = productRows[0].id;

        // Fetch approved ratings for the product
        const [ratings] = await db.query(
            `SELECT name, email, rating, review, created_at
             FROM product_ratings
             WHERE product_id = ? AND approved = 'approved'
             ORDER BY created_at DESC`,
            [productId]
        );

        res.json({ success: true, ratings });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching ratings' });
    }
});
// GET API to Fetch All Ratings by Product ID (Approved, Pending, or Rejected) 
app.get('/api/ratings/id/:id', async (req, res) => {
    const { id } = req.params;

    try {
        // Check if the product exists based on the provided ID
        const [productRows] = await db.query('SELECT id FROM products WHERE id = ?', [id]);
        if (productRows.length === 0) return res.status(404).json({ message: 'Product not found' });

        // Fetch all ratings (approved, pending, rejected) for the product by ID
        const [ratings] = await db.query(
            `SELECT id, name, email, rating, review, approved, created_at
             FROM product_ratings
             WHERE product_id = ?
             ORDER BY created_at DESC`,
            [id]
        );

        res.json({ success: true, ratings });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching ratings' });
    }
});
//  GET API to Fetch All Ratings (Approved, Pending, or Rejected for All Products) 
app.get('/api/ratings', async (req, res) => {
    try {
        // Fetch all ratings (approved, pending, rejected) for all products
        const [ratings] = await db.query(
            `SELECT r.id, r.product_id, r.name, r.email, r.rating, r.review, r.approved, r.created_at, p.slug
             FROM product_ratings r
             JOIN products p ON r.product_id = p.id
             ORDER BY r.created_at DESC`
        );

        res.json({ success: true, ratings });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching ratings' });
    }
});

// POST: Create a new call request
app.post('/api/call-requests', async (req, res) => {
    const { customer_name, phone_number } = req.body;

    if (!customer_name || !phone_number) {
        return res.status(400).json({ message: 'Customer name and phone number are required' });
    }

    try {
        await db.query(
            `INSERT INTO call_requests (customer_name, phone_number) VALUES (?, ?)`,
            [customer_name, phone_number]
        );

        res.json({ success: true, message: 'Call request submitted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error submitting call request' });
    }
});
// GET: Get all call requests
app.get('/api/call-requests', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM call_requests ORDER BY created_at DESC');
        res.json({ success: true, data: rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching call requests' });
    }
});
// PUT: Update request_type and description
app.put('/api/call-requests/:id', async (req, res) => {
    const { id } = req.params;
    const { request_type, description } = req.body;

    const validTypes = ['Request a call', 'Call Done', 'Spam Call'];
    if (!validTypes.includes(request_type)) {
        return res.status(400).json({ message: 'Invalid request type' });
    }

    try {
        const [result] = await db.query(
            `UPDATE call_requests SET request_type = ?, description = ? WHERE id = ?`,
            [request_type, description, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Call request not found' });
        }

        res.json({ success: true, message: 'Call request updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating call request' });
    }
});
// DELETE: Delete a Call Request  
app.delete('/api/call-requests/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [result] = await db.query(
            `DELETE FROM call_requests WHERE id = ?`,
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Call request not found' });
        }

        res.json({ success: true, message: 'Call request deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error deleting call request' });
    }
});



app.get('/api/purchasing', async (req, res) => {
    try {
        const [products] = await db.query("SELECT name, buying_price FROM products");
        res.json({ products });
    } catch (err) {
        console.error('Error fetching products:', err.message);
        res.status(500).json({ message: 'Error fetching products.', error: err.message });
    }
});


app.post('/api/purchase-products', authenticate, async (req, res) => {
    const { orders, total } = req.body;

    if (!orders || !orders.length) {
        return res.status(400).json({ message: "Orders data is required." });
    }

    if (typeof total !== "number") {
        return res.status(400).json({ message: "Total amount is required and must be a number." });
    }

    try {
        const values = orders.map(order => [
            order.product_name,
            order.unit_cost,
            order.quantity,
            order.discount,
            order.subtotal,
            total // Include the total amount in each row
        ]);

        const sql = `
        INSERT INTO purchase_products (product_name, unit_cost, quantity, discount, subtotal, total)
        VALUES ?
      `;
        await db.query(sql, [values]);

        res.status(201).json({ message: "Orders saved successfully." });
    } catch (err) {
        console.error("Error saving orders:", err.message);
        res.status(500).json({ message: "Error saving orders.", error: err.message });
    }
});

app.get('/api/purchase-products', authenticate, async (req, res) => {
    try {
        const sql = `
        SELECT id, product_name, unit_cost, quantity, discount, subtotal, total, created_at
        FROM purchase_products
      `;

        // Execute the query to fetch purchase products
        const [rows] = await db.query(sql);

        // Send the response with the fetched records
        res.status(200).json({ products: rows });
    } catch (err) {
        console.error("Error fetching purchase products:", err.message);
        res.status(500).json({ message: "Error retrieving purchase products.", error: err.message });
    }
});


app.delete('/api/products/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete a product by ID
        const sql = `
            DELETE FROM products
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [id]);

        // Check if a product was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }

        // Send success response
        res.status(200).json({ message: 'Product deleted successfully' });
    } catch (err) {
        console.error('Error deleting product record:', err.message);
        res.status(500).json({ message: 'Error deleting product record' });
    }
});

app.get('/api/products/exportXLS', authenticate, async (req, res) => {
    try {
        // Fetch data from the 'products' table
        const results = await db.query('SELECT * FROM products');

        // Create a new workbook and worksheet
        const workbook = xlsx.utils.book_new();
        const worksheet = xlsx.utils.json_to_sheet(results);

        // Add worksheet to the workbook
        xlsx.utils.book_append_sheet(workbook, worksheet, 'Products');

        // Save the workbook to a temporary file
        const tempFilePath = path.join(__dirname, 'products.xlsx');
        xlsx.writeFile(workbook, tempFilePath);

        // Send the file to the client
        res.download(tempFilePath, 'products.xlsx', (err) => {
            if (err) {
                console.error('Error downloading file:', err);
            }

            // Delete the temporary file after sending it
            fs.unlink(tempFilePath, (err) => {
                if (err) {
                    console.error('Error deleting temporary file:', err);
                }
            });
        });
    } catch (err) {
        console.error('Error:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});
// API to fetch a product by ID
app.get('/api/products/:id', authenticate, async (req, res) => {
    const productId = req.params.id;

    try {
        // console.log('Fetching product with ID:', productId); // Debug log
        const sql = `SELECT * FROM products WHERE id = ?`;
        const [rows] = await db.query(sql, [productId]);

        if (rows.length === 0) {
            // console.log('No product found for ID:', productId); // Debug log
            return res.status(404).json({ message: 'Product not found' });
        }

        // console.log('Fetched Product:', rows[0]); // Debug log
        res.status(200).json({ product: rows[0] });
    } catch (err) {
        console.error('Error fetching product:', err.message);
        res.status(500).json({ message: 'Error fetching product', error: err.message });
    }
});

// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     let insertedCount = 0;
//     let skippedCount = 0;
//     let errorLogs = [];

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);
//         const totalRows = data.length;

//         const uploadsDir = path.join(__dirname, 'Uploads'); // ✅ corrected path
//         if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

//         const downloadImage = async (url) => {
//             try {
//                 const cleanUrl = String(url || '').trim();
//                 if (!cleanUrl.startsWith('http')) return null;

//                 const ext = path.extname(cleanUrl).split('?')[0] || '.png';
//                 const fileName = Date.now() + '-' + Math.floor(Math.random() * 1000) + ext;
//                 const filePath = path.join(uploadsDir, fileName);

//                 const response = await axios({ url: cleanUrl, method: 'GET', responseType: 'stream' });
//                 await new Promise((resolve, reject) => {
//                     const stream = response.data.pipe(fs.createWriteStream(filePath));
//                     stream.on('finish', resolve);
//                     stream.on('error', reject);
//                 });
//                 return `Uploads/${fileName}`;
//             } catch (err) {
//                 errorLogs.push({ name: 'Image Download Failed', reason: err.message });
//                 return null;
//             }
//         };

//         const productsToInsert = [];

//         for (const row of data) {
//             const name = String(row.Name || '').trim();
//             const sku = String(row.SKU || '').trim();

//             if (!name || !sku) {
//                 skippedCount++;
//                 errorLogs.push({ name: name || 'N/A', reason: 'Missing name or SKU' });
//                 continue;
//             }

//             const [existingProduct] = await db.query('SELECT id FROM products WHERE sku = ? OR name = ?', [sku, name]);
//             if (existingProduct.length > 0) {
//                 skippedCount++;
//                 errorLogs.push({ name, reason: 'Duplicate SKU or Name' });
//                 continue;
//             }

//             let brandId = null;
//             if (row.brand) {
//                 const [existingBrand] = await db.query('SELECT id FROM product_brands WHERE name = ?', [row.brand]);
//                 if (existingBrand.length > 0) {
//                     brandId = existingBrand[0].id;
//                 } else {
//                     const [insertBrand] = await db.query('INSERT INTO product_brands (name, status) VALUES (?, "Active")', [row.brand]);
//                     brandId = insertBrand.insertId;
//                 }
//             }

//             let categoryId = null;
//             let specifications = [], details = [];
//             if (row.category) {
//                 const [existingCategory] = await db.query('SELECT id FROM product_categories WHERE name = ?', [row.category]);
//                 if (existingCategory.length > 0) {
//                     categoryId = existingCategory[0].id;
//                 } else {
//                     let parentId = null;
//                     if (row.parent_category) {
//                         const [parentCat] = await db.query('SELECT id FROM product_categories WHERE name = ?', [row.parent_category]);
//                         if (parentCat.length > 0) parentId = parentCat[0].id;
//                     }
//                     const [insertCategory] = await db.query(
//                         'INSERT INTO product_categories (name, status, specs, parent_category) VALUES (?, "Active", ?, ?)',
//                         [row.category, JSON.stringify(specifications), parentId]
//                     );
//                     categoryId = insertCategory.insertId;
//                 }
//             }

//             try {
//                 if (row.specifications) specifications = JSON.parse(String(row.specifications).replace(/'/g, '"'));
//                 if (row.details) details = JSON.parse(String(row.details).replace(/'/g, '"'));
//             } catch (err) {
//                 errorLogs.push({ name, reason: `JSON parse error: ${err.message}` });
//             }

//             let localImageFilename = '';
//             const localImagePaths = [];

//             const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '') + '-' + Date.now();

//             if (row.image_path) {
//                 const img = await downloadImage(row.image_path);
//                 if (img) localImageFilename = img;
//             }

//             if (row.image_paths) {
//                 const paths = String(row.image_paths).split(',').map(i => i.trim());
//                 for (const url of paths) {
//                     const img = await downloadImage(url);
//                     if (img) localImagePaths.push(img);
//                 }
//             }

//             productsToInsert.push([
//                 sku, slug, categoryId, row.barcode || '', row.buying_price || 0, row.selling_price || 0,
//                 row.offer_price || 0, row.tax || 'VAT-1', brandId, 'Active', 'Yes', 'Enable', 'Yes',
//                 row.max_purchase_quantity || 10, row.low_stock_warning || 5, row.unit || 'unit',
//                 row.weight || 0, row.tags || '',
//                 row.short_description || '',
//                 row.description || '',
//                 localImageFilename,
//                 localImagePaths.length ? JSON.stringify(localImagePaths) : '[]',
//                 row.discount || 0,
//                 JSON.stringify(specifications),
//                 JSON.stringify(details),
//                 name
//             ]);

//             insertedCount++;
//         }

//         if (productsToInsert.length) {
//             await db.query(`
//           INSERT INTO products (
//             sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//             status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//             weight, tags, short_description, description, image_path, image_paths, discount,
//             specifications, details, name
//           ) VALUES ?`, [productsToInsert]);
//         }

//         fs.unlinkSync(req.file.path);

//         res.json({
//             message: 'Excel import completed.',
//             totalRows,
//             inserted: insertedCount,
//             skipped: skippedCount,
//             errors: errorLogs
//         });

//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
//         res.status(500).json({ error: 'Error processing Excel file' });
//     }
// });

// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     let insertedCount = 0;
//     let skippedCount = 0;
//     let errorLogs = [];

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);
//         const totalRows = data.length;

//         const uploadsDir = path.join(__dirname, 'Uploads');
//         if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

//         // ... [keep the existing downloadImage function and other setup code] ...

//         const productsToInsert = [];

//         for (const row of data) {
//             // ... [keep existing name/sku validation and duplicate checking] ...

//             // ... [keep existing brand handling code] ...

//             let categoryId = null;
//             let specifications = [];
//             let details = [];

//             // Process specifications (keep existing code)
//             try {
//                 if (row.specifications) {
//                     const specsString = String(row.specifications).trim();
//                     if (specsString.startsWith('[') && specsString.endsWith(']')) {
//                         specifications = JSON.parse(specsString.replace(/<br\s*\/?>/g, '\n'));
//                     } else {
//                         specifications = specsString.split(',').map(item => item.trim());
//                     }
//                 }
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Specifications parse error: ${err.message}` });
//             }

//             // NEW IMPROVED DETAILS PROCESSING
//             try {
//                 if (row.details) {
//                     let detailsString = String(row.details).trim();

//                     // Handle the specific format from your Excel file
//                     if (detailsString.startsWith('[') && detailsString.endsWith(']')) {
//                         // Clean up the string - remove HTML tags and fix quotes
//                         detailsString = detailsString
//                             .replace(/<br\s*\/?>/gi, '') // Remove <br> tags
//                             .replace(/\\"/g, '"')        // Fix escaped quotes
//                             .replace(/'/g, '"')          // Replace single quotes with double
//                             .replace(/(\w)"(\w)/g, '$1\\"$2'); // Fix words with quotes between them

//                         try {
//                             details = JSON.parse(detailsString);
//                         } catch (parseError) {
//                             // If JSON parsing fails, try to fix common issues
//                             detailsString = detailsString
//                                 .replace(/,\s*]/g, ']')  // Remove trailing commas
//                                 .replace(/,\s*$/g, '')   // Remove trailing commas
//                                 .replace(/"\s*,\s*"/g, '","'); // Ensure proper comma separation

//                             try {
//                                 details = JSON.parse(detailsString);
//                             } catch (finalError) {
//                                 // If still fails, treat as comma-separated values
//                                 details = detailsString
//                                     .slice(1, -1) // Remove brackets
//                                     .split(',')
//                                     .map(item => item.trim().replace(/^"(.*)"$/, '$1'));
//                             }
//                         }
//                     } else {
//                         // If not in array format, treat as single value
//                         details = [detailsString];
//                     }

//                     // Ensure we always have an array
//                     if (!Array.isArray(details)) {
//                         details = [details];
//                     }

//                     // Clean each detail item
//                     details = details.map(item =>
//                         String(item)
//                             .replace(/<br\s*\/?>/gi, '\n')
//                             .replace(/\\"/g, '"')
//                             .trim()
//                     );
//                 }
//             } catch (err) {
//                 console.error('Details processing error:', err);
//                 errorLogs.push({ name, reason: `Details parse error: ${err.message}` });
//                 details = []; // Fallback to empty array
//             }

//             // ... [keep existing category handling code] ...

//             // ... [keep existing image handling code] ...

//             // Prepare product data for insertion
//             productsToInsert.push([
//                 sku, slug, categoryId, row.barcode || '', row.buying_price || 0, row.selling_price || 0,
//                 row.offer_price || 0, row.tax || 'VAT-1', brandId, 'Active', 'Yes', 'Enable', 'Yes',
//                 row.max_purchase_quantity || 10, row.low_stock_warning || 5, row.unit || 'unit',
//                 row.weight || 0, row.tags || '',
//                 row.short_description || '',
//                 row.description || '',
//                 localImageFilename,
//                 localImagePaths.length ? JSON.stringify(localImagePaths) : '[]',
//                 row.discount || 0,
//                 JSON.stringify(specifications),
//                 JSON.stringify(details), // This will now properly store the details
//                 name
//             ]);

//             insertedCount++;
//         }

//         if (productsToInsert.length) {
//             await db.query(`
//                 INSERT INTO products (
//                     sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//                     status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//                     weight, tags, short_description, description, image_path, image_paths, discount,
//                     specifications, details, name
//                 ) VALUES ?`, [productsToInsert]);
//         }

//         fs.unlinkSync(req.file.path);

//         res.json({
//             message: 'Excel import completed.',
//             totalRows,
//             inserted: insertedCount,
//             skipped: skippedCount,
//             errors: errorLogs
//         });

//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
//         res.status(500).json({ error: 'Error processing Excel file' });
//     }
// });
// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     let insertedCount = 0;
//     let skippedCount = 0;
//     let errorLogs = [];

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);
//         const totalRows = data.length;

//         const productsToInsert = [];

//         for (const row of data) {
//             // Normalize keys to lowercase
//             const normalizedRow = {};
//             Object.keys(row).forEach(key => {
//                 normalizedRow[key.toLowerCase()] = row[key];
//             });

//             const sku = String(normalizedRow.sku || '').trim();
//             const name = String(normalizedRow.name || '').trim();
//             const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');

//             if (!sku || !name) {
//                 skippedCount++;
//                 errorLogs.push({ name: sku || 'Unnamed', reason: 'Missing SKU or name' });
//                 continue;
//             }

//             // === BRAND HANDLING ===
//             let brandId = null;
//             const brandName = normalizedRow.brand?.trim();
//             if (brandName) {
//                 const [brand] = await db.query('SELECT id FROM product_brands WHERE name = ?', [brandName]);
//                 if (brand.length > 0) {
//                     brandId = brand[0].id;
//                 } else {
//                     const result = await db.query('INSERT INTO product_brands (name, status) VALUES (?, ?)', [brandName, 'Active']);
//                     brandId = result[0].insertId;
//                 }
//             }

//             // === CATEGORY HANDLING ===
//             let categoryId = null;
//             const categoryName = normalizedRow.category?.trim();
//             if (categoryName) {
//                 const [category] = await db.query('SELECT id FROM product_categories WHERE name = ?', [categoryName]);
//                 if (category.length > 0) {
//                     categoryId = category[0].id;
//                 } else {
//                     const result = await db.query('INSERT INTO product_categories (name, status) VALUES (?, ?)', [categoryName, 'Active']);
//                     categoryId = result[0].insertId;
//                 }
//             }

//             // === SPECIFICATIONS HANDLING ===
//             let specifications = [];
//             try {
//                 if (normalizedRow.specifications) {
//                     const specsString = String(normalizedRow.specifications).trim();
//                     specifications = specsString.startsWith('[')
//                         ? JSON.parse(specsString.replace(/<br\s*\/?>/g, '\n'))
//                         : specsString.split(',').map(item => item.trim());
//                 }
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Specifications parse error: ${err.message}` });
//             }

//             // === DETAILS HANDLING ===
//             let details = [];
//             try {
//                 if (normalizedRow.details) {
//                     let detailsString = String(normalizedRow.details).trim();
//                     if (detailsString.startsWith('[')) {
//                         detailsString = detailsString
//                             .replace(/<br\s*\/?>/gi, '')
//                             .replace(/\\"/g, '"')
//                             .replace(/'/g, '"')
//                             .replace(/(\w)"(\w)/g, '$1\\"$2');
//                         try {
//                             details = JSON.parse(detailsString);
//                         } catch {
//                             detailsString = detailsString
//                                 .replace(/,\s*]/g, ']')
//                                 .replace(/,\s*$/g, '')
//                                 .replace(/"\s*,\s*"/g, '","');
//                             try {
//                                 details = JSON.parse(detailsString);
//                             } catch {
//                                 details = detailsString.slice(1, -1).split(',').map(i => i.trim().replace(/^"(.*)"$/, '$1'));
//                             }
//                         }
//                     } else {
//                         details = [detailsString];
//                     }
//                     details = details.map(d => String(d).replace(/<br\s*\/?>/gi, '\n').replace(/\\"/g, '"').trim());
//                 }
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Details parse error: ${err.message}` });
//             }

//             // === IMAGE PLACEHOLDER ===
//             const localImageFilename = ''; // You can assign filename if you're handling image
//             const localImagePaths = [];

//             // === INSERT DATA PREP ===
//             productsToInsert.push([
//                 sku, slug, categoryId, normalizedRow.barcode || '', normalizedRow.buying_price || 0,
//                 normalizedRow.selling_price || 0, normalizedRow.offer_price || 0, normalizedRow.tax || 'VAT-1',
//                 brandId, 'Active', 'Yes', 'Enable', 'Yes', normalizedRow.max_purchase_quantity || 10,
//                 normalizedRow.low_stock_warning || 5, normalizedRow.unit || 'unit', normalizedRow.weight || 0,
//                 normalizedRow.tags || '', normalizedRow.short_description || '', normalizedRow.description || '',
//                 localImageFilename, JSON.stringify(localImagePaths), normalizedRow.discount || 0,
//                 JSON.stringify(specifications), JSON.stringify(details), name
//             ]);

//             insertedCount++;
//         }

//         if (productsToInsert.length) {
//             await db.query(`
//                 INSERT INTO products (
//                     sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//                     status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//                     weight, tags, short_description, description, image_path, image_paths, discount,
//                     specifications, details, name
//                 ) VALUES ?`, [productsToInsert]);
//         }

//         fs.unlinkSync(req.file.path);

//         res.json({
//             message: 'Excel import completed.',
//             totalRows,
//             inserted: insertedCount,
//             skipped: skippedCount,
//             errors: errorLogs
//         });

//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
//         res.status(500).json({ error: 'Error processing Excel file' });
//     }
// });
// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     let insertedCount = 0;
//     let skippedCount = 0;
//     let errorLogs = [];

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);
//         const totalRows = data.length;

//         const productsToInsert = [];

//         for (const row of data) {
//             // Normalize headers to lowercase
//             const normalizedRow = {};
//             Object.keys(row).forEach(key => {
//                 normalizedRow[key.toLowerCase()] = row[key];
//             });

//             const sku = String(normalizedRow.sku || '').trim();
//             const name = String(normalizedRow.name || '').trim();
//             const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');

//             if (!sku || !name) {
//                 skippedCount++;
//                 errorLogs.push({ name: sku || 'Unnamed', reason: 'Missing SKU or name' });
//                 continue;
//             }

//             // === BRAND HANDLING ===
//             let brandId = null;
//             const brandName = normalizedRow.brand?.trim();
//             if (brandName) {
//                 const [brand] = await db.query('SELECT id FROM product_brands WHERE name = ?', [brandName]);
//                 if (brand.length > 0) {
//                     brandId = brand[0].id;
//                 } else {
//                     const result = await db.query(
//                         'INSERT INTO product_brands (name, status) VALUES (?, ?)',
//                         [brandName, 'Active']
//                     );
//                     brandId = result[0].insertId;
//                 }
//             }

//             // === CATEGORY HANDLING ===
//             let categoryId = null;
//             const categoryName = normalizedRow.category?.trim();
//             if (categoryName) {
//                 const [category] = await db.query('SELECT id FROM product_categories WHERE name = ?', [categoryName]);
//                 if (category.length > 0) {
//                     categoryId = category[0].id;
//                 } else {
//                     const result = await db.query(
//                         'INSERT INTO product_categories (name, status) VALUES (?, ?)',
//                         [categoryName, 'Active']
//                     );
//                     categoryId = result[0].insertId;
//                 }
//             }

//             // === SPECIFICATIONS ===
//             let specifications = [];
//             try {
//                 if (normalizedRow.specifications) {
//                     const specsString = String(normalizedRow.specifications).trim();
//                     if (specsString.startsWith('[')) {
//                         specifications = JSON.parse(specsString.replace(/<br\s*\/?>/g, '\n'));
//                     } else {
//                         specifications = specsString.split(',').map(i => i.trim());
//                     }
//                 }
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Specifications parse error: ${err.message}` });
//             }

//             // === DETAILS ===
//             let details = [];
//             try {
//                 if (normalizedRow.details) {
//                     let detailsString = String(normalizedRow.details).trim();
//                     if (detailsString.startsWith('[')) {
//                         detailsString = detailsString
//                             .replace(/<br\s*\/?>/gi, '')
//                             .replace(/\\"/g, '"')
//                             .replace(/'/g, '"')
//                             .replace(/(\w)"(\w)/g, '$1\\"$2');
//                         try {
//                             details = JSON.parse(detailsString);
//                         } catch {
//                             detailsString = detailsString
//                                 .replace(/,\s*]/g, ']')
//                                 .replace(/,\s*$/g, '')
//                                 .replace(/"\s*,\s*"/g, '","');
//                             try {
//                                 details = JSON.parse(detailsString);
//                             } catch {
//                                 details = detailsString.slice(1, -1).split(',').map(i => i.trim().replace(/^"(.*)"$/, '$1'));
//                             }
//                         }
//                     } else {
//                         details = [detailsString];
//                     }
//                     details = details.map(d => String(d).replace(/<br\s*\/?>/gi, '\n').replace(/\\"/g, '"').trim());
//                 }
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Details parse error: ${err.message}` });
//                 details = [];
//             }

//             // === IMAGE PLACEHOLDER ===
//             const localImageFilename = ''; // You can extend image upload logic
//             const localImagePaths = [];

//             // === Final Row Insert ===
//             productsToInsert.push([
//                 sku,
//                 slug,
//                 categoryId,
//                 normalizedRow.barcode || '',
//                 normalizedRow.buying_price || 0,
//                 normalizedRow.selling_price || 0,
//                 normalizedRow.offer_price || 0,
//                 normalizedRow.tax || 'VAT-1',
//                 brandId,
//                 'Active',
//                 'Yes',
//                 'Enable',
//                 'Yes',
//                 normalizedRow.max_purchase_quantity || 10,
//                 normalizedRow.low_stock_warning || 5,
//                 normalizedRow.unit || 'unit',
//                 normalizedRow.weight || 0,
//                 normalizedRow.tags || '',
//                 normalizedRow.short_description || '',
//                 normalizedRow.description || '',
//                 localImageFilename,
//                 JSON.stringify(localImagePaths),
//                 normalizedRow.discount || 0,
//                 JSON.stringify(specifications),
//                 JSON.stringify(details),
//                 name
//             ]);

//             insertedCount++;
//         }

//         // === Final Insert Query ===
//         if (productsToInsert.length) {
//             await db.query(`
//                 INSERT INTO products (
//                     sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//                     status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//                     weight, tags, short_description, description, image_path, image_paths, discount,
//                     specifications, details, name
//                 ) VALUES ?`, [productsToInsert]);
//         }

//         fs.unlinkSync(req.file.path);

//         res.json({
//             message: 'Excel import completed.',
//             totalRows,
//             inserted: insertedCount,
//             skipped: skippedCount,
//             errors: errorLogs
//         });

//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
//         res.status(500).json({ error: 'Error processing Excel file' });
//     }
// });
// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     let insertedCount = 0;
//     let skippedCount = 0;
//     let errorLogs = [];

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);
//         const totalRows = data.length;

//         const productsToInsert = [];

//         for (const row of data) {
//             const normalizedRow = {};
//             Object.keys(row).forEach(key => {
//                 normalizedRow[key.toLowerCase()] = row[key];
//             });

//             const sku = String(normalizedRow.sku || '').trim();
//             const name = String(normalizedRow.name || '').trim();
//             const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');

//             if (!sku || !name) {
//                 skippedCount++;
//                 errorLogs.push({ name: sku || 'Unnamed', reason: 'Missing SKU or name' });
//                 continue;
//             }

//             // === BRAND HANDLING ===
//             let brandId = null;
//             const brandName = normalizedRow.brand?.trim();
//             if (brandName) {
//                 const [brand] = await db.query('SELECT id FROM product_brands WHERE name = ?', [brandName]);
//                 if (brand.length > 0) {
//                     brandId = brand[0].id;
//                 } else {
//                     const result = await db.query(
//                         'INSERT INTO product_brands (name, status) VALUES (?, ?)',
//                         [brandName, 'Active']
//                     );
//                     brandId = result[0].insertId;
//                 }
//             }

//             // === CATEGORY HANDLING ===
//             let categoryId = null;
//             const categoryName = normalizedRow.category?.trim();
//             if (categoryName) {
//                 const [category] = await db.query('SELECT id FROM product_categories WHERE name = ?', [categoryName]);
//                 if (category.length > 0) {
//                     categoryId = category[0].id;
//                 } else {
//                     const result = await db.query(
//                         'INSERT INTO product_categories (name, status) VALUES (?, ?)',
//                         [categoryName, 'Active']
//                     );
//                     categoryId = result[0].insertId;
//                 }
//             }

//             // ✅ Skip if product with same name + slug + category + brand exists
//             const [existing] = await db.query(
//                 'SELECT id FROM products WHERE name = ? AND slug = ? AND category = ? AND brand = ?',
//                 [name, slug, categoryId, brandId]
//             );
//             if (existing.length > 0) {
//                 skippedCount++;
//                 errorLogs.push({
//                     name,
//                     reason: 'Product with same name, slug, category, and brand already exists'
//                 });
//                 continue;
//             }

//             // === SPECIFICATIONS ===
//             let specifications = [];
//             try {
//                 if (normalizedRow.specifications) {
//                     const specsString = String(normalizedRow.specifications).trim();
//                     if (specsString.startsWith('[')) {
//                         specifications = JSON.parse(specsString.replace(/<br\s*\/?>/g, '\n'));
//                     } else {
//                         specifications = specsString.split(',').map(item => item.trim());
//                     }
//                 }
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Specifications parse error: ${err.message}` });
//             }

//             // === DETAILS ===
//             let details = [];
//             try {
//                 if (normalizedRow.details) {
//                     let detailsString = String(normalizedRow.details).trim();
//                     if (detailsString.startsWith('[')) {
//                         detailsString = detailsString
//                             .replace(/<br\s*\/?>/gi, '')
//                             .replace(/\\"/g, '"')
//                             .replace(/'/g, '"')
//                             .replace(/(\w)"(\w)/g, '$1\\"$2');
//                         try {
//                             details = JSON.parse(detailsString);
//                         } catch {
//                             detailsString = detailsString
//                                 .replace(/,\s*]/g, ']')
//                                 .replace(/,\s*$/g, '')
//                                 .replace(/"\s*,\s*"/g, '","');
//                             try {
//                                 details = JSON.parse(detailsString);
//                             } catch {
//                                 details = detailsString.slice(1, -1).split(',').map(i => i.trim().replace(/^"(.*)"$/, '$1'));
//                             }
//                         }
//                     } else {
//                         details = [detailsString];
//                     }
//                     details = details.map(d => String(d).replace(/<br\s*\/?>/gi, '\n').replace(/\\"/g, '"').trim());
//                 }
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Details parse error: ${err.message}` });
//                 details = [];
//             }

//             // === IMAGE PLACEHOLDER ===
//             const localImageFilename = '';
//             const localImagePaths = [];

//             // === FINAL PRODUCT ROW PREPARATION ===
//             productsToInsert.push([
//                 sku,
//                 slug,
//                 categoryId,
//                 normalizedRow.barcode || '',
//                 normalizedRow.buying_price || 0,
//                 normalizedRow.selling_price || 0,
//                 normalizedRow.offer_price || 0,
//                 normalizedRow.tax || 'VAT-1',
//                 brandId,
//                 'Active',
//                 'Yes',
//                 'Enable',
//                 'Yes',
//                 normalizedRow.max_purchase_quantity || 10,
//                 normalizedRow.low_stock_warning || 5,
//                 normalizedRow.unit || 'unit',
//                 normalizedRow.weight || 0,
//                 normalizedRow.tags || '',
//                 normalizedRow.short_description || '',
//                 normalizedRow.description || '',
//                 localImageFilename,
//                 JSON.stringify(localImagePaths),
//                 normalizedRow.discount || 0,
//                 JSON.stringify(specifications),
//                 JSON.stringify(details),
//                 name
//             ]);

//             insertedCount++;
//         }

//         // === BULK INSERT ===
//         if (productsToInsert.length > 0) {
//             await db.query(`
//                 INSERT INTO products (
//                     sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//                     status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//                     weight, tags, short_description, description, image_path, image_paths, discount,
//                     specifications, details, name
//                 ) VALUES ?`, [productsToInsert]);
//         }

//         fs.unlinkSync(req.file.path);

//         res.json({
//             message: 'Excel import completed.',
//             totalRows,
//             inserted: insertedCount,
//             skipped: skippedCount,
//             errors: errorLogs
//         });

//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
//         res.status(500).json({ error: err.message }); // ✅ full error in response
//     }
// });

// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     let insertedCount = 0;
//     let skippedCount = 0;
//     let errorLogs = [];

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);
//         const totalRows = data.length;
//         const productsToInsert = [];

//         const downloadImage = async (url) => {
//             try {
//                 const response = await axios.get(url, { responseType: 'stream' });
//                 const ext = path.extname(url).split('?')[0] || '.png'; // Ensure extension
//                 const filename = `${uuidv4()}${ext}`;
//                 const filepath = path.join('Uploads', filename);

//                 const writer = fs.createWriteStream(filepath);
//                 response.data.pipe(writer);
//                 await new Promise((resolve, reject) => {
//                     writer.on('finish', resolve);
//                     writer.on('error', reject);
//                 });
//                 return filename;
//             } catch (err) {
//                 errorLogs.push({ reason: `Image download failed: ${err.message}` });
//                 return null;
//             }
//         };

//         for (const row of data) {
//             const normalizedRow = {};
//             Object.keys(row).forEach(key => {
//                 normalizedRow[key.toLowerCase()] = row[key];
//             });

//             const sku = String(normalizedRow.sku || '').trim();
//             const name = String(normalizedRow.name || '').trim();
//             const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');

//             if (!sku || !name) {
//                 skippedCount++;
//                 errorLogs.push({ name: sku || 'Unnamed', reason: 'Missing SKU or name' });
//                 continue;
//             }

//             // Brand Handling
//             let brandId = null;
//             const brandName = normalizedRow.brand?.trim();
//             if (brandName) {
//                 const [brand] = await db.query('SELECT id FROM product_brands WHERE name = ?', [brandName]);
//                 if (brand.length > 0) {
//                     brandId = brand[0].id;
//                 } else {
//                     const result = await db.query(
//                         'INSERT INTO product_brands (name, status) VALUES (?, ?)',
//                         [brandName, 'Active']
//                     );
//                     brandId = result[0].insertId;
//                 }
//             }

//             // Parent Category Handling
//             let categoryId = null;
//             const categoryName = normalizedRow.category?.trim();
//             let parentCategoryId = null;
//             const parentCategoryName = normalizedRow.parent_category?.trim();

//             if (parentCategoryName) {
//                 const [parentCat] = await db.query('SELECT id FROM product_categories WHERE name = ?', [parentCategoryName]);
//                 if (parentCat.length > 0) {
//                     parentCategoryId = parentCat[0].id;
//                 }
//             }

//             if (categoryName) {
//                 const [category] = await db.query('SELECT id FROM product_categories WHERE name = ?', [categoryName]);
//                 if (category.length > 0) {
//                     categoryId = category[0].id;
//                 } else {
//                     const result = await db.query(
//                         'INSERT INTO product_categories (name, status, parent_category) VALUES (?, ?, ?)',
//                         [categoryName, 'Active', parentCategoryId]
//                     );
//                     categoryId = result[0].insertId;
//                 }
//             }

//             // Duplicate Check
//             const [existing] = await db.query(
//                 'SELECT id FROM products WHERE name = ? AND slug = ? AND category = ? AND brand = ?',
//                 [name, slug, categoryId, brandId]
//             );
//             if (existing.length > 0) {
//                 skippedCount++;
//                 errorLogs.push({
//                     name,
//                     reason: 'Product with same name, slug, category, and brand already exists'
//                 });
//                 continue;
//             }

//             // Specifications Parsing
//             let specifications = [];
//             try {
//                 const specsString = String(normalizedRow.specifications || '').trim();
//                 if (specsString.startsWith('[')) {
//                     specifications = JSON.parse(specsString.replace(/<br\s*\/?>/g, '\n'));
//                 } else if (specsString) {
//                     specifications = specsString.split(',').map(item => item.trim());
//                 }
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Specifications parse error: ${err.message}` });
//             }

//             // Details Parsing
//             let details = [];
//             try {
//                 let detailsString = String(normalizedRow.details || '').trim();
//                 if (detailsString.startsWith('[')) {
//                     detailsString = detailsString.replace(/<br\s*\/?>/gi, '').replace(/\\"/g, '"').replace(/'/g, '"').replace(/(\w)"(\w)/g, '$1\\"$2');
//                     try {
//                         details = JSON.parse(detailsString);
//                     } catch {
//                         details = detailsString.replace(/,\s*]/g, ']').replace(/,\s*$/, '').replace(/"\s*,\s*"/g, '","').slice(1, -1).split(',').map(i => i.trim().replace(/^"(.*)"$/, '$1'));
//                     }
//                 } else if (detailsString) {
//                     details = [detailsString];
//                 }
//                 details = details.map(d => String(d).replace(/<br\s*\/?>/gi, '\n').replace(/\\"/g, '"').trim());
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Details parse error: ${err.message}` });
//                 details = [];
//             }

//             // Image Handling
//             let localImageFilename = '';
//             const localImagePaths = [];

//             if (normalizedRow.image_path) {
//                 const file = await downloadImage(normalizedRow.image_path);
//                 if (file) localImageFilename = `Uploads/${file}`;
//             }

//             if (normalizedRow.image_paths) {
//                 try {
//                     const paths = JSON.parse(normalizedRow.image_paths);
//                     const downloadPromises = paths.map(async (url) => {
//                         const file = await downloadImage(url);
//                         if (file) localImagePaths.push(`Uploads/${file}`);
//                     });
//                     await Promise.all(downloadPromises);
//                 } catch (err) {
//                     errorLogs.push({ name, reason: `Image paths parse error: ${err.message}` });
//                 }
//             }

//             // Final Product Data
//             productsToInsert.push([
//                 sku,
//                 slug,
//                 categoryId,
//                 normalizedRow.barcode || '',
//                 normalizedRow.buying_price || 0,
//                 normalizedRow.selling_price || 0,
//                 normalizedRow.offer_price || 0,
//                 normalizedRow.tax || 'VAT-1',
//                 brandId,
//                 'Active',
//                 'Yes',
//                 'Enable',
//                 'Yes',
//                 normalizedRow.max_purchase_quantity || 10,
//                 normalizedRow.low_stock_warning || 5,
//                 normalizedRow.unit || 'unit',
//                 normalizedRow.weight || 0,
//                 normalizedRow.tags || '',
//                 normalizedRow.short_description || '',
//                 normalizedRow.description || '',
//                 localImageFilename,
//                 JSON.stringify(localImagePaths),
//                 normalizedRow.discount || 0,
//                 JSON.stringify(specifications),
//                 JSON.stringify(details),
//                 name
//             ]);

//             insertedCount++;
//         }

//         if (productsToInsert.length > 0) {
//             await db.query(`
//                 INSERT INTO products (
//                     sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//                     status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//                     weight, tags, short_description, description, image_path, image_paths, discount,
//                     specifications, details, name
//                 ) VALUES ?`, [productsToInsert]);
//         }

//         fs.unlinkSync(req.file.path);

//         res.json({
//             message: 'Excel import completed.',
//             totalRows,
//             inserted: insertedCount,
//             skipped: skippedCount,
//             errors: errorLogs
//         });

//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
//         res.status(500).json({ error: err.message });
//     }
// });

// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     let insertedCount = 0;
//     let skippedCount = 0;
//     let errorLogs = [];

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);
//         const totalRows = data.length;
//         const productsToInsert = [];

//         const downloadImage = async (url) => {
//             try {
//                 const response = await axios.get(url, { responseType: 'stream' });
//                 const ext = path.extname(url).split('?')[0] || '.png';
//                 const filename = `${uuidv4()}${ext}`;
//                 const filepath = path.join('Uploads', filename);

//                 const writer = fs.createWriteStream(filepath);
//                 response.data.pipe(writer);
//                 await new Promise((resolve, reject) => {
//                     writer.on('finish', resolve);
//                     writer.on('error', reject);
//                 });
//                 return filename;
//             } catch (err) {
//                 errorLogs.push({ reason: `Image download failed: ${err.message}` });
//                 return null;
//             }
//         };

//         // Function to handle category creation with image
//         const handleCategory = async (categoryName, parentCategoryName = null) => {
//             if (!categoryName) return null;

//             // Check if category already exists
//             const [existingCategory] = await db.query(
//                 'SELECT id, image FROM product_categories WHERE name = ?', 
//                 [categoryName]
//             );

//             let categoryId = existingCategory.length > 0 ? existingCategory[0].id : null;
//             let categoryImage = existingCategory.length > 0 ? existingCategory[0].image : null;

//             // Handle parent category
//             let parentCategoryId = null;
//             if (parentCategoryName) {
//                 const [parentCat] = await db.query(
//                     'SELECT id FROM product_categories WHERE name = ?', 
//                     [parentCategoryName]
//                 );
//                 if (parentCat.length > 0) {
//                     parentCategoryId = parentCat[0].id;
//                 } else {
//                     // Create parent category if it doesn't exist
//                     const [newParent] = await db.query(
//                         'INSERT INTO product_categories (name, status) VALUES (?, ?)',
//                         [parentCategoryName, 'Active']
//                     );
//                     parentCategoryId = newParent[0].insertId;
//                 }
//             }

//             // If category doesn't exist, create it
//             if (!categoryId) {
//                 // Download category image (if you want to associate an image with new categories)
//                 // You would need to have a way to get the image URL for the category
//                 // For now, we'll just create the category without an image
//                 const [newCategory] = await db.query(
//                     'INSERT INTO product_categories (name, status, parent_category) VALUES (?, ?, ?)',
//                     [categoryName, 'Active', parentCategoryId]
//                 );
//                 categoryId = newCategory[0].insertId;
//             }

//             return categoryId;
//         };

//         for (const row of data) {
//             const normalizedRow = {};
//             Object.keys(row).forEach(key => {
//                 normalizedRow[key.toLowerCase()] = row[key];
//             });

//             const sku = String(normalizedRow.sku || '').trim();
//             const name = String(normalizedRow.name || '').trim();
//             const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');

//             if (!sku || !name) {
//                 skippedCount++;
//                 errorLogs.push({ name: sku || 'Unnamed', reason: 'Missing SKU or name' });
//                 continue;
//             }

//             // Brand Handling
//             let brandId = null;
//             const brandName = normalizedRow.brand?.trim();
//             if (brandName) {
//                 const [brand] = await db.query('SELECT id FROM product_brands WHERE name = ?', [brandName]);
//                 if (brand.length > 0) {
//                     brandId = brand[0].id;
//                 } else {
//                     const result = await db.query(
//                         'INSERT INTO product_brands (name, status) VALUES (?, ?)',
//                         [brandName, 'Active']
//                     );
//                     brandId = result[0].insertId;
//                 }
//             }

//             // Category Handling with parent category
//             const categoryName = normalizedRow.category?.trim();
//             const parentCategoryName = normalizedRow.parent_category?.trim();
//             const categoryId = await handleCategory(categoryName, parentCategoryName);

//             // Duplicate Check
//             const [existing] = await db.query(
//                 'SELECT id FROM products WHERE name = ? AND slug = ? AND category = ? AND brand = ?',
//                 [name, slug, categoryId, brandId]
//             );
//             if (existing.length > 0) {
//                 skippedCount++;
//                 errorLogs.push({
//                     name,
//                     reason: 'Product with same name, slug, category, and brand already exists'
//                 });
//                 continue;
//             }

//             // Specifications Parsing
//             let specifications = [];
//             try {
//                 const specsString = String(normalizedRow.specifications || '').trim();
//                 if (specsString.startsWith('[')) {
//                     specifications = JSON.parse(specsString.replace(/<br\s*\/?>/g, '\n'));
//                 } else if (specsString) {
//                     specifications = specsString.split(',').map(item => item.trim());
//                 }
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Specifications parse error: ${err.message}` });
//             }

//             // Details Parsing
//             let details = [];
//             try {
//                 let detailsString = String(normalizedRow.details || '').trim();
//                 if (detailsString.startsWith('[')) {
//                     detailsString = detailsString.replace(/<br\s*\/?>/gi, '').replace(/\\"/g, '"').replace(/'/g, '"').replace(/(\w)"(\w)/g, '$1\\"$2');
//                     try {
//                         details = JSON.parse(detailsString);
//                     } catch {
//                         details = detailsString.replace(/,\s*]/g, ']').replace(/,\s*$/, '').replace(/"\s*,\s*"/g, '","').slice(1, -1).split(',').map(i => i.trim().replace(/^"(.*)"$/, '$1'));
//                     }
//                 } else if (detailsString) {
//                     details = [detailsString];
//                 }
//                 details = details.map(d => String(d).replace(/<br\s*\/?>/gi, '\n').replace(/\\"/g, '"').trim());
//             } catch (err) {
//                 errorLogs.push({ name, reason: `Details parse error: ${err.message}` });
//                 details = [];
//             }

//             // Image Handling
//             let localImageFilename = '';
//             const localImagePaths = [];

//             if (normalizedRow.image_path) {
//                 const file = await downloadImage(normalizedRow.image_path);
//                 if (file) localImageFilename = `Uploads/${file}`;
//             }

//             if (normalizedRow.image_paths) {
//                 try {
//                     const paths = Array.isArray(normalizedRow.image_paths) 
//                         ? normalizedRow.image_paths 
//                         : normalizedRow.image_paths.split(',').map(p => p.trim());

//                     const downloadPromises = paths.map(async (url) => {
//                         const file = await downloadImage(url);
//                         if (file) localImagePaths.push(`Uploads/${file}`);
//                     });
//                     await Promise.all(downloadPromises);
//                 } catch (err) {
//                     errorLogs.push({ name, reason: `Image paths parse error: ${err.message}` });
//                 }
//             }

//             // Final Product Data
//             productsToInsert.push([
//                 sku,
//                 slug,
//                 categoryId,
//                 normalizedRow.barcode || '',
//                 normalizedRow.buying_price || 0,
//                 normalizedRow.selling_price || 0,
//                 normalizedRow.offer_price || 0,
//                 normalizedRow.tax || 'VAT-1',
//                 brandId,
//                 'Active',
//                 'Yes',
//                 'Enable',
//                 'Yes',
//                 normalizedRow.max_purchase_quantity || 10,
//                 normalizedRow.low_stock_warning || 5,
//                 normalizedRow.unit || 'unit',
//                 normalizedRow.weight || 0,
//                 normalizedRow.tags || '',
//                 normalizedRow.short_description || '',
//                 normalizedRow.description || '',
//                 localImageFilename,
//                 JSON.stringify(localImagePaths),
//                 normalizedRow.discount || 0,
//                 JSON.stringify(specifications),
//                 JSON.stringify(details),
//                 name
//             ]);

//             insertedCount++;
//         }

//         if (productsToInsert.length > 0) {
//             await db.query(`
//                 INSERT INTO products (
//                     sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//                     status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//                     weight, tags, short_description, description, image_path, image_paths, discount,
//                     specifications, details, name
//                 ) VALUES ?`, [productsToInsert]);
//         }

//         fs.unlinkSync(req.file.path);

//         res.json({
//             message: 'Excel import completed.',
//             totalRows,
//             inserted: insertedCount,
//             skipped: skippedCount,
//             errors: errorLogs
//         });

//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
//         res.status(500).json({ error: err.message });
//     }
// });
// if (!fs.existsSync('Uploads')) {
//   fs.mkdirSync('Uploads');
// }
// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//   if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//   let insertedCount = 0;
//   let skippedCount = 0;
//   let errorLogs = [];

//   try {
//     const workbook = xlsx.readFile(req.file.path);
//     const sheet = workbook.Sheets[workbook.SheetNames[0]];
//     const data = xlsx.utils.sheet_to_json(sheet);
//     const totalRows = data.length;
//     const productsToInsert = [];

//     // Improved image download function
//     const downloadImage = async (url) => {
//       try {
//         if (!url || typeof url !== 'string' || !url.startsWith('http')) {
//           throw new Error('Invalid URL');
//         }

//         const cleanUrl = url.split('?')[0]; // Remove query parameters
//         const ext = path.extname(cleanUrl) || '.png';
//         const filename = `${Date.now()}${ext}`;
//         const filepath = path.join('Uploads', filename);

//         const response = await axios({
//           method: 'get',
//           url: url,
//           responseType: 'stream',
//           timeout: 10000
//         });

//         const writer = fs.createWriteStream(filepath);
//         response.data.pipe(writer);

//         await new Promise((resolve, reject) => {
//           writer.on('finish', resolve);
//           writer.on('error', (err) => {
//             fs.unlinkSync(filepath); // Clean up if write fails
//             reject(err);
//           });
//         });

//         return filename; // Return just the filename
//       } catch (err) {
//         console.error(`Failed to download image from ${url}:`, err.message);
//         errorLogs.push({ reason: `Image download failed for ${url}: ${err.message}` });
//         return null;
//       }
//     };

//     // Updated category handling with proper error handling
//     const handleCategory = async (categoryName, parentCategoryName = null) => {
//       if (!categoryName) return null;

//       try {
//         // Check if category exists
//         const [existingCategories] = await db.query(
//           'SELECT id FROM product_categories WHERE name = ?', 
//           [categoryName]
//         );

//         let categoryId = existingCategories.length > 0 ? existingCategories[0].id : null;

//         // Handle parent category
//         let parentCategoryId = null;
//         if (parentCategoryName) {
//           const [parentCategories] = await db.query(
//             'SELECT id FROM product_categories WHERE name = ?', 
//             [parentCategoryName]
//           );

//           if (parentCategories.length > 0) {
//             parentCategoryId = parentCategories[0].id;
//           } else {
//             const [parentInsertResult] = await db.query(
//               'INSERT INTO product_categories (name, status) VALUES (?, ?)',
//               [parentCategoryName, 'Active']
//             );

//             if (!parentInsertResult || !parentInsertResult.insertId) {
//               throw new Error('Failed to create parent category');
//             }
//             parentCategoryId = parentInsertResult.insertId;
//           }
//         }

//         // Create category if it doesn't exist
//         if (!categoryId) {
//           const [categoryInsertResult] = await db.query(
//             'INSERT INTO product_categories (name, status, parent_category) VALUES (?, ?, ?)',
//             [categoryName, 'Active', parentCategoryId]
//           );

//           if (!categoryInsertResult || !categoryInsertResult.insertId) {
//             throw new Error('Failed to create category');
//           }
//           categoryId = categoryInsertResult.insertId;
//         }

//         return categoryId;
//       } catch (err) {
//         console.error(`Error handling category ${categoryName}:`, err);
//         errorLogs.push({ reason: `Category handling error: ${err.message}` });
//         return null;
//       }
//     };

//     for (const row of data) {
//       try {
//         const normalizedRow = {};
//         Object.keys(row).forEach(key => {
//           normalizedRow[key.toLowerCase()] = row[key];
//         });

//         const sku = String(normalizedRow.sku || '').trim();
//         const name = String(normalizedRow.name || '').trim();
//         const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');

//         if (!sku || !name) {
//           skippedCount++;
//           errorLogs.push({ name: sku || 'Unnamed', reason: 'Missing SKU or name' });
//           continue;
//         }

//         // Brand Handling with proper error handling
//         let brandId = null;
//         const brandName = normalizedRow.brand?.trim();
//         if (brandName) {
//           try {
//             const [brands] = await db.query('SELECT id FROM product_brands WHERE name = ?', [brandName]);
//             if (brands.length > 0) {
//               brandId = brands[0].id;
//             } else {
//               const [brandInsertResult] = await db.query(
//                 'INSERT INTO product_brands (name, status) VALUES (?, ?)',
//                 [brandName, 'Active']
//               );

//               if (!brandInsertResult || !brandInsertResult.insertId) {
//                 throw new Error('Failed to create brand');
//               }
//               brandId = brandInsertResult.insertId;
//             }
//           } catch (err) {
//             console.error(`Error handling brand ${brandName}:`, err);
//             errorLogs.push({ name, reason: `Brand handling error: ${err.message}` });
//             continue;
//           }
//         }

//         // Category Handling
//         const categoryName = normalizedRow.category?.trim();
//         const parentCategoryName = normalizedRow.parent_category?.trim();
//         const categoryId = await handleCategory(categoryName, parentCategoryName);

//         if (!categoryId) {
//           skippedCount++;
//           errorLogs.push({ name, reason: 'Invalid category' });
//           continue;
//         }

//         // Duplicate Check
//         try {
//           const [existingProducts] = await db.query(
//             'SELECT id FROM products WHERE name = ? AND slug = ? AND category = ? AND brand = ?',
//             [name, slug, categoryId, brandId]
//           );
//           if (existingProducts.length > 0) {
//             skippedCount++;
//             errorLogs.push({
//               name,
//               reason: 'Product with same name, slug, category, and brand already exists'
//             });
//             continue;
//           }
//         } catch (err) {
//           console.error(`Error checking for duplicates for ${name}:`, err);
//           errorLogs.push({ name, reason: `Duplicate check error: ${err.message}` });
//           continue;
//         }

//         // Specifications Parsing
//         let specifications = [];
//         try {
//           const specsString = String(normalizedRow.specifications || '').trim();
//           if (specsString.startsWith('[')) {
//             specifications = JSON.parse(specsString.replace(/<br\s*\/?>/g, '\n'));
//           } else if (specsString) {
//             specifications = specsString.split(',').map(item => item.trim());
//           }
//         } catch (err) {
//           errorLogs.push({ name, reason: `Specifications parse error: ${err.message}` });
//         }

//         // Details Parsing
//         let details = [];
//         try {
//           let detailsString = String(normalizedRow.details || '').trim();
//           if (detailsString.startsWith('[')) {
//             detailsString = detailsString.replace(/<br\s*\/?>/gi, '').replace(/\\"/g, '"').replace(/'/g, '"').replace(/(\w)"(\w)/g, '$1\\"$2');
//             try {
//               details = JSON.parse(detailsString);
//             } catch {
//               details = detailsString.replace(/,\s*]/g, ']').replace(/,\s*$/, '').replace(/"\s*,\s*"/g, '","').slice(1, -1).split(',').map(i => i.trim().replace(/^"(.*)"$/, '$1'));
//             }
//           } else if (detailsString) {
//             details = [detailsString];
//           }
//           details = details.map(d => String(d).replace(/<br\s*\/?>/gi, '\n').replace(/\\"/g, '"').trim());
//         } catch (err) {
//           errorLogs.push({ name, reason: `Details parse error: ${err.message}` });
//           details = [];
//         }

//         // Image Handling
//         let mainImageFilename = '';
//         const additionalImageFilenames = [];

//         if (normalizedRow.image_path) {
//           const file = await downloadImage(normalizedRow.image_path.trim());
//           if (file) mainImageFilename = file;
//         }

//         if (normalizedRow.image_paths) {
//           try {
//             const paths = Array.isArray(normalizedRow.image_paths) 
//               ? normalizedRow.image_paths 
//               : normalizedRow.image_paths.split(',').map(p => p.trim());

//             const downloadPromises = paths.map(url => downloadImage(url));
//             const downloadedFiles = await Promise.all(downloadPromises);
//             additionalImageFilenames.push(...downloadedFiles.filter(file => file !== null));
//           } catch (err) {
//             errorLogs.push({ name, reason: `Image paths processing error: ${err.message}` });
//           }
//         }

//         // Final Product Data
//         productsToInsert.push([
//           sku,
//           slug,
//           categoryId,
//           normalizedRow.barcode || '',
//           normalizedRow.buying_price || 0,
//           normalizedRow.selling_price || 0,
//           normalizedRow.offer_price || 0,
//           normalizedRow.tax || 'VAT-1',
//           brandId,
//           'Active',
//           'Yes',
//           'Enable',
//           'Yes',
//           normalizedRow.max_purchase_quantity || 10,
//           normalizedRow.low_stock_warning || 5,
//           normalizedRow.unit || 'unit',
//           normalizedRow.weight || 0,
//           normalizedRow.tags || '',
//           normalizedRow.short_description || '',
//           normalizedRow.description || '',
//           mainImageFilename,
//           JSON.stringify(additionalImageFilenames),
//           normalizedRow.discount || 0,
//           JSON.stringify(specifications),
//           JSON.stringify(details),
//           name
//         ]);

//         insertedCount++;
//       } catch (err) {
//         console.error(`Error processing row:`, err);
//         errorLogs.push({ name: normalizedRow.name || 'Unknown', reason: `Row processing error: ${err.message}` });
//         skippedCount++;
//       }
//     }

//     if (productsToInsert.length > 0) {
//       try {
//         const [insertResult] = await db.query(`
//           INSERT INTO products (
//             sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//             status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//             weight, tags, short_description, description, image_path, image_paths, discount,
//             specifications, details, name
//           ) VALUES ?`, [productsToInsert]);

//         if (!insertResult || !insertResult.affectedRows) {
//           throw new Error('Failed to insert products');
//         }
//       } catch (err) {
//         console.error('Error inserting products:', err);
//         throw err; // This will be caught by the outer try-catch
//       }
//     }

//     fs.unlinkSync(req.file.path);

//     res.json({
//       message: 'Excel import completed.',
//       totalRows,
//       inserted: insertedCount,
//       skipped: skippedCount,
//       errors: errorLogs
//     });

//   } catch (err) {
//     console.error('❌ Upload Error:', err);
//     if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
//     res.status(500).json({ 
//       error: err.message,
//       details: process.env.NODE_ENV === 'development' ? err.stack : undefined
//     });
//   }
// });

if (!fs.existsSync('Uploads')) {
    fs.mkdirSync('Uploads');
}

app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    let insertedCount = 0;
    let skippedCount = 0;
    let errorLogs = [];

    try {
        const workbook = xlsx.readFile(req.file.path);
        const sheet = workbook.Sheets[workbook.SheetNames[0]];
        const data = xlsx.utils.sheet_to_json(sheet);
        const totalRows = data.length;
        const productsToInsert = [];

        const downloadImage = async (url) => {
            try {
                if (!url || typeof url !== 'string' || !url.startsWith('http')) {
                    throw new Error('Invalid URL');
                }

                const cleanUrl = url.split('?')[0];
                const ext = path.extname(cleanUrl) || '.png';
                const filename = `${Date.now()}${ext}`;
                const filepath = path.join('Uploads', filename);

                const response = await axios({
                    method: 'get',
                    url: url,
                    responseType: 'stream',
                    timeout: 10000
                });

                const writer = fs.createWriteStream(filepath);
                response.data.pipe(writer);

                await new Promise((resolve, reject) => {
                    writer.on('finish', resolve);
                    writer.on('error', (err) => {
                        fs.unlinkSync(filepath);
                        reject(err);
                    });
                });

                return filename;
            } catch (err) {
                console.error(`Failed to download image from ${url}:`, err.message);
                errorLogs.push({ reason: `Image download failed for ${url}: ${err.message}` });
                return null;
            }
        };

        const handleCategory = async (categoryName, parentCategoryName = null) => {
            if (!categoryName) return null;

            try {
                const [existingCategories] = await db.query(
                    'SELECT id FROM product_categories WHERE name = ?',
                    [categoryName]
                );

                let categoryId = existingCategories.length > 0 ? existingCategories[0].id : null;

                let parentCategoryId = null;
                if (parentCategoryName) {
                    const [parentCategories] = await db.query(
                        'SELECT id FROM product_categories WHERE name = ?',
                        [parentCategoryName]
                    );

                    if (parentCategories.length > 0) {
                        parentCategoryId = parentCategories[0].id;
                    } else {
                        const [parentInsertResult] = await db.query(
                            'INSERT INTO product_categories (name, status) VALUES (?, ?)',
                            [parentCategoryName, 'Active']
                        );

                        if (!parentInsertResult || !parentInsertResult.insertId) {
                            throw new Error('Failed to create parent category');
                        }
                        parentCategoryId = parentInsertResult.insertId;
                    }
                }

                if (!categoryId) {
                    const [categoryInsertResult] = await db.query(
                        'INSERT INTO product_categories (name, status, parent_category) VALUES (?, ?, ?)',
                        [categoryName, 'Active', parentCategoryId]
                    );

                    if (!categoryInsertResult || !categoryInsertResult.insertId) {
                        throw new Error('Failed to create category');
                    }
                    categoryId = categoryInsertResult.insertId;
                }

                return categoryId;
            } catch (err) {
                console.error(`Error handling category ${categoryName}:`, err);
                errorLogs.push({ reason: `Category handling error: ${err.message}` });
                return null;
            }
        };

        for (const row of data) {
            try {
                const normalizedRow = {};
                Object.keys(row).forEach(key => {
                    normalizedRow[key.toLowerCase()] = row[key];
                });

                const sku = String(normalizedRow.sku || '').trim();
                const name = String(normalizedRow.name || '').trim();
                const slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');

                if (!sku || !name) {
                    skippedCount++;
                    errorLogs.push({ name: sku || 'Unnamed', reason: 'Missing SKU or name' });
                    continue;
                }

                let brandId = null;
                const brandName = normalizedRow.brand?.trim();
                if (brandName) {
                    try {
                        const [brands] = await db.query('SELECT id FROM product_brands WHERE name = ?', [brandName]);
                        if (brands.length > 0) {
                            brandId = brands[0].id;
                        } else {
                            const [brandInsertResult] = await db.query(
                                'INSERT INTO product_brands (name, status) VALUES (?, ?)',
                                [brandName, 'Active']
                            );

                            if (!brandInsertResult || !brandInsertResult.insertId) {
                                throw new Error('Failed to create brand');
                            }
                            brandId = brandInsertResult.insertId;
                        }
                    } catch (err) {
                        console.error(`Error handling brand ${brandName}:`, err);
                        errorLogs.push({ name, reason: `Brand handling error: ${err.message}` });
                        continue;
                    }
                }

                const categoryName = normalizedRow.category?.trim();
                const parentCategoryName = normalizedRow.parent_category?.trim();
                const categoryId = await handleCategory(categoryName, parentCategoryName);

                if (!categoryId) {
                    skippedCount++;
                    errorLogs.push({ name, reason: 'Invalid category' });
                    continue;
                }

                try {
                    const [existingProducts] = await db.query(
                        'SELECT id FROM products WHERE name = ? AND slug = ? AND category = ? AND brand = ?',
                        [name, slug, categoryId, brandId]
                    );
                    if (existingProducts.length > 0) {
                        skippedCount++;
                        errorLogs.push({
                            name,
                            reason: 'Product with same name, slug, category, and brand already exists'
                        });
                        continue;
                    }
                } catch (err) {
                    console.error(`Error checking for duplicates for ${name}:`, err);
                    errorLogs.push({ name, reason: `Duplicate check error: ${err.message}` });
                    continue;
                }

                let specifications = [];
                try {
                    const specsString = String(normalizedRow.specifications || '').trim();
                    if (specsString.startsWith('[')) {
                        specifications = JSON.parse(specsString.replace(/<br\s*\/?>/g, '\n'));
                    } else if (specsString) {
                        specifications = specsString.split(',').map(item => item.trim());
                    }
                } catch (err) {
                    errorLogs.push({ name, reason: `Specifications parse error: ${err.message}` });
                }

                let details = [];
                try {
                    let detailsString = String(normalizedRow.details || '').trim();
                    if (detailsString.startsWith('[')) {
                        detailsString = detailsString.replace(/<br\s*\/?>/gi, '').replace(/\\"/g, '"').replace(/'/g, '"').replace(/(\w)"(\w)/g, '$1\\"$2');
                        try {
                            details = JSON.parse(detailsString);
                        } catch {
                            details = detailsString.replace(/,\s*]/g, ']').replace(/,\s*$/, '').replace(/"\s*,\s*"/g, '","').slice(1, -1).split(',').map(i => i.trim().replace(/^"(.*)"$/, '$1'));
                        }
                    } else if (detailsString) {
                        details = [detailsString];
                    }
                    details = details.map(d => String(d).replace(/<br\s*\/?>/gi, '\n').replace(/\\"/g, '"').trim());
                } catch (err) {
                    errorLogs.push({ name, reason: `Details parse error: ${err.message}` });
                    details = [];
                }

                let mainImagePath = '';
                const additionalImagePaths = [];

                if (normalizedRow.image_path) {
                    const filename = await downloadImage(normalizedRow.image_path.trim());
                    if (filename) {
                        mainImagePath = `Uploads/${filename}`;
                    }
                }

                if (normalizedRow.image_paths) {
                    try {
                        const paths = Array.isArray(normalizedRow.image_paths)
                            ? normalizedRow.image_paths
                            : normalizedRow.image_paths.split(',').map(p => p.trim());

                        const downloadPromises = paths.map(url => downloadImage(url));
                        const downloadedFiles = await Promise.all(downloadPromises);

                        additionalImagePaths.push(
                            ...downloadedFiles
                                .filter(file => file !== null)
                                .map(file => `Uploads/${file}`)
                        );
                    } catch (err) {
                        errorLogs.push({ name, reason: `Image paths processing error: ${err.message}` });
                    }
                }

                productsToInsert.push([
                    sku,
                    slug,
                    categoryId,
                    normalizedRow.barcode || '',
                    normalizedRow.buying_price || 0,
                    normalizedRow.selling_price || 0,
                    normalizedRow.offer_price || 0,
                    normalizedRow.tax || 'VAT-1',
                    brandId,
                    'Active',
                    'Yes',
                    'Enable',
                    'Yes',
                    normalizedRow.max_purchase_quantity || 10,
                    normalizedRow.low_stock_warning || 5,
                    normalizedRow.unit || 'unit',
                    normalizedRow.weight || 0,
                    normalizedRow.tags || '',
                    normalizedRow.short_description || '',
                    normalizedRow.description || '',
                    mainImagePath,
                    JSON.stringify(additionalImagePaths),
                    normalizedRow.discount || 0,
                    JSON.stringify(specifications),
                    JSON.stringify(details),
                    name
                ]);

                insertedCount++;
            } catch (err) {
                console.error(`Error processing row:`, err);
                errorLogs.push({ name: normalizedRow.name || 'Unknown', reason: `Row processing error: ${err.message}` });
                skippedCount++;
            }
        }

        if (productsToInsert.length > 0) {
            try {
                const [insertResult] = await db.query(`
          INSERT INTO products (
            sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
            status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
            weight, tags, short_description, description, image_path, image_paths, discount,
            specifications, details, name
          ) VALUES ?`, [productsToInsert]);

                if (!insertResult || !insertResult.affectedRows) {
                    throw new Error('Failed to insert products');
                }
            } catch (err) {
                console.error('Error inserting products:', err);
                throw err;
            }
        }

        fs.unlinkSync(req.file.path);

        res.json({
            message: 'Excel import completed.',
            totalRows,
            inserted: insertedCount,
            skipped: skippedCount,
            errors: errorLogs
        });

    } catch (err) {
        console.error('❌ Upload Error:', err);
        if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.status(500).json({
            error: err.message,
            details: process.env.NODE_ENV === 'development' ? err.stack : undefined
        });
    }
});

// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     let insertedCount = 0;
//     let updatedCount = 0;
//     let skippedCount = 0;
//     let errorLogs = [];

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);
//         const uploadsDir = path.join(__dirname, 'Uploads');
//         if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

//         const downloadImage = async (url) => {
//             try {
//                 const cleanUrl = String(url || '').trim();
//                 if (!cleanUrl.startsWith('http')) return null;

//                 const ext = path.extname(cleanUrl).split('?')[0] || '.png';
//                 const fileName = Date.now() + '-' + Math.floor(Math.random() * 1000) + ext;
//                 const filePath = path.join(uploadsDir, fileName);

//                 const response = await axios({ url: cleanUrl, method: 'GET', responseType: 'stream' });
//                 await new Promise((resolve, reject) => {
//                     const stream = response.data.pipe(fs.createWriteStream(filePath));
//                     stream.on('finish', resolve);
//                     stream.on('error', reject);
//                 });
//                 return `Uploads/${fileName}`;
//             } catch (err) {
//                 errorLogs.push({ name: 'Image Download Failed', reason: err.message });
//                 return null;
//             }
//         };

//         for (const row of data) {
//             const name = String(row.Name || '').trim();
//             const sku = String(row.SKU || '').trim();
//             if (!name || !sku) {
//                 skippedCount++;
//                 errorLogs.push({ name: name || 'N/A', reason: 'Missing name or SKU' });
//                 continue;
//             }

//             let brandId = null;
//             if (row.brand) {
//                 const [existingBrand] = await db.query('SELECT id FROM product_brands WHERE name = ?', [row.brand]);
//                 if (existingBrand.length > 0) {
//                     brandId = existingBrand[0].id;
//                 } else {
//                     const [insertBrand] = await db.query('INSERT INTO product_brands (name, status) VALUES (?, "Active")', [row.brand]);
//                     brandId = insertBrand.insertId;
//                 }
//             }

//             let categoryId = null;
//             let specifications = [], details = [];
//             try {
//                 if (row.specifications) specifications = JSON.parse(String(row.specifications).replace(/'/g, '"'));
//                 if (row.details) details = JSON.parse(String(row.details).replace(/'/g, '"'));
//             } catch (err) {
//                 errorLogs.push({ name, reason: `JSON parse error: ${err.message}` });
//             }

//             if (row.category) {
//                 const [existingCategory] = await db.query('SELECT * FROM product_categories WHERE name = ?', [row.category]);
//                 if (existingCategory.length > 0) {
//                     const cat = existingCategory[0];
//                     categoryId = cat.id;
//                     const oldSpecs = cat.specs || '[]';
//                     if (oldSpecs !== JSON.stringify(specifications)) {
//                         await db.query('UPDATE product_categories SET specs = ? WHERE id = ?', [JSON.stringify(specifications), categoryId]);
//                     }
//                 } else {
//                     let parentId = null;
//                     if (row.parent_category) {
//                         const [parentCat] = await db.query('SELECT id FROM product_categories WHERE name = ?', [row.parent_category]);
//                         if (parentCat.length > 0) parentId = parentCat[0].id;
//                     }
//                     const [insertCategory] = await db.query(
//                         'INSERT INTO product_categories (name, status, specs, parent_category) VALUES (?, "Active", ?, ?)',
//                         [row.category, JSON.stringify(specifications), parentId]
//                     );
//                     categoryId = insertCategory.insertId;
//                 }
//             }

//             const slug = row.slug
//                 ? String(row.slug).trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '')
//                 : name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '') + '-' + Date.now();

//             const localImageFilename = await downloadImage(row.image_path);
//             const localImagePaths = [];
//             if (row.image_paths) {
//                 const paths = String(row.image_paths).split(',').map(i => i.trim());
//                 for (const url of paths) {
//                     const img = await downloadImage(url);
//                     if (img) localImagePaths.push(img);
//                 }
//             }

//             const [existingProduct] = await db.query('SELECT * FROM products WHERE sku = ?', [sku]);
//             if (existingProduct.length > 0) {
//                 const prod = existingProduct[0];
//                 await db.query(
//                     `UPDATE products SET 
//                         slug=?, category=?, barcode=?, buying_price=?, selling_price=?, offer_price=?, tax=?, brand=?,
//                         tags=?, short_description=?, description=?, image_path=?, image_paths=?, discount=?, 
//                         specifications=?, details=?, name=?
//                      WHERE id=?`,
//                     [
//                         slug, categoryId, row.barcode || '', row.buying_price || 0, row.selling_price || 0,
//                         row.offer_price || 0, row.tax || 'VAT-1', brandId,
//                         row.tags || '', row.short_description || '', row.description || row['description.1'] || '',
//                         localImageFilename, JSON.stringify(localImagePaths), row.discount || 0,
//                         JSON.stringify(specifications), JSON.stringify(details), name, prod.id
//                     ]
//                 );
//                 updatedCount++;
//             } else {
//                 await db.query(
//                     `INSERT INTO products (
//                         sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//                         status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning,
//                         unit, weight, tags, short_description, description, image_path, image_paths, discount,
//                         specifications, details, name
//                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "Active", "Yes", "Enable", "Yes", ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
//                     [
//                         sku, slug, categoryId, row.barcode || '', row.buying_price || 0, row.selling_price || 0,
//                         row.offer_price || 0, row.tax || 'VAT-1', brandId,
//                         row.max_purchase_quantity || 10, row.low_stock_warning || 5, row.unit || 'unit',
//                         row.weight || 0, row.tags || '', row.short_description || '', row.description || row['description.1'] || '',
//                         localImageFilename, JSON.stringify(localImagePaths), row.discount || 0,
//                         JSON.stringify(specifications), JSON.stringify(details), name
//                     ]
//                 );
//                 insertedCount++;
//             }
//         }

//         fs.unlinkSync(req.file.path);
//         res.json({
//             message: 'Excel import completed.',
//             inserted: insertedCount,
//             updated: updatedCount,
//             skipped: skippedCount,
//             errors: errorLogs
//         });

//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
//         res.status(500).json({ error: 'Error processing Excel file' });
//     }
// });

// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     let insertedCount = 0;
//     let skippedCount = 0;
//     let errorLogs = [];

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);
//         const totalRows = data.length;

//         const uploadsDir = path.join(__dirname, '../Uploads');
//         if (!fs.existsSync(uploadsDir)) {
//             fs.mkdirSync(uploadsDir, { recursive: true });
//         }

//         const productsToInsert = [];

//         for (const row of data) {
//             const name = typeof row.Name === 'string' ? row.Name.trim() : String(row.Name || '').trim();
//             const sku = typeof row.SKU === 'string' ? row.SKU.trim() : String(row.SKU || '').trim();

//             if (!name || !sku) {
//                 skippedCount++;
//                 errorLogs.push({ name: name || 'N/A', reason: 'Missing name or SKU' });
//                 continue;
//             }

//             const [existingProduct] = await db.query('SELECT id FROM products WHERE sku = ? OR name = ?', [sku, name]);
//             if (existingProduct.length > 0) {
//                 skippedCount++;
//                 errorLogs.push({ name, reason: 'Duplicate SKU or Name' });
//                 continue;
//             }

//             let brandId = null, categoryId = null;
//             let specifications = [], details = [];
//             let localImageFilename = '', localImagePaths = [];

//             let slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');
//             const [slugExists] = await db.query('SELECT id FROM products WHERE slug = ?', [slug]);
//             if (slugExists.length > 0) slug += '-' + Date.now();

//             if (row.brand) {
//                 const [existingBrand] = await db.query('SELECT id FROM product_brands WHERE name = ?', [row.brand]);
//                 if (existingBrand.length > 0) {
//                     brandId = existingBrand[0].id;
//                 } else {
//                     const [insertBrand] = await db.query('INSERT INTO product_brands (name, status) VALUES (?, "Active")', [row.brand]);
//                     brandId = insertBrand.insertId;
//                 }
//             }

//             try {
//                 if (row.specifications) specifications = JSON.parse(String(row.specifications).replace(/'/g, '"'));
//                 if (row.details) details = JSON.parse(String(row.details).replace(/'/g, '"'));
//             } catch (err) {
//                 errorLogs.push({ name, reason: `JSON parse error: ${err.message}` });
//             }

//             if (row.category) {
//                 const [existingCategory] = await db.query('SELECT id FROM product_categories WHERE name = ?', [row.category]);
//                 if (existingCategory.length > 0) {
//                     categoryId = existingCategory[0].id;
//                 } else {
//                     let parentId = null;
//                     if (row.parent_category) {
//                         const [parentCat] = await db.query('SELECT id FROM product_categories WHERE name = ?', [row.parent_category]);
//                         if (parentCat.length > 0) parentId = parentCat[0].id;
//                     }
//                     const [insertCategory] = await db.query(
//                         'INSERT INTO product_categories (name, status, specs, parent_category) VALUES (?, "Active", ?, ?)',
//                         [row.category, JSON.stringify(specifications), parentId]
//                     );
//                     categoryId = insertCategory.insertId;
//                 }
//             }

//             const downloadImage = async (url) => {
//                 try {
//                     const cleanUrl = typeof url === 'string' ? url.trim() : String(url || '').trim();
//                     if (!cleanUrl.startsWith('http')) return null;

//                     const ext = path.extname(cleanUrl).split('?')[0] || '.png';
//                     const fileName = Date.now() + '-' + Math.floor(Math.random() * 1000) + ext;
//                     const filePath = path.join(uploadsDir, fileName);

//                     const response = await axios({ url: cleanUrl, method: 'GET', responseType: 'stream' });
//                     await new Promise((resolve, reject) => {
//                         const stream = response.data.pipe(fs.createWriteStream(filePath));
//                         stream.on('finish', resolve);
//                         stream.on('error', reject);
//                     });
//                     return `Uploads/${fileName}`;
//                 } catch (err) {
//                     errorLogs.push({ name, reason: `Image download failed: ${err.message}` });
//                     return null;
//                 }
//             };

//             if (row.image_path) {
//                 const img = await downloadImage(row.image_path);
//                 if (img) localImageFilename = img;
//             }

//             if (row.image_paths) {
//                 const paths = String(row.image_paths).split(',').map(i => i.trim());
//                 for (const url of paths) {
//                     const img = await downloadImage(url);
//                     if (img) localImagePaths.push(img);
//                 }
//             }

//             productsToInsert.push([
//                 sku, slug, categoryId, row.barcode || '', row.buying_price || 0, row.selling_price || 0,
//                 row.offer_price || 0, row.tax || 'VAT-1', brandId, 'Active', 'Yes', 'Enable', 'Yes',
//                 row.max_purchase_quantity || 10, row.low_stock_warning || 5, row.unit || 'unit',
//                 row.weight || 0, row.tags || '', row.description || '', localImageFilename,
//                 localImagePaths.length ? JSON.stringify(localImagePaths) : '[]',
//                 row.discount || 0, JSON.stringify(specifications), JSON.stringify(details), name
//             ]);

//             insertedCount++;
//         }

//         if (productsToInsert.length) {
//             await db.query(`
//                 INSERT INTO products (
//                     sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//                     status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//                     weight, tags, description, image_path, image_paths, discount,
//                     specifications, details, name
//                 ) VALUES ?`, [productsToInsert]);
//         }

//         fs.unlinkSync(req.file.path); // cleanup

//         res.json({
//             message: 'Excel import completed.',
//             totalRows,
//             inserted: insertedCount,
//             skipped: skippedCount,
//             errors: errorLogs
//         });
//         console.log({ totalRows, insertedCount, skippedCount, errorLogs });

//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         if (req.file?.path && fs.existsSync(req.file.path)) {
//             fs.unlinkSync(req.file.path);
//         }
//         res.status(500).json({ error: 'Error processing Excel file' });
//     }
// });

// app.post('/api/products/uploadFile', upload.single('file'), async (req, res) => {
//     if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

//     try {
//         const workbook = xlsx.readFile(req.file.path);
//         const sheet = workbook.Sheets[workbook.SheetNames[0]];
//         const data = xlsx.utils.sheet_to_json(sheet);

//         // Ensure Uploads directory exists
//         const uploadsDir = path.join(__dirname, 'Uploads');
//         if (!fs.existsSync(uploadsDir)) {
//             fs.mkdirSync(uploadsDir, { recursive: true });
//         }

//         for (const row of data) {
//             const name = row.Name?.trim();
//             const sku = row.SKU?.trim();

//             if (!name || !sku) continue;

//             // Generate slug
//             let slug = name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');
//             const [slugExists] = await db.query('SELECT id FROM products WHERE slug = ?', [slug]);
//             if (slugExists.length > 0) slug += '-' + Date.now();

//             // Skip if product already exists
//             const [existingProduct] = await db.query('SELECT id FROM products WHERE sku = ? OR name = ?', [sku, name]);
//             if (existingProduct.length > 0) continue;

//             // Get or insert brand
//             let brandId = null;
//             if (row.brand) {
//                 const [existingBrand] = await db.query('SELECT id FROM product_brands WHERE name = ?', [row.brand]);
//                 if (existingBrand.length > 0) {
//                     brandId = existingBrand[0].id;
//                 } else {
//                     const [insertBrand] = await db.query('INSERT INTO product_brands (name, status) VALUES (?, "Active")', [row.brand]);
//                     brandId = insertBrand.insertId;
//                 }
//             }

//             // Parse specifications and details
//             let specifications = [];
//             let details = [];

//             try {
//                 if (row.specifications && typeof row.specifications === 'string') {
//                     specifications = JSON.parse(row.specifications.replace(/'/g, '"'));
//                 }
//                 if (row.details && typeof row.details === 'string') {
//                     details = JSON.parse(row.details.replace(/'/g, '"'));
//                 }
//             } catch (err) {
//                 console.warn(`⚠️ Error parsing specifications/details for ${name}: ${err.message}`);
//             }

//             // Get or insert category
//             let categoryId = null;
//             if (row.category) {
//                 const [existingCategory] = await db.query('SELECT id FROM product_categories WHERE name = ?', [row.category]);
//                 if (existingCategory.length > 0) {
//                     categoryId = existingCategory[0].id;

//                     // Update category specs if needed
//                     if (specifications.length > 0) {
//                         await db.query('UPDATE product_categories SET specs = ? WHERE id = ?', 
//                             [JSON.stringify(specifications), categoryId]);
//                     }
//                 } else {
//                     let parentId = null;
//                     if (row.parent_category) {
//                         const [parentCat] = await db.query('SELECT id FROM product_categories WHERE name = ?', [row.parent_category]);
//                         if (parentCat.length > 0) parentId = parentCat[0].id;
//                     }

//                     const [insertCategory] = await db.query(
//                         'INSERT INTO product_categories (name, status, specs, parent_category) VALUES (?, "Active", ?, ?)',
//                         [row.category, JSON.stringify(specifications), parentId]
//                     );
//                     categoryId = insertCategory.insertId;
//                 }
//             }

//             // Process main image
//             let localImageFilename = '';
//             if (row.image_path && row.image_path.startsWith('http')) {
//                 try {
//                     const imageExt = path.extname(row.image_path).split('?')[0] || '.png';
//                     const fileName = Date.now() + imageExt;
//                     const filePath = path.join(uploadsDir, fileName);

//                     const response = await axios({
//                         url: row.image_path,
//                         method: 'GET',
//                         responseType: 'stream'
//                     });

//                     await new Promise((resolve, reject) => {
//                         const stream = response.data.pipe(fs.createWriteStream(filePath));
//                         stream.on('finish', () => {
//                             localImageFilename = `Uploads/${fileName}`;
//                             resolve();
//                         });
//                         stream.on('error', reject);
//                     });
//                 } catch (err) {
//                     console.warn(`⚠️ Main image download failed for ${row.image_path}: ${err.message}`);
//                 }
//             }

//             // Process multiple images
//             let localImagePaths = [];
//             if (row.image_paths && typeof row.image_paths === 'string') {
//                 const imageUrls = row.image_paths.split(',').map(url => url.trim());

//                 for (const url of imageUrls) {
//                     if (!url.startsWith('http')) continue;

//                     try {
//                         const imageExt = path.extname(url).split('?')[0] || '.png';
//                         const fileName = Date.now() + '-' + Math.floor(Math.random() * 1000) + imageExt;
//                         const filePath = path.join(uploadsDir, fileName);

//                         const response = await axios({
//                             url: url,
//                             method: 'GET',
//                             responseType: 'stream'
//                         });

//                         await new Promise((resolve, reject) => {
//                             const stream = response.data.pipe(fs.createWriteStream(filePath));
//                             stream.on('finish', () => {
//                                 localImagePaths.push(`Uploads/${fileName}`);
//                                 resolve();
//                             });
//                             stream.on('error', reject);
//                         });
//                     } catch (err) {
//                         console.warn(`⚠️ Additional image download failed for ${url}: ${err.message}`);
//                     }
//                 }
//             }

//             // Insert product
//             await db.query(
//                 `INSERT INTO products (
//                     sku, slug, category, barcode, buying_price, selling_price, offer_price, tax, brand,
//                     status, can_purchasable, show_stock_out, refundable, max_purchase_quantity, low_stock_warning, unit,
//                     weight, tags, description, image_path, image_paths, discount,
//                     specifications, details, name
//                 )
//                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', 'Yes', 'Enable', 'Yes', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
//                 [
//                     sku,
//                     slug,
//                     categoryId,
//                     row.barcode,
//                     row.buying_price || 0,
//                     row.selling_price || 0,
//                     row.offer_price || 0,
//                     row.tax || 'VAT-1',
//                     brandId,
//                     row.max_purchase_quantity || 10,
//                     row.low_stock_warning || 5,
//                     row.unit || 'unit',
//                     row.weight || 0,
//                     row.tags || '',
//                     row.description || '',
//                     localImageFilename || '',
//                     localImagePaths.length > 0 ? JSON.stringify(localImagePaths) : '[]',
//                     row.discount || 0,
//                     JSON.stringify(specifications),
//                     JSON.stringify(details),
//                     name
//                 ]
//             );
//         }

//         fs.unlinkSync(req.file.path); // delete uploaded Excel file
//         res.json({ message: 'Excel import completed. Images downloaded, data inserted. Duplicates skipped.' });
//     } catch (err) {
//         console.error('❌ Upload Error:', err);
//         res.status(500).json({ error: 'Error processing Excel file' });
//     }
// });
app.post('/api/product-specifications', authenticate, async (req, res) => {
    // console.log('Request Body:', req.body);  // Log the incoming data

    const { specifications } = req.body;  // Only get specifications from the request body

    // Check if specifications array is provided
    if (!specifications || specifications.length === 0) {
        return res.status(400).json({ message: 'At least one specification is required.' });
    }

    try {
        // Iterate over the array of specifications and save them
        for (let spec of specifications) {
            const sql = 'INSERT INTO product_specifications (specification) VALUES (?)';  // Insert without category
            const [result] = await db.query(sql, [spec]);
        }

        res.status(201).json({
            message: 'Product specifications added successfully.',
        });
    } catch (err) {
        console.error('Error inserting product specification:', err);
        res.status(500).json({ message: 'Error saving product specification.', error: err.message });
    }
});

app.get('/api/product-specifications', authenticate, async (req, res) => {
    try {
        // Adjust SQL query to exclude the category column
        const sql = 'SELECT id, specification FROM product_specifications';
        const [rows] = await db.query(sql);

        res.status(200).json({
            product_specifications: rows,
        });
    } catch (err) {
        console.error('Error fetching product specifications:', err);
        res.status(500).json({ message: 'Error fetching product specifications.', error: err.message });
    }
});

app.delete('/api/product-specifications/:id', authenticate, async (req, res) => {
    const { id } = req.params;  // Get the ID from the URL parameter

    if (!id) {
        return res.status(400).json({ message: 'Specification ID is required.' });
    }

    try {
        // SQL query to delete the specification by its ID
        const sql = 'DELETE FROM product_specifications WHERE id = ?';
        const [result] = await db.query(sql, [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Specification not found.' });
        }

        res.status(200).json({ message: 'Specification deleted successfully.' });
    } catch (err) {
        console.error('Error deleting product specification:', err);
        res.status(500).json({ message: 'Error deleting product specification.', error: err.message });
    }
});
app.post('/api/products-section', authenticate, async (req, res) => {
    const { name, status } = req.body;

    // Validate required fields
    if (!name || !status) {
        return res.status(400).json({ message: 'Name and Status are required fields' });
    }

    try {
        // SQL query to insert a new product section record
        const sql = `
            INSERT INTO products_section (name, status)
            VALUES (?, ?)
        `;
        const [result] = await db.query(sql, [name, status]);

        // Send response with the new product section details
        res.status(201).json({
            id: result.insertId,
            name,
            status,
        });
    } catch (err) {
        console.error('Error inserting product section record:', err.message);
        res.status(500).json({ message: 'Error saving product section record' });
    }
});

app.get('/products-section', authenticate, async (req, res) => {
    try {
        // SQL query to fetch name and status from the products_section table
        const sql = `SELECT id, name, status FROM products_section ORDER BY id DESC`;
        const [rows] = await db.query(sql);

        // Send the fetched data as the response
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching product sections:', err.message);
        res.status(500).json({ message: 'Error fetching product sections' });
    }
});

app.get('/api/products/exportXLS', authenticate, async (req, res) => {
    try {
        // Fetch data from the 'products' table
        const results = await db.query('SELECT * FROM products');

        // Create a new workbook and worksheet
        const workbook = xlsx.utils.book_new();
        const worksheet = xlsx.utils.json_to_sheet(results);

        // Add worksheet to the workbook with the new name "Product Sections"
        xlsx.utils.book_append_sheet(workbook, worksheet, 'Product Sections');

        // Save the workbook to a temporary file with the updated name
        const tempFilePath = path.join(__dirname, 'product_sections.xlsx');
        xlsx.writeFile(workbook, tempFilePath);

        // Send the file to the client with the updated name
        res.download(tempFilePath, 'product_sections.xlsx', (err) => {
            if (err) {
                console.error('Error downloading file:', err);
            }

            // Delete the temporary file after sending it
            fs.unlink(tempFilePath, (err) => {
                if (err) {
                    console.error('Error deleting temporary file:', err);
                }
            });
        });
    } catch (err) {
        console.error('Error:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

app.get('/products-section/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to fetch the product section details by ID
        const sql = `SELECT id, name, status FROM products_section WHERE id = ?`;
        const [rows] = await db.query(sql, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Product section not found' });
        }

        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching product section details:', err.message);
        res.status(500).json({ message: 'Error fetching product section details' });
    }
});

app.delete('/api/products-section/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete a product record by ID from the 'products-section' table
        const sql = `
            DELETE FROM products_section
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [id]);

        // Check if a product record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }

        // Send success response 
        res.status(200).json({ message: 'Product deleted successfully' });
    } catch (err) {
        console.error('Error deleting product record:', err.message);
        res.status(500).json({ message: 'Error deleting product record' });
    }
});

app.get('/api/products-section/:id', authenticate, async (req, res) => {
    const sectionId = req.params.id;

    try {
        const sql = 'SELECT * FROM products_section WHERE id = ?';
        const [rows] = await db.query(sql, [sectionId]);

        if (rows.length === 0) {
            // console.log(`Product section with ID ${sectionId} not found.`);
            return res.status(404).json({ message: 'Product section not found' });
        }

        res.status(200).json(rows[0]); // Return the first row
    } catch (error) {
        console.error('Error fetching product section:', error.message);
        res.status(500).json({ message: 'Error fetching product section' });
    }
});

// PUT API for Updating Product Section
app.put('/api/products-section/:id', authenticate, async (req, res) => {
    const sectionId = req.params.id;
    const { name, status } = req.body;

    // console.log('Received update request:', { sectionId, name, status });

    // Input Validation
    if (!name || !status || (status !== 'active' && status !== 'inactive')) {
        return res.status(400).json({ message: 'Invalid input data' });
    }

    try {
        const sql = `
            UPDATE products_section 
            SET name = ?, status = ?
            WHERE id = ?
        `;


        const [result] = await db.query(sql, [name, status, sectionId]);

        if (result.affectedRows === 0) {
            // console.log(`Product section with ID ${sectionId} not found or no changes made.`);
            return res.status(404).json({ message: 'Product section not found or no changes made' });
        }

        // console.log(`Product section with ID ${sectionId} updated successfully.`);
        res.status(200).json({ message: 'Product section updated successfully' });
    } catch (error) {
        console.error('Error updating product section:', error.message);
        res.status(500).json({ message: 'Error updating product section' });
    }
});


app.post('/api/promotions', authenticate, upload.single('image'), async (req, res) => {
    const { name, status, type } = req.body;

    // Validate required fields
    if (!name || !status || !type) {
        return res.status(400).json({ message: 'Name, Status, and Type are required fields' });
    }

    // Get the uploaded file information 
    const file = req.file;

    try {
        // SQL query to insert a new promotion record
        const sql = `
            INSERT INTO promotions (name, status, type, image_path)
            VALUES (?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [
            name,
            status,
            type,
            file ? file.path : null,
        ]);

        // Send response with the new promotion details
        res.status(201).json({
            id: result.insertId,
            name,
            status,
            type,
            image_path: file ? file.path : null,
        });
    } catch (err) {
        console.error('Error inserting promotion record:', err.message);
        res.status(500).json({ message: 'Error saving promotion record' });
    }
});

app.get('/api/promotions', authenticate, async (req, res) => {
    try {
        const { name, type, status } = req.query;

        // Base SQL query 
        let sql = `
            SELECT 
                id,
                name, 
                type, 
                status 
            FROM promotions
            WHERE 1=1
        `;
        const params = [];

        // Add filtering conditions dynamically
        if (name) {
            sql += ' AND name LIKE ?';
            params.push(`%${name}%`);
        }
        if (type) {
            sql += ' AND type = ?';
            params.push(type);
        }
        if (status) {
            sql += ' AND status = ?';
            params.push(status);
        }

        const [rows] = await db.query(sql, params);

        // Send response with the fetched promotion records
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching promotion records:', err.message);
        res.status(500).json({ message: 'Error retrieving promotion records' });
    }
});


app.get('/api/promotions/exportXLS', authenticate, async (req, res) => {
    try {
        // Fetch data from the 'promotions' table
        const [results] = await db.query('SELECT * FROM promotions');

        // Create a new workbook and worksheet
        const workbook = xlsx.utils.book_new();
        const worksheet = xlsx.utils.json_to_sheet(results);

        // Add worksheet to the workbook with the name "Promotions"
        xlsx.utils.book_append_sheet(workbook, worksheet, 'Promotions');

        // Save the workbook to a temporary file with the updated name
        const tempFilePath = path.join(__dirname, 'promotions.xlsx');
        xlsx.writeFile(workbook, tempFilePath);

        // Send the file to the client with the updated name
        res.download(tempFilePath, 'promotions.xlsx', (err) => {
            if (err) {
                console.error('Error downloading file:', err);
            }

            // Delete the temporary file after sending it
            fs.unlink(tempFilePath, (err) => {
                if (err) {
                    console.error('Error deleting temporary file:', err);
                }
            });
        });
    } catch (err) {
        console.error('Error:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

app.delete('/api/promotions/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete a promotion record by ID from the 'promotions' table
        const sql = `
            DELETE FROM promotions
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [id]);

        // Check if a promotion record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Promotion not found' });
        }

        // Send success response
        res.status(200).json({ message: 'Promotion deleted successfully' });
    } catch (err) {
        console.error('Error deleting promotion record:', err.message);
        res.status(500).json({ message: 'Error deleting promotion record' });
    }
});

// GET Method: Retrieve a promotion by ID
app.get('/api/promotions/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to fetch the promotion by ID
        const sql = `SELECT * FROM promotions WHERE id = ?`;
        const [rows] = await db.query(sql, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Promotion not found' });
        }

        // Send the promotion details as a response
        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error retrieving promotion record:', err.message);
        res.status(500).json({ message: 'Error retrieving promotion record' });
    }
});

// PUT Method: Update a promotion by ID
app.put('/api/promotions/:id', authenticate, upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { name, status, type } = req.body;
    const file = req.file;

    // Validate required fields
    if (!name || !status || !type) {
        return res.status(400).json({ message: 'Name, Status, and Type are required fields' });
    }

    try {
        // SQL query to check if the promotion exists
        const checkSql = `SELECT * FROM promotions WHERE id = ?`;
        const [promotion] = await db.query(checkSql, [id]);

        if (promotion.length === 0) {
            return res.status(404).json({ message: 'Promotion not found' });
        }

        // SQL query to update the promotion record
        const sql = `
            UPDATE promotions
            SET name = ?, status = ?, type = ?, image_path = ?
            WHERE id = ?
        `;
        const [result] = await db.query(sql, [
            name,
            status,
            type,
            file ? file.path : promotion[0].image_path, // Keep the existing image if no new file is uploaded
            id,
        ]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Promotion not found or no changes made' });
        }

        // Send response with the updated promotion details
        res.status(200).json({
            id,
            name,
            status,
            type,
            image_path: file ? file.path : promotion[0].image_path,
        });
    } catch (err) {
        console.error('Error updating promotion record:', err.message);
        res.status(500).json({ message: 'Error updating promotion record' });
    }
});

// Product Brands

app.post('/api/product-brands', authenticate, upload.single('image'), async (req, res) => {
    const { name, status, description } = req.body;

    // Validate required fields
    if (!name || !status) {
        return res.status(400).json({ message: 'Name and Status are required fields' });
    }

    // Get the uploaded image file information
    // const image = req.file; // Access the uploaded image file
    const image = req.file ? req.file.path : null;
    try {
        // SQL query to insert a new product brand record
        const sql = `
            INSERT INTO product_brands (name, status, image_path, description)
            VALUES (?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [
            name,
            status,
            image, // Save the image path or null if no image is uploaded
            description || 'No description', // Default description if not provided
        ]);

        // Send response with the new product brand details
        res.status(201).json({
            id: result.insertId,
            name,
            status,
            image_path: image || null,
            description: description || 'No description',
        });
    } catch (err) {
        console.error('Error inserting product brand record:', err.message);
        res.status(500).json({ message: 'Error saving product brand record' });
    }
});

// GET API for fetching product brands
app.get('/api/product-brands', authenticate, async (req, res) => {
    try {
        // SQL query to fetch all product brand records
        const sql = `
            SELECT 
                id, 
                name, 
                status, 
                description
            FROM product_brands
        `;

        const [rows] = await db.query(sql);

        // Send the fetched data as JSON response
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching product brands:', err.message);
        res.status(500).json({ message: 'Error retrieving product brands' });
    }
});

app.delete('/api/product-brands/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete a product brand record by ID from the 'product_brands' table
        const sql = `
            DELETE FROM product_brands
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [id]);

        // Check if a product brand record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product brand not found' });
        }

        // Send success response
        res.status(200).json({ message: 'Product brand deleted successfully' });
    } catch (err) {
        console.error('Error deleting product brand record:', err.message);
        res.status(500).json({ message: 'Error deleting product brand record' });
    }
});

app.put('/api/product-brands/:id', authenticate, upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { name, status, description } = req.body;
    const image = req.file ? req.file.path : null; // Get image path if an image is uploaded

    // Validate required fields
    if (!name || !status) {
        return res.status(400).json({ message: 'Name and Status are required fields' });
    }

    try {
        // SQL query to update the product brand record
        const sql = `
            UPDATE product_brands
            SET name = ?, status = ?, image_path = ?, description = ?
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [
            name,
            status,
            image || null, // Update image path if a new image is uploaded, otherwise keep existing
            description || 'No description',
            id,
        ]);

        // Check if any row was updated
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product brand not found' });
        }

        // Return success response with updated brand details
        res.status(200).json({
            message: 'Product brand updated successfully',
            id,
            name,
            status,
            image_path: image || null,
            description: description || 'No description',
        });
    } catch (error) {
        console.error('Error updating product brand:', error.message);
        res.status(500).json({ message: 'Error updating product brand' });
    }
});

// GET API for fetching a single product brand by ID
app.get('/api/product-brands/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to fetch the product brand by ID
        const sql = `
            SELECT 
                id, 
                name, 
                status, 
                image_path, 
                description
            FROM product_brands
            WHERE id = ?
        `;

        const [rows] = await db.query(sql, [id]);

        // Check if the product brand exists
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Product brand not found' });
        }

        // Send the product brand data as JSON response
        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching product brand:', err.message);
        res.status(500).json({ message: 'Error retrieving product brand' });
    }
});
app.post('/api/product-categories', authenticate, upload.single('image'), async (req, res) => {
    const { name, status, description, categorySpecs, parent_category } = req.body;
    const imageFilename = req.file ? path.basename(req.file.path) : null;

    if (!name || !status) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ message: "Name and status are required." });
    }

    let parsedSpecs = [];
    try {
        parsedSpecs = categorySpecs ? JSON.parse(categorySpecs) : [];
    } catch (err) {
        console.error('Error parsing categorySpecs:', err);
        return res.status(400).json({ message: "Invalid format for category specifications." });
    }

    const parentCategoryId = parent_category && !isNaN(parseInt(parent_category))
        ? parseInt(parent_category)
        : null;

    try {
        const sql = `
        INSERT INTO product_categories 
        (name, status, description, specs, parent_category, image_path)
        VALUES (?, ?, ?, ?, ?, ?)
      `;

        const [result] = await db.query(sql, [
            name,
            status,
            description || 'No description',
            JSON.stringify(parsedSpecs),
            parentCategoryId,
            imageFilename ? `uploads/${imageFilename}` : null
        ]);

        res.status(201).json({
            id: result.insertId,
            name,
            status,
            description: description || 'No description',
            specs: parsedSpecs,
            parent_category: parentCategoryId,
            image_path: imageFilename ? `/uploads/${imageFilename}` : null
        });

    } catch (err) {
        if (req.file) fs.unlinkSync(req.file.path);
        console.error('Database Error:', err.message);
        res.status(500).json({ message: 'Error saving product category' });
    }
});
app.get('/api/product-categories/:categoryId/specifications', async (req, res) => {
    const { categoryId } = req.params;

    try {
        const [rows] = await db.query('SELECT specs FROM product_categories WHERE id = ?', [categoryId]);

        if (rows.length === 0 || !rows[0].specs) {
            return res.status(404).json({ message: 'No specifications found for this category', specifications: [] });
        }

        let specifications = [];

        try {
            specifications = JSON.parse(rows[0].specs);
        } catch (jsonErr) {
            console.error('JSON parse error:', jsonErr);
            return res.status(500).json({ message: 'Invalid JSON format for specifications.', specifications: [] });
        }

        if (!Array.isArray(specifications) || specifications.length === 0) {
            return res.status(404).json({ message: 'No specifications found for this category', specifications: [] });
        }

        res.json({ success: true, specifications });

    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).json({ success: false, message: 'Error fetching specifications', error: err.message });
    }
});
app.get('/api/product-categories', authenticate, async (req, res) => {
    try {
        const sql = `
            SELECT 
                pc.id, 
                pc.name, 
                pc.status, 
                pc.specs,
                pc.parent_category,
                COALESCE(parent.name, 'No Parent') AS parent_category_name
            FROM product_categories pc
            LEFT JOIN product_categories parent ON pc.parent_category = parent.id
        `;

        const [rows] = await db.query(sql);

        // console.log("Fetched Categories:", rows); // Debugging Line

        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching product categories:', err.message);
        res.status(500).json({ message: 'Error retrieving product brands' });
    }
});


app.delete('/api/product-categories/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete a product brand record by ID from the 'product_brands' table
        const sql = `
            DELETE FROM product_categories
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [id]);

        // Check if a product brand record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product categories not found' });
        }

        // Send success response
        res.status(200).json({ message: 'Product categories deleted successfully' });
    } catch (err) {
        console.error('Error deleting product categories record:', err.message);
        res.status(500).json({ message: 'Error deleting product categories record' });
    }
});
// GET API for fetching a single product brand by ID
// app.patch('/api/product-categories/:id', authenticate, upload.single('image'), async (req, res) => {
//     const { id } = req.params;
//     const { name, status, description, categorySpecs, parent_category } = req.body;
//     const imageFilename = req.file ? path.basename(req.file.path) : null;

//     if (!name || !status) {
//         if (req.file) fs.unlinkSync(req.file.path);
//         return res.status(400).json({ message: 'Name and Status are required' });
//     }

//     try {
//         // First get current image path to delete old image if needed
//         const [current] = await db.query(
//             'SELECT image_path FROM product_categories WHERE id = ?',
//             [id]
//         );

//         const sql = `
//             UPDATE product_categories
//             SET name = ?, status = ?, description = ?, specs = ?, 
//                 parent_category = ?, image_path = ?
//             WHERE id = ?
//         `;

//         const newImagePath = imageFilename ? `uploads/${imageFilename}` : current[0]?.image_path;

//         const [result] = await db.query(sql, [
//             name,
//             status,
//             description || 'No description',
//             JSON.stringify(categorySpecs || []),
//             parent_category ? parseInt(parent_category) : null,
//             newImagePath,
//             id
//         ]);

//         if (result.affectedRows === 0) {
//             if (req.file) fs.unlinkSync(req.file.path);
//             return res.status(404).json({ message: 'Product category not found' });
//         }

//         // Delete old image if a new one was uploaded
//         if (req.file && current[0]?.image_path) {
//             try {
//                 fs.unlinkSync(path.join(__dirname, '..', current[0].image_path));
//             } catch (err) {
//                 console.error('Error deleting old image:', err.message);
//             }
//         }

//         res.status(200).json({
//             message: 'Product category updated successfully',
//             id,
//             name,
//             status,
//             description: description || 'No description',
//             specs: categorySpecs || [],
//             parent_category: parent_category || null,
//             image_path: imageFilename ? `/uploads/${imageFilename}` : current[0]?.image_path
//         });
//     } catch (error) {
//         if (req.file) fs.unlinkSync(req.file.path);
//         console.error('Error updating product category:', error.message);
//         res.status(500).json({ message: 'Error updating product category' });
//     }
// });
app.patch('/api/product-categories/:id', authenticate, upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { name, status, description, categorySpecs, parent_category } = req.body;
    const imageFilename = req.file ? path.basename(req.file.path) : null;

    try {
        // Fetch current row from DB
        const [currentRows] = await db.query(
            'SELECT * FROM product_categories WHERE id = ?',
            [id]
        );
        const current = currentRows[0];

        if (!current) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(404).json({ message: 'Product category not found' });
        }

        // Validate required fields only if provided, otherwise fallback to current
        if (name !== undefined && !name) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(400).json({ message: 'Name cannot be empty' });
        }
        if (status !== undefined && !status) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(400).json({ message: 'Status cannot be empty' });
        }

        // Determine final values: use new if provided, else keep existing
        const finalName = name !== undefined ? name : current.name;
        const finalStatus = status !== undefined ? status : current.status;
        const finalDescription = description !== undefined ? description : current.description;
        const finalSpecs = categorySpecs !== undefined
            ? JSON.stringify(categorySpecs)
            : current.specs;
        const finalParentCategory = parent_category !== undefined
            ? (parent_category ? parseInt(parent_category) : null)
            : current.parent_category;
        const finalImagePath = imageFilename
            ? `uploads/${imageFilename}`
            : current.image_path;

        // Run update query
        const sql = `
            UPDATE product_categories
            SET name = ?, status = ?, description = ?, specs = ?, parent_category = ?, image_path = ?
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [
            finalName,
            finalStatus,
            finalDescription || 'No description',
            finalSpecs,
            finalParentCategory,
            finalImagePath,
            id
        ]);

        if (result.affectedRows === 0) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(404).json({ message: 'Product category not found' });
        }

        // Delete old image if a new one was uploaded and old exists
        if (req.file && current.image_path && current.image_path !== finalImagePath) {
            try {
                fs.unlinkSync(path.join(__dirname, '..', current.image_path));
            } catch (err) {
                console.error('Error deleting old image:', err.message);
            }
        }

        res.status(200).json({
            message: 'Product category updated successfully',
            id,
            name: finalName,
            status: finalStatus,
            description: finalDescription || 'No description',
            specs: finalSpecs ? JSON.parse(finalSpecs) : [],
            parent_category: finalParentCategory,
            image_path: finalImagePath.startsWith('uploads/') ? `/${finalImagePath}` : finalImagePath
        });

    } catch (error) {
        if (req.file) fs.unlinkSync(req.file.path);
        console.error('Error updating product category:', error.message);
        res.status(500).json({ message: 'Error updating product category' });
    }
});


app.get('/api/product-categories/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to fetch the product brand by ID
        const sql = `
            SELECT 
                id, 
                name, 
                status, 
                image_path, 
                description
            FROM product_categories
            WHERE id = ?
        `;

        const [rows] = await db.query(sql, [id]);

        // Check if the product brand exists
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Product category not found' });
        }

        // Send the product brand data as JSON response
        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching product category:', err.message);
        res.status(500).json({ message: 'Error retrieving product category' });
    }
});

// Product Attributes
app.post('/api/product-attributes', authenticate, async (req, res) => {
    const { name } = req.body;


    // console.log('Processing product attribute:', name); // Corrected log message

    try {
        const sql = `
            INSERT INTO product_attributes (name)
            VALUES (?)
        `;
        const [result] = await db.query(sql, [name]);
        // console.log('Product attribute inserted with ID:', result.insertId); // Log the ID of the inserted attribute

        // Send response with the new product attribute details
        res.status(201).json({
            id: result.insertId,
            name,
        });
    } catch (err) {
        console.error('Error inserting product attribute record:', err.message);
        res.status(500).json({ message: 'Error saving product attribute record' });
    }
});

app.get('/api/product-attributes', authenticate, async (req, res) => {
    try {
        // SQL query to fetch all product attributes
        const sql = `
            SELECT 
                id, 
                name 
            FROM product_attributes
        `;

        const [rows] = await db.query(sql);

        // Send the fetched data as a JSON response
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching product attributes:', err.message);
        res.status(500).json({ message: 'Error retrieving product attributes' });
    }
});

app.delete('/api/product-attributes/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete a product attribute record by ID from the 'product_attributes' table
        const sql = `
            DELETE FROM product_attributes
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [id]);

        // Check if a product attribute record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product attribute not found' });
        }

        // Send success response
        res.status(200).json({ message: 'Product attribute deleted successfully' });
    } catch (err) {
        console.error('Error deleting product attribute record:', err.message);
        res.status(500).json({ message: 'Error deleting product attribute record' });
    }
});

app.get('/api/product-attributes/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    // console.log('Fetching product attribute with ID:', id);

    try {
        const sql = `SELECT * FROM product_attributes WHERE id = ?`;
        const [rows] = await db.query(sql, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Product attribute not found' });
        }

        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching product attribute by ID:', err.message);
        res.status(500).json({ message: 'Error fetching product attribute' });
    }
});

app.put('/api/product-attributes/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;

    // console.log('Updating product attribute:', id, name);

    if (!name) {
        return res.status(400).json({ message: 'Name is a required field' });
    }

    try {
        const sql = `
            UPDATE product_attributes
            SET name = ?
            WHERE id = ?
        `;
        const [result] = await db.query(sql, [name, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product attribute not found' });
        }

        // console.log('Product attribute updated with ID:', id);
        res.status(200).json({ id, name });
    } catch (err) {
        console.error('Error updating product attribute record:', err.message);
        res.status(500).json({ message: 'Error updating product attribute record' });
    }
});

app.post('/api/product-attribute-section', authenticate, async (req, res) => {
    const { name } = req.body;

    try {
        // Updated table name: product_attribute_section
        const sql = 'INSERT INTO product_attribute_section (name) VALUES (?)';
        const [result] = await db.query(sql, [name]);

        res.status(201).json({ id: result.insertId, name });
    } catch (err) {
        console.error('Error inserting product attribute section:', err.message);
        res.status(500).json({ message: 'Error saving product attribute section' });
    }
});

app.get('/api/product-attribute-section', authenticate, async (req, res) => {
    try {
        // Log the incoming request for debugging
        // console.log('Fetching all product attribute sections...');

        // Query to fetch all records from product_attribute_section
        const sql = 'SELECT id, name FROM product_attribute_section';
        const [rows] = await db.query(sql);

        // Log the fetched data
        // console.log('Fetched Product Attribute Sections:', rows);

        // Send the data as JSON
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching product attribute sections:', err.message);
        res.status(500).json({ message: 'Error retrieving product attribute sections' });
    }
});

app.delete('/api/product-attribute-section/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        const sql = 'DELETE FROM product_attribute_section WHERE id = ?';
        const [result] = await db.query(sql, [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product attribute section not found.' });
        }

        res.status(200).json({ message: 'Product attribute section deleted successfully.' });
    } catch (err) {
        console.error('Error deleting product attribute section:', err.message);
        res.status(500).json({ message: 'Error deleting product attribute section.' });
    }
});

app.put('/api/product-attribute-section/:id', authenticate, async (req, res) => {
    const { id } = req.params; // Extract ID from the URL
    const { name } = req.body; // Extract updated data from the request body

    try {
        const sql = 'UPDATE product_attribute_section SET name = ? WHERE id = ?';
        const [result] = await db.query(sql, [name, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Product attribute not found.' });
        }

        res.status(200).json({ message: 'Product attribute updated successfully.' });
    } catch (err) {
        console.error('Error updating product attribute:', err.message);
        res.status(500).json({ message: 'Error updating product attribute.' });
    }
});


app.get('/api/product-attribute-section/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await db.query('SELECT id, name FROM product_attribute_section WHERE id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Attribute not found.' });
        res.status(200).json(rows[0]);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching attribute.' });
    }
});

app.post('/api/currencies', authenticate, async (req, res) => {
    const { name, symbol, code, isCryptocurrency, exchangeRate } = req.body;

    // Validate required fields
    if (!name || !symbol || !code || !isCryptocurrency || !exchangeRate) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // Insert new currency record into the database
        const sql = `
            INSERT INTO currencies (name, symbol, code, is_cryptocurrency, exchange_rate)
            VALUES (?, ?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [
            name,
            symbol,
            code,
            isCryptocurrency, // Directly store "Yes" or "No"
            parseFloat(exchangeRate),    // Ensure numeric value
        ]);

        // Send response with the new currency details
        res.status(201).json({
            id: result.insertId,
            name,
            symbol,
            code,
            is_cryptocurrency: isCryptocurrency, // Send back "Yes" or "No"
            exchange_rate: parseFloat(exchangeRate),
        });
    } catch (err) {
        console.error('Error inserting currency record:', err.message);
        res.status(500).json({ message: 'Error saving currency record' });
    }
});

app.get('/api/currencies', async (req, res) => {
    try {
        const [currencies] = await db.query('SELECT * FROM currencies');
        res.status(200).json(currencies);
    } catch (error) {
        console.error('Error fetching currencies:', error.message);
        res.status(500).json({ message: 'Failed to fetch currencies' });
    }
});

app.get('/api/currencies/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        const sql = `SELECT * FROM currencies WHERE id = ?`;
        const [result] = await db.query(sql, [id]);

        if (result.length === 0) {
            return res.status(404).json({ message: 'Currency not found' });
        }

        // Send the retrieved currency data as a response
        res.json(result[0]);
    } catch (err) {
        console.error('Error fetching currency:', err.message);
        res.status(500).json({ message: 'Failed to fetch currency' });
    }
});

app.put('/api/currencies/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    const { name, symbol, code, exchangeRate, isCryptocurrency } = req.body;

    // Validate input fields
    if (!name || !symbol || !code || !exchangeRate || !isCryptocurrency) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const sql = 'UPDATE currencies SET name = ?, symbol = ?, code = ?, exchange_rate = ?, is_cryptocurrency = ? WHERE id = ?';
        const [result] = await db.query(sql, [name, symbol, code, exchangeRate, isCryptocurrency, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Currency not found' });
        }

        res.status(200).json({ message: 'Currency updated successfully', id, name, symbol, code, exchangeRate, isCryptocurrency });
    } catch (error) {
        console.error('Error updating currency:', error);
        res.status(500).json({ message: 'Error updating currency' });
    }
});


// Taxes
app.post('/api/taxes', authenticate, async (req, res) => {
    // console.log('Received data:', req.body); // Log the incoming request body

    const { name, status, code, tax_rate } = req.body;

    // Validate required fields
    if (!name || !status || !code || !tax_rate) {
        return res.status(400).json({ message: 'Name, Status, Code, and Tax Rate are required fields' });
    }

    try {
        const sql = `
            INSERT INTO taxes (name, status, code, tax_rate)
            VALUES (?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [name, status, code, tax_rate]);

        res.status(201).json({
            id: result.insertId,
            name,
            status,
            code,
            tax_rate
        });
    } catch (err) {
        console.error('Error inserting tax record:', err.message);
        res.status(500).json({ message: 'Error saving tax record' });
    }
});

app.get('/api/taxes', authenticate, async (req, res) => {
    try {
        const sql = 'SELECT * FROM taxes'; // Adjust the query to match your database
        const [result] = await db.query(sql);

        if (result.length > 0) {
            res.status(200).json(result); // Send the data as JSON
        } else {
            res.status(404).json({ message: 'No taxes found' });
        }
    } catch (error) {
        console.error('Error fetching taxes:', error.message);
        res.status(500).json({ message: 'An error occurred while fetching taxes data' });
    }
});

app.delete('/api/taxes/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete a tax record by ID from the 'taxes' table
        const sql = `
            DELETE FROM taxes
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [id]);

        // Check if a tax record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Tax not found' });
        }

        // Send success response
        res.status(200).json({ message: 'Tax deleted successfully' });
    } catch (err) {
        console.error('Error deleting tax record:', err.message);
        res.status(500).json({ message: 'Error deleting tax record' });
    }
});

app.put('/api/taxes/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    const { name, status, code, tax_rate } = req.body;

    if (!name || !status || !code || !tax_rate) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const sql = `
            UPDATE taxes
            SET name = ?, status = ?, code = ?, tax_rate = ?
            WHERE id = ?
        `;
        const [result] = await db.query(sql, [name, status, code, tax_rate, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Tax not found' });
        }

        res.json({ message: 'Tax updated successfully' });
    } catch (error) {
        console.error('Error updating tax record:', error.message);
        res.status(500).json({ message: 'Failed to update tax record' });
    }
});

app.get('/api/taxes/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        const [result] = await db.query('SELECT * FROM taxes WHERE id = ?', [id]);
        if (result.length === 0) {
            return res.status(404).json({ message: 'Tax not found' });
        }
        res.json(result[0]);
    } catch (error) {
        console.error('Error fetching tax record:', error.message);
        res.status(500).json({ message: 'Failed to fetch tax record' });
    }
});


// Units
app.post('/api/units', authenticate, async (req, res) => {
    // console.log('Received data:', req.body); // Log the incoming request body

    const { name, code, status } = req.body;

    // Validate required fields
    if (!name || !code || !status) {
        return res.status(400).json({ message: 'Name, Code, and Status are required fields' });
    }

    try {
        const sql = `
            INSERT INTO units (name, code, status)
            VALUES (?, ?, ?)
        `;
        const [result] = await db.query(sql, [name, code, status]);

        res.status(201).json({
            id: result.insertId,
            name,
            code,
            status,
        });
    } catch (err) {
        console.error('Error inserting unit record:', err.message);
        res.status(500).json({ message: 'Error saving unit record' });
    }
});

// GET API to fetch all units   
app.get('/api/units', authenticate, async (req, res) => {
    try {
        const sql = `SELECT * FROM units ORDER BY id DESC`;
        const [units] = await db.query(sql);

        res.status(200).json(units);
    } catch (err) {
        console.error('Error fetching units:', err.message);
        res.status(500).json({ message: 'Error fetching units' });
    }
});

app.put('/api/units/:id', authenticate, async (req, res) => {
    const { id } = req.params;  // Get the unit ID from the URL
    const { name, code, status } = req.body; // Get the updated unit data

    // Validate required fields
    if (!name || !code || !status) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const sql = `
            UPDATE units
            SET name = ?, code = ?, status = ?
            WHERE id = ?
        `;
        const [result] = await db.query(sql, [name, code, status, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Unit not found' });
        }

        res.status(200).json({ message: 'Unit updated successfully' });
    } catch (err) {
        console.error('Error updating unit:', err.message);
        res.status(500).json({ message: 'Error updating unit' });
    }
});

// GET endpoint to fetch a unit's details by ID
app.get('/api/units/:id', authenticate, async (req, res) => {
    const unitId = req.params.id;  // Get the unit ID from the URL

    try {
        // SQL query to fetch the unit details
        const sql = 'SELECT * FROM units WHERE id = ?';
        const [result] = await db.query(sql, [unitId]);

        // If no unit is found, return an error
        if (result.length === 0) {
            return res.status(404).json({ message: 'Unit not found' });
        }

        // Send back the unit details
        res.status(200).json(result[0]);  // Send the first unit in the result
    } catch (err) {
        console.error('Error fetching unit:', err.message);
        res.status(500).json({ message: 'Error fetching unit' });
    }
});

app.delete('/api/units/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete the unit record by id
        const sql = `DELETE FROM units WHERE id = ?`;
        const [result] = await db.query(sql, [id]);

        // Check if the record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Unit record not found' });
        }

        res.status(200).json({ message: 'Unit record deleted successfully' });
    } catch (err) {
        console.error('Error deleting unit record:', err.message);
        res.status(500).json({ message: 'Error deleting unit record' });
    }
});


// Outlets

app.post('/api/outlets', authenticate, async (req, res) => {
    // console.log('Received data:', req.body); // Log the incoming request body

    const { name, latitude, longitude, email, phone, city, state, zip, status, address } = req.body;

    // Validate required fields
    if (!name || !latitude || !longitude || !email || !phone || !city || !state || !zip || !status || !address) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const sql = `
                INSERT INTO outlets (name, latitude, longitude, email, phone, city, state, zip, status, address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
        const [result] = await db.query(sql, [name, latitude, longitude, email, phone, city, state, zip, status, address]);

        res.status(201).json({
            id: result.insertId,
            name,
            latitude,
            longitude,
            email,
            phone,
            city,
            state,
            zip,
            status,
            address
        });
    } catch (err) {
        console.error('Error inserting outlet record:', err.message);
        res.status(500).json({ message: 'Error saving outlet record' });
    }
});

// GET all outlets
app.get('/api/outlets', authenticate, async (req, res) => {
    try {
        const sql = `SELECT * FROM outlets`;
        const [rows] = await db.query(sql);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'No outlets found' });
        }

        // Respond with the list of outlets
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching outlets:', err.message);
        res.status(500).json({ message: 'Error fetching outlets' });
    }
});

app.get('/api/outlets/:id', authenticate, async (req, res) => {
    const outletId = req.params.id;

    try {
        const sql = 'SELECT * FROM outlets WHERE id = ?';
        const [rows] = await db.query(sql, [outletId]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Outlet not found' });
        }

        res.status(200).json(rows[0]); // Return the first (and only) row
    } catch (error) {
        console.error('Error fetching outlet:', error.message);
        res.status(500).json({ message: 'Error fetching outlet' });
    }
});

app.put('/api/outlets/:id', authenticate, async (req, res) => {
    const outletId = req.params.id;
    const {
        name,
        latitude,
        longitude,
        email,
        phone,
        city,
        state,
        zip,
        status,
        address,
    } = req.body;

    try {
        const sql = `
            UPDATE outlets 
            SET name = ?, latitude = ?, longitude = ?, email = ?, phone = ?, city = ?, state = ?, zip = ?, status = ?, address = ?
            WHERE id = ?
        `;
        const [result] = await db.query(sql, [
            name,
            latitude,
            longitude,
            email,
            phone,
            city,
            state,
            zip,
            status,
            address,
            outletId,
        ]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Outlet not found or no changes made' });
        }

        res.status(200).json({ message: 'Outlet updated successfully' });
    } catch (error) {
        console.error('Error updating outlet:', error.message);
        res.status(500).json({ message: 'Error updating outlet' });
    }
});

app.delete('/api/outlets/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete the outlets record by id
        const sql = `DELETE FROM outlets WHERE id = ?`;
        const [result] = await db.query(sql, [id]);

        // Check if the record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Outlets record not found' });
        }

        res.status(200).json({ message: 'Outlets record deleted successfully' });
    } catch (err) {
        console.error('Error deleting outlets record:', err.message);
        res.status(500).json({ message: 'Error deleting outlets record' });
    }
});

// Language
app.post('/api/languages', authenticate, upload.single('image'), async (req, res) => {
    const { name, code, display_mode, status } = req.body;

    // Validate required fields
    if (!name || !code || !display_mode || !status) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    // Ensure display_mode and status have valid values
    const validDisplayModes = ['LTR', 'RTL'];
    const validStatuses = ['Active', 'Inactive'];

    if (!validDisplayModes.includes(display_mode)) {
        return res.status(400).json({ message: 'Invalid display mode' });
    }

    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: 'Invalid status' });
    }

    // Get the file path from the uploaded file
    const imagePath = req.file ? req.file.path : null;

    try {
        // SQL query to insert new language
        const sql = `
            INSERT INTO languages (name, code, image_path, display_mode, status)
            VALUES (?, ?, ?, ?, ?)
        `;

        const [result] = await db.query(sql, [name, code, imagePath, display_mode, status]);

        // Send response with new language details
        res.status(201).json({
            id: result.insertId,
            name,
            code,
            image: imagePath,
            display_mode,
            status,
        });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Code must be unique' });
        }

        console.error('Error inserting language:', err.message);
        res.status(500).json({ message: 'Error saving language' });
    }
});

app.get('/api/languages', authenticate, async (req, res) => {
    try {
        // SQL query to retrieve all languages
        const sql = `
            SELECT id, name, code, status
            FROM languages
        `;

        const [languages] = await db.query(sql);

        // Send the retrieved languages as the response
        res.status(200).json(languages);
    } catch (err) {
        console.error('Error retrieving languages:', err.message);
        res.status(500).json({ message: 'Error retrieving languages' });
    }
});

app.get('/api/languages/:id', authenticate, async (req, res) => {
    try {
        const sql = `
            SELECT id, name, code, image_path AS image, display_mode, status 
            FROM languages 
            WHERE id = ?
        `;
        const [language] = await db.query(sql, [req.params.id]);

        if (!language.length) {
            return res.status(404).json({ message: 'Language not found' });
        }

        // Prepend base URL to the image path
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        const languageDetails = {
            ...language[0],
            image: language[0].image ? `${baseUrl}/${language[0].image}` : null, // Full URL for the image
        };

        res.status(200).json(languageDetails);
    } catch (err) {
        console.error('Error fetching language:', err.message);
        res.status(500).json({ message: 'Error fetching language' });
    }
});

app.put('/api/languages/:id', authenticate, upload.single('image'), async (req, res) => {
    const { name, code, display_mode, status } = req.body;
    const imagePath = req.file ? req.file.path : null;

    try {
        const sql = `
            UPDATE languages
            SET name = ?, code = ?, image_path = COALESCE(?, image_path), display_mode = ?, status = ?
            WHERE id = ?
        `;

        const [result] = await db.query(sql, [name, code, imagePath, display_mode, status, req.params.id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Language not found' });
        }

        res.status(200).json({ message: 'Language updated successfully' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Code must be unique' });
        }

        console.error('Error updating language:', err.message);
        res.status(500).json({ message: 'Error updating language' });
    }
});

app.delete('/api/languages/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;

        // Check if the language exists
        const checkSql = `SELECT id FROM languages WHERE id = ?`;
        const [checkResult] = await db.query(checkSql, [id]);

        if (!checkResult.length) {
            return res.status(404).json({ message: 'Language not found' });
        }

        // Delete the language
        const deleteSql = `DELETE FROM languages WHERE id = ?`;
        const [result] = await db.query(deleteSql, [id]);

        if (result.affectedRows === 0) {
            return res.status(500).json({ message: 'Failed to delete language' });
        }

        res.status(200).json({ message: 'Language deleted successfully' });
    } catch (err) {
        console.error('Error deleting language:', err.message);
        res.status(500).json({ message: 'Error deleting language' });
    }
});

// Analytics
app.post('/api/analytics', authenticate, async (req, res) => {
    // console.log('Received data:', req.body); // Log the incoming request body

    const { name, status } = req.body;

    // Validate required fields
    if (!name || !status) {
        return res.status(400).json({ message: 'Name and Status are required' });
    }

    try {
        const sql = `
            INSERT INTO analytics (name, status)
            VALUES (?, ?)
        `;
        const [result] = await db.query(sql, [name, status]);

        res.status(201).json({
            id: result.insertId,
            name,
            status
        });
    } catch (err) {
        console.error('Error inserting analytics record:', err.message);
        res.status(500).json({ message: 'Error saving analytics record' });
    }
});

app.get('/api/analytics', authenticate, async (req, res) => {
    try {
        const sql = `
            SELECT id, name, status
            FROM analytics
        `;

        const [rows] = await db.query(sql);

        res.status(200).json(rows); // Send the retrieved data as JSON
    } catch (err) {
        console.error('Error fetching analytics records:', err.message);
        res.status(500).json({ message: 'Error fetching analytics records' });
    }
});

app.delete('/api/analytics/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete the analytics record by id
        const sql = `DELETE FROM analytics WHERE id = ?`;
        const [result] = await db.query(sql, [id]);

        // Check if the record was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Analytics record not found' });
        }

        res.status(200).json({ message: 'Analytics record deleted successfully' });
    } catch (err) {
        console.error('Error deleting analytics record:', err.message);
        res.status(500).json({ message: 'Error deleting analytics record' });
    }
});

// PUT API to update an analytics record
app.put('/api/analytics/:id', async (req, res) => {
    const { id } = req.params;
    const { name, status } = req.body;

    if (!name || !status) {
        return res.status(400).json({ message: 'Name and status are required.' });
    }

    try {
        const sql = 'UPDATE analytics SET name = ?, status = ? WHERE id = ?';
        const [result] = await db.query(sql, [name, status, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Analytics record not found.' });
        }

        res.status(200).json({ message: 'Analytics record updated successfully.' });
    } catch (error) {
        console.error('Error updating analytics record:', error.message);
        res.status(500).json({ message: 'Internal server error. Please try again later.' });
    }
});

app.get('/api/analytics/:id', authenticate, async (req, res) => {
    const { id } = req.params; // Get the ID from the URL parameters

    try {
        // SQL query to fetch a single analytics record by ID
        const sql = `
            SELECT id, name, status
            FROM analytics
            WHERE id = ?
        `;

        // Query the database for the record with the given ID
        const [rows] = await db.query(sql, [id]);

        // Check if any record was found
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Analytics record not found.' });
        }

        // Send the found record as a JSON response
        res.status(200).json(rows[0]); // Return the first result (only one record)
    } catch (err) {
        console.error('Error fetching analytics record:', err.message);
        res.status(500).json({ message: 'Error fetching analytics record' });
    }
});

app.post('/api/analytic-section', authenticate, async (req, res) => {
    // console.log('Received data:', req.body); // Log the incoming request body

    const { name, section, data } = req.body;

    // Validate required fields
    if (!name || !section || !data) {
        return res.status(400).json({ message: 'Name, Section, and Data are required' });
    }

    try {
        const sql = `
            INSERT INTO analytic_section (name, section, data)
            VALUES (?, ?, ?)
        `;
        const [result] = await db.query(sql, [name, section, data]);

        res.status(201).json({
            id: result.insertId,
            name,
            section,
            data,
        });
    } catch (err) {
        console.error('Error inserting analytic-section record:', err.message);
        res.status(500).json({ message: 'Error saving analytic-section record' });
    }
});
app.get('/api/analytic-section', authenticate, async (req, res) => {
    try {
        const sql = `
            SELECT id, name, section, data
            FROM analytic_section
        `;

        const [rows] = await db.query(sql);

        res.status(200).json(rows); // Return all records
    } catch (err) {
        console.error('Error fetching analytic-section records:', err.message);
        res.status(500).json({ message: 'Error fetching analytic-section records' });
    }
});

app.get('/api/analytic-section/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        const sql = `
            SELECT id, name, section, data, created_at, updated_at
            FROM analytic_section
            WHERE id = ?
        `;
        const [rows] = await db.query(sql, [id]);

        // console.log('Fetched Record:', rows); // Debugging: Log fetched data

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Analytic-section record not found' });
        }

        res.status(200).json(rows[0]); // Return the first record
    } catch (err) {
        console.error('Error fetching analytic-section record:', err.message);
        res.status(500).json({ message: 'Error fetching analytic-section record' });
    }
});

app.put('/api/analytic-section/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    const { name, section, data } = req.body;

    // Validate required fields
    if (!name || !section || !data) {
        return res.status(400).json({ message: 'Name, Section, and Data are required' });
    }

    try {
        const sql = `
            UPDATE analytic_section
            SET name = ?, section = ?, data = ?, updated_at = NOW()
            WHERE id = ?
        `;
        const [result] = await db.query(sql, [name, section, data, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Analytic-section record not found' });
        }

        res.status(200).json({ message: 'Analytic-section record updated successfully' });
    } catch (err) {
        console.error('Error updating analytic-section record:', err.message);
        res.status(500).json({ message: 'Error updating analytic-section record' });
    }
});

app.delete('/api/analytic-section/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        const sql = `DELETE FROM analytic_section WHERE id = ?`; // Replace with your table name
        const [result] = await db.query(sql, [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Analytic section not found' });
        }

        res.status(200).json({ message: 'Analytic section deleted successfully' });
    } catch (err) {
        console.error('Error deleting analytic section:', err.message);
        res.status(500).json({ message: 'Error deleting analytic section' });
    }
});

// Countries
app.post('/api/countries', authenticate, async (req, res) => {
    // console.log('Received data:', req.body);

    const { name, code, status } = req.body;

    // Validate required fields
    if (!name || !code || !status) {
        return res.status(400).json({ message: 'Name, Code, and Status are required fields' });
    }

    try {
        const sql = `
            INSERT INTO countries (name, code, status)
            VALUES (?, ?, ?)
        `;
        const [result] = await db.query(sql, [name, code, status]);

        res.status(201).json({
            id: result.insertId,
            name,
            code,
            status,
        });
    } catch (err) {
        console.error('Error inserting country record:', err.message);
        res.status(500).json({ message: 'Error saving country record' });
    }
});

app.get('/api/countries', authenticate, async (req, res) => {
    // console.log('Fetching all countries');

    try {
        // Query to get all countries from the database
        const sql = 'SELECT id, name, code, status FROM countries';
        const [rows] = await db.query(sql);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'No countries found' });
        }

        res.status(200).json(rows); // Send the list of countries
    } catch (err) {
        console.error('Error fetching country records:', err.message);
        res.status(500).json({ message: 'Error retrieving country records' });
    }
});

app.get('/api/countries/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    // Validate the ID
    if (!id || isNaN(id)) {
        return res.status(400).json({ message: 'Invalid ID parameter' });
    }

    try {
        const sql = `SELECT id, name, code, status FROM countries WHERE id = ?`;
        const [rows] = await db.query(sql, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Country record not found' });
        }

        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching country record:', err.message);
        res.status(500).json({ message: 'Error retrieving country record' });
    }
});

app.delete('/api/countries/:id', authenticate, async (req, res) => {
    const { id } = req.params;  // Extract the country ID from the URL parameters

    try {
        const sql = `DELETE FROM countries WHERE id = ?`; // Using the 'countries' table
        const [result] = await db.query(sql, [id]);  // Run the DELETE query

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Country not found' });  // If no rows are affected, the country doesn't exist
        }

        res.status(200).json({ message: 'Country deleted successfully' });  // Return a success message
    } catch (err) {
        console.error('Error deleting country:', err.message);
        res.status(500).json({ message: 'Error deleting country' });  // Handle any server errors
    }
});

app.put('/api/countries/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    const { name, code, status } = req.body;

    if (!name || !code || !status) {
        return res.status(400).json({ message: 'Name, code, and status are required.' });
    }

    try {
        const sql = 'UPDATE countries SET name = ?, code = ?, status = ? WHERE id = ?';
        const [result] = await db.query(sql, [name, code, status, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Country not found.' });
        }

        res.json({ id, name, code, status });
    } catch (error) {
        console.error('Error updating country:', error.message);
        res.status(500).json({ message: 'Error updating country.' });
    }
});


// States
app.post('/api/states', authenticate, async (req, res) => {
    // // console.log('Received data:', req.body);

    const { name, country, status } = req.body;

    // Validate required fields
    if (!name || !country || !status) {
        return res.status(400).json({ message: 'Name, Country, and Status are required fields' });
    }

    try {
        const sql = `
            INSERT INTO states (name, country, status)
            VALUES (?, ?, ?)
        `;
        const [result] = await db.query(sql, [name, country, status]);

        res.status(201).json({
            id: result.insertId,
            name,
            country,
            status,
        });
    } catch (err) {
        console.error('Error inserting state record:', err.message);
        res.status(500).json({ message: 'Error saving state record' });
    }
});

app.get('/api/states', authenticate, async (req, res) => {
    // console.log('Fetching all states');

    try {
        const sql = `
            SELECT id, name, country, status
            FROM states
        `;
        const [rows] = await db.query(sql);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'No states found' });
        }

        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching states:', err.message);
        res.status(500).json({ message: 'Error retrieving state records' });
    }
});

app.delete('/api/states/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    if (!id || isNaN(id)) {
        return res.status(400).json({ message: 'Invalid ID parameter' });
    }

    try {
        const sql = 'DELETE FROM states WHERE id = ?';
        const [result] = await db.query(sql, [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'State not found' });
        }

        res.status(200).json({ message: 'State deleted successfully' });
    } catch (err) {
        console.error('Error deleting state record:', err.message);
        res.status(500).json({ message: 'Error deleting state record' });
    }
});


app.get('/api/states/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        const sql = `SELECT id, name, country, status FROM states WHERE id = ?`;
        const [rows] = await db.query(sql, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'State not found' });
        }

        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching state:', err.message);
        res.status(500).json({ message: 'Error retrieving state' });
    }
});

app.put('/api/states/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    const { name, country, status } = req.body;

    if (!name || !country || !status) {
        return res.status(400).json({ message: 'Name, Country, and Status are required fields.' });
    }

    try {
        const sql = `UPDATE states SET name = ?, country = ?, status = ? WHERE id = ?`;
        const [result] = await db.query(sql, [name, country, status, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'State not found.' });
        }

        res.status(200).json({ id, name, country, status });
    } catch (err) {
        console.error('Error updating state:', err.message);
        res.status(500).json({ message: 'Error updating state.' });
    }
});

// Cities
app.post('/api/cities', authenticate, async (req, res) => {
    const { name, state, status } = req.body; // Change `country` to `state`

    // Validate required fields
    if (!name || !state || !status) {
        return res.status(400).json({ message: 'Name, State, and Status are required fields' });
    }

    try {
        const sql = `
            INSERT INTO cities (name, state, status)
            VALUES (?, ?, ?)
        `; // Update table name to `cities` and field to `state`
        const [result] = await db.query(sql, [name, state, status]);

        res.status(201).json({
            id: result.insertId,
            name,
            state, // Reflect the updated field
            status,
        });
    } catch (err) {
        console.error('Error inserting city record:', err.message); // Adjust log message
        res.status(500).json({ message: 'Error saving city record' }); // Adjust response message
    }
});

app.get('/api/cities', authenticate, async (req, res) => {
    // console.log('Fetching all cities');

    try {
        const sql = `
            SELECT 
                cities.id, 
                cities.name, 
                states.name AS state_name, 
                cities.status 
            FROM cities
            LEFT JOIN states ON cities.state = states.id
        `;
        const [rows] = await db.query(sql);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'No cities found' });
        }

        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching city records:', err.message);
        res.status(500).json({ message: 'Error retrieving city records' });
    }
});

app.get('/api/cities/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        const sql = `
            SELECT 
                id, 
                name, 
                state, 
                status 
            FROM cities 
            WHERE id = ?
        `;
        const [rows] = await db.query(sql, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'City not found' });
        }

        res.status(200).json(rows[0]); // Send the first row as the response
    } catch (err) {
        console.error('Error fetching city record:', err.message);
        res.status(500).json({ message: 'Error retrieving city record' });
    }
});

app.put('/api/cities/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    const { name, state, status } = req.body;

    if (!name || !state || !status) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const sql = `
            UPDATE cities
            SET name = ?, state = ?, status = ?
            WHERE id = ?
        `;
        const [result] = await db.query(sql, [name, state, status, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'City not found' });
        }

        res.status(200).json({ id, name, state, status });
    } catch (err) {
        console.error('Error updating city:', err.message);
        res.status(500).json({ message: 'Error updating city' });
    }
});

// DELETE /api/cities/:id
app.delete('/api/cities/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // Check if the city exists
        const checkCitySql = 'SELECT * FROM cities WHERE id = ?';
        const [city] = await db.query(checkCitySql, [id]);

        if (city.length === 0) {
            return res.status(404).json({ message: 'City record not found' });
        }

        // Delete the city record
        const deleteCitySql = 'DELETE FROM cities WHERE id = ?';
        const [result] = await db.query(deleteCitySql, [id]);

        if (result.affectedRows === 0) {
            return res.status(500).json({ message: 'Failed to delete city record' });
        }

        res.status(200).json({
            message: 'City record deleted successfully',
            id: id
        });
    } catch (error) {
        console.error('Error deleting city record:', error.message);
        res.status(500).json({ message: 'Error deleting city record', error: error.message });
    }
});

// Push Notifications
app.post('/api/push-notifications', authenticate, upload.single('image'), async (req, res) => {
    const {
        role,
        user,
        title,
        description = 'NA' // Default value for optional field
    } = req.body;

    // Validate required fields
    if (!role || !user || !title) {
        return res.status(400).json({ message: 'Role, User, and Title are required fields' });
    }

    // Get the file path from the uploaded file
    const imagePath = req.file ? req.file.path : null;

    try {
        // SQL query to insert new push notification record
        const sql = `
            INSERT INTO push_notifications (role, user, title, image_path, description)
            VALUES (?, ?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [role, user, title, imagePath, description]);

        // Send response with new record details
        res.status(201).json({
            id: result.insertId,
            role,
            user,
            title,
            image: imagePath,
            description
        });
    } catch (err) {
        console.error('Error inserting push notification record:', err.message);
        res.status(500).json({ message: 'Error saving push notification record' });
    }
});

app.get('/api/push-notifications', authenticate, async (req, res) => {
    try {
        // SQL query to fetch all push notifications
        const sql = `SELECT id, role, user, title, image_path AS image, description FROM push_notifications`;
        const [rows] = await db.query(sql);

        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching push notification records:', err.message);
        res.status(500).json({ message: 'Error retrieving push notifications' });
    }
});

app.get('/api/push-notifications/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        const sql = `SELECT id, role, user, title, description, image_path AS image FROM push_notifications WHERE id = ?`;
        const [rows] = await db.query(sql, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Push notification not found.' });
        }

        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching push notification:', err.message);
        res.status(500).json({ message: 'Error retrieving push notification.' });
    }
});

app.delete('/api/push-notifications/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to delete a notification by ID
        const sql = `DELETE FROM push_notifications WHERE id = ?`;
        const [result] = await db.query(sql, [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Push notification not found' });
        }

        res.status(200).json({ message: 'Push notification deleted successfully' });
    } catch (err) {
        console.error('Error deleting push notification:', err.message);
        res.status(500).json({ message: 'Error deleting push notification' });
    }
});

app.post('/api/admin/paypal', authenticate, async (req, res) => {
    const { client_id, client_secret, environment } = req.body;

    if (!client_id || !client_secret || !environment) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const sql = `
            REPLACE INTO paypal_settings (id, client_id, client_secret, environment)
            VALUES (1, ?, ?, ?)
        `;
        await db.query(sql, [client_id, client_secret, environment]);
        res.status(200).json({ message: 'PayPal settings updated successfully' });
    } catch (err) {
        console.error('Error updating PayPal settings:', err.message);
        res.status(500).json({ message: 'Error updating PayPal settings' });
    }
});

app.get('/api/admin/paypal', authenticate, async (req, res) => {
    try {
        const sql = `
            SELECT client_id, client_secret, environment
            FROM paypal_settings
            LIMIT 1
        `;
        const [rows] = await db.query(sql);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'PayPal settings not found' });
        }

        const settings = rows[0];
        res.status(200).json(settings);
    } catch (err) {
        console.error('Error fetching PayPal settings:', err.message);
        res.status(500).json({ message: 'Error retrieving PayPal settings' });
    }
});




app.post('/api/roles-permissions', authenticate, async (req, res) => {
    const { name } = req.body;

    // Validate required field
    if (!name) {
        return res.status(400).json({ message: 'Name is required' });
    }

    try {
        // SQL query to insert new role or permission
        const sql = `
            INSERT INTO roles_and_permissions (name)
            VALUES (?)
        `;
        const [result] = await db.query(sql, [name]);

        // Send response with new role or permission details
        res.status(201).json({
            id: result.insertId,
            name
        });
    } catch (err) {
        console.error('Error inserting role or permission:', err.message);
        res.status(500).json({ message: 'Error saving role or permission' });
    }
});

app.post('/api/subscribers', authenticate, async (req, res) => {
    // console.log('Received data:', req.body); // Log the incoming request body

    const { subject, message } = req.body;

    // Validate required fields
    if (!subject || !message) {
        return res.status(400).json({ message: 'Subject and Message are required fields' });
    }

    try {
        const sql = `
            INSERT INTO subscribers (subject, message)
            VALUES (?, ?)
        `;
        const [result] = await db.query(sql, [subject, message]);

        res.status(201).json({
            id: result.insertId,
            subject,
            message,
        });
    } catch (err) {
        console.error('Error inserting subscriber record:', err.message);
        res.status(500).json({ message: 'Error saving subscriber record' });
    }
});






// POS orders

// API to store order data
app.post("/api/store-pos-data", (req, res) => {
    const {
        customerType,
        orderID,
        orderDate,
        orderTime,
        paymentType,
        discountValue,
        subtotal,
        tax,
        quantity,
        productName,
        color,
        size,
        imagePath,
        total,
    } = req.body;
    // SQL query to insert data into the `pos` table
    const query = `
    INSERT INTO pos (
        customerType, orderID, orderDate, orderTime, paymentType,
        discountValue, subtotal, tax, quantity, productName,
        color, size, imagePath, total, orderType, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'POS', 'Pending')
`;

    db.query(
        query,
        [
            customerType,
            orderID,
            orderDate,
            orderTime,
            paymentType,
            discountValue,
            subtotal,
            tax,
            quantity,
            productName,
            color,
            size,
            imagePath,
            total,
        ],
        (err, result) => {
            if (err) {
                console.error("Error storing order in the database:", err);
                return res.status(500).json({ error: "Database error" });
            }
            res.status(200).json({ message: "Order stored successfully", orderId: result.insertId });
        }
    );

});

app.get("/api/orders/:id", async (req, res) => {
    const { id } = req.params; // Extract id from the request URL
    // console.log("Received request to fetch order details for ID:", id); // Log the order ID

    try {
        const query = `
            SELECT 
                id,
                orderID, 
                customerType AS customer, 
                orderDate, 
                orderTime, 
                paymentType, 
                discountValue, 
                subtotal, 
                tax, 
                quantity, 
                productName, 
                color, 
                size, 
                imagePath, 
                total, 
                orderType, 
                status
            FROM pos
            WHERE id = ? 
        `;

        // console.log("Executing query to fetch order details..."); // Log before running the query
        const [results] = await db.query(query, [id]); // Use parameterized queries for security
        // console.log("Query executed successfully:", results); // Log the query results

        if (results.length === 0) {
            console.warn(`No order found for ID: ${id}`); // Log a warning if no order is found
            return res.status(404).json({ error: "Order not found" }); // Handle case when order doesn't exist
        }

        // console.log(`Order details fetched for ID: ${id}:`, results[0]); // Log the fetched order details
        res.status(200).json(results[0]); // Send the first result (since orderID is unique)
    } catch (err) {
        console.error("Error occurred while fetching order details:", err); // Log the error
        res.status(500).json({ error: "Database query failed" });
    }
});

app.get("/api/get-pos-orders", async (req, res) => {
    try {
        const query = `
            SELECT 
                id,
                orderID, 
                customerType AS customer, 
                subtotal AS amount, 
                CONCAT(orderTime, ', ', DATE_FORMAT(orderDate, '%d-%m-%Y')) AS date, 
                status 
            FROM pos 
            ORDER BY id DESC
        `;

        const [results] = await db.query(query); // Use async/await here
        res.status(200).json(results); // Send the results to the frontend
    } catch (err) {
        console.error("Error fetching POS orders:", err);
        res.status(500).json({ error: "Database query failed" });

    }
});
app.delete("/api/delete-pos-order/:id", async (req, res) => {
    const { id } = req.params; // Extract id from the request URL
    // console.log("Order ID to delete:", id); // Log the id for debugging

    try {
        // Execute the DELETE query based on id
        const query = "DELETE FROM pos WHERE id = ?";
        const [result] = await db.query(query, [id]);

        if (result.affectedRows > 0) {
            // If the query deleted at least one row
            res.status(200).json({ message: "Order deleted successfully." });
        } else {
            // If no rows were deleted (e.g., id not found)
            res.status(404).json({ message: "Order not found." });
        }
    } catch (error) {
        // Log any errors and send a 500 status
        console.error("Error deleting order:", error);
        res.status(500).json({ error: "Database error occurred." });
    }
});



//shiping setup
app.post('/api/orders123', async (req, res) => {
    const { country, state, city, shippingCost, orderStatus } = req.body;

    // console.log('Received data:', req.body); // Log incoming data for debugging

    // Validation
    if (!country || !state || !city || !shippingCost || !orderStatus) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    const sql = `
      INSERT INTO area_shipping (country, state, city, shipping_cost, order_status)
      VALUES (?, ?, ?, ?, ?)
    `;

    try {
        // Use the database query with async/await
        const [result] = await db.query(sql, [country, state, city, shippingCost, orderStatus]);

        // Send success response
        res.status(201).json({
            message: 'Data saved successfully!',
            orderId: result.insertId,
            orderData: { country, state, city, shippingCost, orderStatus },
        });
    } catch (err) {
        console.error('Error saving the order:', err.message);
        res.status(500).json({ message: 'Error saving the order.', error: err.message });
    }
});

// API to fetch orders
app.get('/api/orders123', async (req, res) => {
    const sql = 'SELECT * FROM area_shipping';

    try {
        const [rows] = await db.query(sql); // Using mysql2 with promises
        res.status(200).json({ orders: rows });
    } catch (err) {
        console.error('Error fetching data:', err.message);
        res.status(500).json({ message: 'Error fetching data', error: err.message });
    }
});


app.get('/api/order/:id', (req, res) => {
    const orderId = req.params.id;
    // console.log('Fetching order with ID:', orderId); // Log the order ID received

    const sql = 'SELECT * FROM area_shipping WHERE id = ?';

    db.query(sql, [orderId], (err, result) => {
        if (err) {
            console.error('Error fetching data:', err.message); // Log the error if query fails
            return res.status(500).json({ message: 'Error fetching data', error: err.message });
        }

        if (result.length > 0) {
            // console.log('Order found:', result[0]); // Log the found order
            res.status(200).json({ order: result[0] }); // Send the order data to the frontend
        } else {
            // console.log('Order not found with ID:', orderId); // Log if no order found
            res.status(404).json({ message: 'Order not found' }); // Send error if order not found
        }
    });
});
// Get order by ID
app.get('/api/order/:id', async (req, res) => {
    const orderId = req.params.id;
    const sql = 'SELECT * FROM area_shipping WHERE id = ?';

    try {
        // console.log(`Fetching order with ID: ${orderId}`); // Log the order ID being fetched

        const [rows] = await db.query(sql, [orderId]);

        // Log the raw result from the database
        // console.log('Database response:', rows);

        if (rows.length === 0) {
            console.warn(`Order with ID ${orderId} not found`);
            return res.status(404).json({ message: 'Order not found' });
        }

        res.status(200).json({ order: rows[0] });
    } catch (err) {
        console.error('Error fetching order:', err.message);
        res.status(500).json({ message: 'Error fetching order', error: err.message });
    }
});


// Update order by ID
app.put('/api/order/:id', async (req, res) => {
    const orderId = req.params.id;
    const { country, state, city, shipping_cost, order_status } = req.body;
    const sql = `
        UPDATE area_shipping 
        SET country = ?, state = ?, city = ?, shipping_cost = ?, order_status = ? 
        WHERE id = ?
    `;

    try {
        const [result] = await db.query(sql, [country, state, city, shipping_cost, order_status, orderId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }
        res.status(200).json({ message: 'Order updated successfully' });
    } catch (err) {
        console.error('Error updating order:', err.message);
        res.status(500).json({ message: 'Error updating order', error: err.message });
    }
});

// Assuming you're using a MySQL database with a 'db' object that has a 'query' method

app.delete('/api/order/:orderId', (req, res) => {
    const orderId = req.params.orderId;

    // SQL query to delete the order by its ID
    const query = 'DELETE FROM area_shipping WHERE id = ?';

    // Execute the query
    db.query(query, [orderId], (err, result) => {
        if (err) {
            console.error('Error deleting order:', err);
            return res.status(500).json({ error: 'Failed to delete order' });
        }

        // Check if the order was deleted
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        return res.status(200).json({ message: 'Order deleted successfully' });
    });
});


app.put('/api/orders123/:id', (req, res) => {
    const orderId = req.params.id;
    const { country, state, city, shippingCost, orderStatus } = req.body;

    const sql = `
      UPDATE area_shipping
      SET country = ?, state = ?, city = ?, shipping_cost = ?, order_status = ?
      WHERE id = ?
    `;

    db.query(sql, [country, state, city, shippingCost, orderStatus, orderId], (err, result) => {
        if (err) {
            console.error('Error updating order:', err.message);
            return res.status(500).json({ message: 'Error updating order', error: err.message });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Order updated successfully!' });
        } else {
            res.status(404).json({ message: 'Order not found' });
        }
    });
});


// API Endpoint to store Twilio gateway configuration
app.post('/api/save-twilio-config', async (req, res) => {
    const { twilioSid, twilioToken, twilioFrom, twilioStatus } = req.body;

    // Validate Twilio fields
    if (!twilioSid || !twilioToken || !twilioFrom) {
        return res.status(400).json({ message: 'All Twilio fields are required' });
    }

    const query = `INSERT INTO gateway_configuration (gateway_type, twilio_account_sid, twilio_auth_token, twilio_from, twilio_status)
                   VALUES (?, ?, ?, ?, ?)`;

    const queryParams = ['Twilio', twilioSid, twilioToken, twilioFrom, twilioStatus];

    try {
        // Execute query using promise-based method
        const [result] = await db.query(query, queryParams); // Await the promise returned by db.query()

        res.status(201).json({
            message: 'Twilio configuration saved successfully',
            data: result
        });
    } catch (err) {
        console.error('Error saving Twilio configuration:', err);
        res.status(500).json({ message: 'Internal server error', details: err.message });
    }
});

// API Endpoint to fetch all gateway configurations
app.get('/api/get-gateway-configs', async (req, res) => {
    try {
        const query = 'SELECT * FROM gateway_configuration'; // SQL query to fetch all records
        const [results] = await db.query(query);  // Execute query with promises

        res.status(200).json(results); // Return the results as JSON
    } catch (err) {
        console.error('Error fetching gateway configurations:', err);
        res.status(500).json({ message: 'Internal server error', details: err.message });
    }
});

// API Endpoint to store Clickatell gateway configuration
app.post('/api/save-clickatell-config', async (req, res) => {
    const { clickatellApikey, clickatellStatus } = req.body;

    // Validate the Clickatell fields
    if (!clickatellApikey || !clickatellStatus) {
        return res.status(400).json({ message: 'Clickatell API Key and Status are required' });
    }

    const query = `INSERT INTO gateway_configuration (gateway_type, clickatell_apikey, clickatell_status)
                   VALUES (?, ?, ?)`;

    const queryParams = ['Clickatell', clickatellApikey, clickatellStatus];

    try {
        // Execute the query using promise-based method
        const [result] = await db.query(query, queryParams); // Await the promise returned by db.query()

        res.status(201).json({
            message: 'Clickatell configuration saved successfully',
            data: result
        });
    } catch (err) {
        console.error('Error saving Clickatell configuration:', err);
        res.status(500).json({ message: 'Internal server error', details: err.message });
    }
});

// API Endpoint to store Nexmo gateway configuration
app.post('/api/save-nexmo-config', async (req, res) => {
    const { nexmoKey, nexmoSecret, nexmoStatus } = req.body;

    // Validate the Nexmo fields
    if (!nexmoKey || !nexmoSecret) {
        return res.status(400).json({ message: 'Nexmo Key and Secret are required' });
    }

    const query = `INSERT INTO gateway_configuration (gateway_type, nexmo_key, nexmo_secret, nexmo_status)
                   VALUES (?, ?, ?, ?)`;

    const queryParams = ['Nexmo', nexmoKey, nexmoSecret, nexmoStatus];

    try {
        // Execute query using promise-based method
        const [result] = await db.query(query, queryParams); // Await the promise returned by db.query()

        res.status(201).json({
            message: 'Nexmo configuration saved successfully',
            data: result
        });
    } catch (err) {
        console.error('Error saving Nexmo configuration:', err);
        res.status(500).json({ message: 'Internal server error', details: err.message });
    }
});



// Add New Company API
app.post('/api/save-company', async (req, res) => {
    const {
        companyName,
        email,
        latitude,
        longitude,
        website,
        phone,
        city,
        zipCode,
        state,
        countryCode,
        address,
    } = req.body;

    // Validate required fields
    if (!companyName || !email || !latitude || !longitude || !website || !phone || !city || !zipCode || !state || !countryCode || !address) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // SQL query to insert company data into the database
        const sql = `
        INSERT INTO company (
          companyName, email, latitude, longitude, website, phone, city, zipCode, state, countryCode, address
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

        // Execute the query to insert the company data
        const [result] = await db.query(sql, [
            companyName,
            email,
            latitude,
            longitude,
            website,
            phone,
            city,
            zipCode,
            state,
            countryCode,
            address,
        ]);

        // Send response with company details
        res.status(201).json({
            id: result.insertId, // Return the inserted company's ID
            companyName,
            email,
            latitude,
            longitude,
            website,
            phone,
            city,
            zipCode,
            state,
            countryCode,
            address,
        });
    } catch (err) {
        console.error('Error saving company information:', err.message);
        res.status(500).json({ message: 'Error saving company information', error: err.message });
    }
});

// Add New Cookies Configuration API
app.post('/api/cookies', async (req, res) => {
    const { cookiesDetailsPage, cookiesSummary } = req.body;

    // Validate required fields
    if (!cookiesDetailsPage || !cookiesSummary) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // SQL query to insert cookies configuration data into the database
        const sql = `
        INSERT INTO cookies (cookiesDetailsPage, cookiesSummary)
        VALUES (?, ?)
      `;

        // Execute the query to insert the cookies configuration data
        const [result] = await db.query(sql, [
            cookiesDetailsPage,
            cookiesSummary,
        ]);

        // Send response with cookies configuration details
        res.status(201).json({
            id: result.insertId, // Return the inserted record's ID
            cookiesDetailsPage,
            cookiesSummary,
        });
    } catch (err) {
        console.error('Error saving cookies configuration:', err.message);
        res.status(500).json({ message: 'Error saving cookies configuration', error: err.message });
    }
});

// Add New Social Media Configuration API
app.post('/api/social-media', async (req, res) => {
    const { facebook, youtube, twitter, instagram } = req.body;

    // Validate required fields
    if (!facebook || !youtube || !twitter || !instagram) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // SQL query to insert social media data into the database
        const socialMediaSql = `
        INSERT INTO social_media (facebook, youtube, twitter, instagram)
        VALUES (?, ?, ?, ?)
      `;

        // Execute the query to insert the social media data
        const [socialMediaResult] = await db.query(socialMediaSql, [
            facebook,
            youtube,
            twitter,
            instagram
        ]);

        // Send response with social media details
        res.status(201).json({
            socialMediaId: socialMediaResult.insertId, // ID of the inserted social media record
            facebook,
            youtube,
            twitter,
            instagram
        });
    } catch (err) {
        console.error('Error saving social media configuration:', err.message);
        res.status(500).json({
            message: 'Error saving social media configuration',
            error: err.message
        });
    }
});



//   ``
// API endpoint to save notification settings
app.post('/api/save-alerts', async (req, res) => {
    const data = req.body; // Data sent from the frontend form
    const {
        notification_type,
        order_pending_message,
        order_confirmation_message,
        order_on_the_way_message,
        order_delivered_message,
        order_canceled_message,
        order_rejected_message,
        admin_new_order_message,
        order_pending_status,
        order_confirmation_status,
        order_on_the_way_status,
        order_delivered_status,
        order_canceled_status,
        order_rejected_status,
        admin_new_order_status
    } = data;

    // MySQL query to insert data into the 'alerts' table
    const query = `
      INSERT INTO alerts (
        notification_type, 
        order_pending_message, 
        order_confirmation_message, 
        order_on_the_way_message, 
        order_delivered_message, 
        order_canceled_message, 
        order_rejected_message, 
        admin_new_order_message, 
        order_pending_status, 
        order_confirmation_status, 
        order_on_the_way_status, 
        order_delivered_status, 
        order_canceled_status, 
        order_rejected_status, 
        admin_new_order_status
      ) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const values = [
        notification_type,
        order_pending_message,
        order_confirmation_message,
        order_on_the_way_message,
        order_delivered_message,
        order_canceled_message,
        order_rejected_message,
        admin_new_order_message,
        order_pending_status,
        order_confirmation_status,
        order_on_the_way_status,
        order_delivered_status,
        order_canceled_status,
        order_rejected_status,
        admin_new_order_status
    ];

    try {
        // Wait for the query to complete
        const result = await queryAsync(query, values);
        res.status(200).send({ message: 'Data saved successfully', result });
    } catch (err) {
        console.error('Error inserting data: ' + err.stack);
        res.status(500).send({ message: 'Error saving data', error: err.message });
    }
});


// API to save notification data
app.post('/api/save-notification', async (req, res) => {
    try {
        const {
            firebaseSecretKey,
            firebasePublicVapidKey,
            firebaseApiKey,
            firebaseAuthDomain,
            firebaseProjectId,
            firebaseStorageBucket,
            firebaseMessageSenderId,
            firebaseAppId,
            firebaseMeasurementId,
        } = req.body;

        // Prepare the query to insert data into the notification table
        const query = `
        INSERT INTO notification (
          firebaseSecretKey, firebasePublicVapidKey, firebaseApiKey,
          firebaseAuthDomain, firebaseProjectId, firebaseStorageBucket,
          firebaseMessageSenderId, firebaseAppId, firebaseMeasurementId
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

        // Insert data into the database
        const result = await new Promise((resolve, reject) => {
            db.query(
                query,
                [
                    firebaseSecretKey,
                    firebasePublicVapidKey,
                    firebaseApiKey,
                    firebaseAuthDomain,
                    firebaseProjectId,
                    firebaseStorageBucket,
                    firebaseMessageSenderId,
                    firebaseAppId,
                    firebaseMeasurementId,
                ],
                (err, result) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(result);
                    }
                }
            );
        });

        // Send a success response
        res.status(201).json({
            message: 'Notification configuration saved successfully!',
            data: result,
        });
    } catch (error) {
        console.error('Error saving notification configuration:', error);
        res.status(500).json({
            message: 'Error saving notification configuration',
            error: error.message,
        });
    }
});


// Add New Mail Configuration API
app.post('/api/save-mail-config', async (req, res) => {
    const {
        mailHost,
        mailPort,
        mailUsername,
        mailPassword,
        mailFromName,
        mailFromEmail,
        mailEncryption,
    } = req.body;

    // Validate required fields
    if (!mailHost || !mailPort || !mailUsername || !mailPassword || !mailFromName || !mailFromEmail || !mailEncryption) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // SQL query to insert mail configuration data into the database
        const sql = `
        INSERT INTO mail_configuration (
          mail_host, mail_port, mail_username, mail_password, mail_from_name, mail_from_email, mail_encryption
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `;

        // Execute the query to insert the mail configuration data
        const [result] = await db.query(sql, [
            mailHost,
            mailPort,
            mailUsername,
            mailPassword,
            mailFromName,
            mailFromEmail,
            mailEncryption,
        ]);

        // Send response with mail configuration details
        res.status(201).json({
            id: result.insertId, // Return the inserted record's ID
            mailHost,
            mailPort,
            mailUsername,
            mailFromName,
            mailFromEmail,
            mailEncryption,
        });
    } catch (err) {
        console.error('Error saving mail configuration:', err.message);
        res.status(500).json({ message: 'Error saving mail configuration', error: err.message });
    }
});



// app.get('/api/area', async (req, res) => {
//     try {
//       const [rows] = await db.query('SELECT country, city, , status FROM shippingArea');
//       res.status(200).json(rows);
//     } catch (err) {
//       console.error('Error fetching sliders:', err.message);
//       res.status(500).json({ message: 'Error fetching sliders', error: err.message });
//     }
//   });

app.post('/api/site', async (req, res) => {
    const {
        dateFormat, timeFormat, defaultTimezone, defaultLanguage, defaultCurrency,
        copyright, androidAppLink, iosAppLink, nonPurchaseProductQuantity, digitAfterDecimal,
        currencyPosition, returnProductPrice, languageSwitch, cashOnDelivery,
        onlinePayment, phoneVerification, autoUpdate, emailVerification, appdebug, address
    } = req.body;

    try {
        const query = `INSERT INTO site (dateFormat, timeFormat, defaultTimezone, defaultLanguage, defaultCurrency, copyright, 
        androidAppLink, iosAppLink, nonPurchaseProductQuantity, digitAfterDecimal, currencyPosition, returnProductPrice, 
        languageSwitch, cashOnDelivery, onlinePayment, phoneVerification, autoUpdate, emailVerification, appdebug, address)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        const values = [dateFormat, timeFormat, defaultTimezone, defaultLanguage, defaultCurrency, copyright,
            androidAppLink, iosAppLink, nonPurchaseProductQuantity, digitAfterDecimal, currencyPosition, returnProductPrice,
            languageSwitch, cashOnDelivery, onlinePayment, phoneVerification, autoUpdate, emailVerification, appdebug, address];

        // Use a promise-based query
        await new Promise((resolve, reject) => {
            db.query(query, values, (err, result) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(result);
                }
            });
        });

        // If successful, send success message
        res.status(200).json({ message: 'Site information saved successfully!' });

    } catch (err) {
        console.error('Error saving site information:', err);
        // Send error message if an error occurs
        res.status(500).json({ error: 'Error saving site information' });
    }
});


// API Endpoint to Add a New Supplier (No Authentication Required)
app.post('/api/suppliers', upload.single('image'), async (req, res) => {
    try {
        // Extract data from the request body
        const {
            name,
            email,
            phone,
            country,
            state,
            city,
            zip_code,
            address,
            company,
        } = req.body;

        // Validate required fields
        if (!name || !email || !phone || !country || !state || !city || !zip_code || !address || !company) {
            return res.status(400).json({
                message: 'All fields (name, email, phone, country, state, city, zip_code, address, company) are required.',
            });
        }

        // Check if a file was uploaded
        if (!req.file) {
            return res.status(400).json({ message: 'Image upload is required.' });
        }

        // Get file path in the format `uploads/<filename>`
        const imageFilePath = `uploads/${req.file.filename}`;

        // Insert supplier data into the database
        const query = `
            INSERT INTO suppliers (
                name,
                email,
                phone,
                country,
                state,
                city,
                zip_code,
                address,
                company,
                image,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
        `;

        const [result] = await db.query(query, [
            name,
            email,
            phone,
            country,
            state,
            city,
            zip_code,
            address,
            company,
            imageFilePath, // Save the file path like `uploads/<filename>`
        ]);

        // Return success response
        res.status(201).json({
            message: `Supplier ${name} added successfully.`,
            supplierId: result.insertId,
        });
    } catch (error) {
        console.error('Error saving supplier:', error);

        // Check for duplicate entry error
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({
                message: 'A supplier with this email already exists.',
            });
        }

        // General server error response
        res.status(500).json({
            message: 'Failed to save supplier. Please try again later.',
        });
    }
});
//sliders

// API to handle slider data  
// app.post('/api/slider', upload.single('image'), async (req, res) => {
//     try {
//       const { title, link, status, description } = req.body;
//       const image = req.file ? req.file.filename : null;

//       // Validate required fields
//       if (!title || !image || !status) {
//         return res.status(400).json({ message: 'Title, image, and status are required' });
//       }

//       // Insert data into the slider table
//       const sql = `
//         INSERT INTO slider (title, link, image, status, description)
//         VALUES (?, ?, ?, ?, ?)
//       `;
//       const [result] = await db.query(sql, [title, link, image, status, description]);

//       res.status(201).json({
//         message: 'Slider saved successfully',
//         id: result.insertId,
//       });
//     } catch (err) {
//       console.error('Error saving slider:', err.message); 
//       res.status(500).json({ message: 'Error saving slider', error: err.message });
//     }
//   }); 


app.post('/api/slider', authenticate, upload.single('image'), async (req, res) => {
    const { title, link, status, description } = req.body;

    // Validate required fields
    if (!title || !status) {
        return res.status(400).json({ message: 'Title and Status are required fields' });
    }

    // Get the uploaded image file information
    const image = req.file; // Access the uploaded image file

    try {
        // SQL query to insert a new slider record
        const sql = `
            INSERT INTO slider (title, link, image, status, description)
            VALUES (?, ?, ?, ?, ?)
        `;
        const [result] = await db.query(sql, [
            title,
            link,
            image ? image.path : null, // Save the image path or null if no image is uploaded
            status,
            description || 'No description', // Default description if not provided
        ]);

        // Send response with the new slider details
        res.status(201).json({
            id: result.insertId,
            title,
            link,
            image_path: image ? image.path : null, // Send back the image path
            status,
            description: description || 'No description',
        });
    } catch (err) {
        console.error('Error saving slider record:', err.message);
        res.status(500).json({ message: 'Error saving slider record', error: err.message });
    }
});

// API to fetch all sliders
app.get('/api/sliders', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT id, title, status FROM slider');
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching sliders:', err.message);
        res.status(500).json({ message: 'Error fetching sliders', error: err.message });
    }
});

app.get('/api/slider/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await db.query('SELECT * FROM slider WHERE id = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Slider not found' });
        }
        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching slider:', err.message);
        res.status(500).json({ message: 'Error fetching slider', error: err.message });
    }
});

app.delete('/api/slider/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const sql = 'DELETE FROM slider WHERE id = ?';
        const [result] = await db.query(sql, [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Slider not found' });
        }

        res.status(200).json({ message: 'Slider deleted successfully' });
    } catch (err) {
        console.error('Error deleting slider:', err.message);
        res.status(500).json({ message: 'Error deleting slider', error: err.message });
    }
});

app.get('/api/slider/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await db.query('SELECT * FROM slider WHERE id = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Slider not found' });
        }
        res.status(200).json(rows[0]);
    } catch (err) {
        console.error('Error fetching slider:', err.message);
        res.status(500).json({ message: 'Error fetching slider', error: err.message });
    }
});

app.put('/api/slider/:id', upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { title, link, status, description } = req.body;
    const image = req.file ? req.file.filename : null;

    try {
        // SQL query to update the slider
        const sql = `
        UPDATE slider
        SET 
          title = ?, 
          link = ?, 
          status = ?, 
          description = ?, 
          image = COALESCE(?, image) -- Keep the existing image if not updated
        WHERE id = ?
      `;

        const [result] = await db.query(sql, [title, link, status, description, image, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Slider not found' });
        }

        res.status(200).json({ message: 'Slider updated successfully' });
    } catch (err) {
        console.error('Error updating slider:', err.message);
        res.status(500).json({ message: 'Error updating slider', error: err.message });
    }
});

app.put('/api/benefits/:id', upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { title, status, description } = req.body;
    const image = req.file ? req.file.filename : null;

    try {
        const sql = `
        UPDATE benefits
        SET 
          title = ?, 
          status = ?, 
          description = ?, 
          image = COALESCE(?, image) -- Retain existing image if not updated
        WHERE id = ?
      `;
        const [result] = await db.query(sql, [title, status, description, image, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Benefit not found' });
        }

        res.status(200).json({ message: 'Benefit updated successfully' });
    } catch (err) {
        console.error('Error updating benefit:', err.message);
        res.status(500).json({ message: 'Error updating benefit', error: err.message });
    }
});


//benefits
// Fetch All Benefits
app.get('/api/benefits', async (req, res) => {
    try {
        const sql = 'SELECT * FROM benefits';
        const [rows] = await db.query(sql);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'No benefits found' });
        }

        res.status(200).json(rows); // Send all benefits as JSON response
    } catch (err) {
        console.error('Error fetching benefits:', err.message);
        res.status(500).json({ message: 'Error fetching benefits', error: err.message });
    }
});

// API to add a benefit
app.post('/api/benefits', upload.single('image'), async (req, res) => {
    const { title, status, description } = req.body;
    const image = req.file ? req.file.filename : null;

    if (!title || !status || !image || !description) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const sql = `
        INSERT INTO benefits (title, status, image, description)
        VALUES (?, ?, ?, ?)
      `;
        const [result] = await db.query(sql, [title, status, image, description]);

        res.status(201).json({ message: 'Benefit added successfully', id: result.insertId });
    } catch (err) {
        console.error('Error adding benefit:', err.message);
        res.status(500).json({ message: 'Error adding benefit', error: err.message });
    }
});
app.get('/api/benefits/:id', async (req, res) => {
    const { id } = req.params;

    try {
        // SQL query to fetch the benefit
        const sql = 'SELECT * FROM benefits WHERE id = ?';
        const [rows] = await db.query(sql, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Benefit not found' });
        }

        res.status(200).json(rows[0]); // Send the first (and only) benefit as a JSON response
    } catch (err) {
        console.error('Error fetching benefit:', err.message);
        res.status(500).json({ message: 'Error fetching benefit', error: err.message });
    }
});


app.put('/api/benefits/:id', upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { title, status, description } = req.body;
    const image = req.file ? req.file.filename : null;

    try {
        const sql = `
        UPDATE benefits
        SET 
          title = ?, 
          status = ?, 
          description = ?, 
          image = COALESCE(?, image) -- Retain existing image if not updated
        WHERE id = ?
      `;
        const [result] = await db.query(sql, [title, status, description, image, id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Benefit not found' });
        }

        res.status(200).json({ message: 'Benefit updated successfully' });
    } catch (err) {
        console.error('Error updating benefit:', err.message);
        res.status(500).json({ message: 'Error updating benefit', error: err.message });
    }
});
app.delete('/api/benefits/:id', async (req, res) => {
    const { id } = req.params;
    // console.log("fhsj");
    try {
        const sql = 'DELETE FROM benefits WHERE id = ?';
        const [result] = await db.query(sql, [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Slider not found' });
        }

        res.status(200).json({ message: 'Benefits deleted successfully' });
    } catch (err) {
        console.error('Error deleting slider:', err.message);
        res.status(500).json({ message: 'Error deleting slider', error: err.message });
    }
});


//lisence key
app.post('/api/License', async (req, res) => {
    const { mailHost } = req.body;

    // Validate required fields
    if (!mailHost) {
        return res.status(400).json({ message: 'License key is required' });
    }

    try {
        // SQL query to insert license key into the database
        const sql = `
            INSERT INTO License (\`key\`) VALUES (?)
        `;

        // Execute the query to insert the license key
        const [result] = await db.query(sql, [mailHost]);

        // Send response with inserted license key details
        res.status(201).json({
            id: result.insertId, // Return the inserted record's ID
            key: mailHost,
        });
    } catch (err) {
        console.error('Error saving license key:', err.message);
        res.status(500).json({ message: 'Error saving license key', error: err.message });
    }
});

// POST route to add a page
app.post('/api/pages', upload.single('image'), async (req, res) => {
    try {
        const { title, status, menu_section, menu_template, description } = req.body;
        const created_at = new Date().toISOString().slice(0, 19).replace('T', ' ');

        const imagePath = `assets/images/products/${req.file.filename}`; // Adjusted image path

        // Log received fields
        // console.log("Received Data:", { title, status, menu_section, menu_template, description, created_at, image: imagePath });

        // Insert page data into the database
        const sql = 'INSERT INTO pages (title, status, menu_section, menu_template, image, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)';
        await queryPromise(sql, [title, status, menu_section, menu_template, imagePath, description, created_at]);

        res.status(200).json({ message: 'Page added successfully' });
    } catch (err) {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});
// GET route to fetch all pages
app.get('/api/pages', async (req, res) => {
    try {
        const sql = 'SELECT id, title, status, menu_section, menu_template, image, description, created_at FROM pages';

        // Use the promise-based query method (returns a promise)
        const [results] = await db.query(sql); // Destructure results from the query

        res.status(200).json(results); // Send results as JSON
    } catch (err) {
        console.error('Error fetching pages:', err);  // Log error to the console
        res.status(500).json({ error: 'Error fetching pages', details: err.message });
    }
});

// DELETE route to delete a page
app.delete('/api/pages/:id', async (req, res) => {
    const pageId = req.params.id; // Get the page ID from the URL parameter
    // console.log('Deleting page ID:', pageId);

    try {
        const sql = 'DELETE FROM pages WHERE id = ?';

        // Use the db.query() method and pass the pageId as a parameter
        const [result] = await db.query(sql, [pageId]);

        if (result.affectedRows > 0) {
            // console.log('Page deleted successfully');
            res.status(200).json({ message: 'Page deleted successfully' });
        } else {
            // console.log('Page not found');
            res.status(404).json({ message: 'Page not found' });
        }
    } catch (err) {
        console.error('Error deleting page:', err);
        res.status(500).json({ message: 'Server error', details: err.message });
    }
});



// GET route to fetch all pages
app.get('/api/pages/getPageById', async (req, res) => {
    const pageId = req.query.id;

    // console.log('Fetching page ID:', pageId);

    // Input validation
    if (!pageId) {
        return res.status(400).json({ error: 'Page ID is required' });
    }

    try {
        const sql = 'SELECT * FROM pages WHERE id = ?';

        // Use the promise-based query method (pass the pageId as a parameter)
        const [results] = await db.query(sql, [pageId]); // Pass pageId as the parameter for ?

        if (results.length > 0) {
            // Send the results as JSON if a page is found
            res.status(200).json(results[0]); // Return the first result if multiple rows are returned
        } else {
            // If no pages are found, send a 404 response
            res.status(404).json({ error: 'Page not found' });
        }
    } catch (err) {
        console.error('Error fetching pages:', err);  // Log error to the console
        res.status(500).json({ error: 'Error fetching pages', details: err.message });
    }
});

// PUT route to update a page
app.put('/api/pages/updatePage/:id', upload.single('image'), async (req, res) => {
    const pageId = req.params.id;
    const { title, status, description, menu_section } = req.body;
    const image = req.file ? req.file.filename : null;

    // console.log(`Updating page with ID: ${pageId}`);

    if (!title && !status && !description && !image && !menu_section) {
        return res.status(400).json({ error: 'At least one attribute is required to update' });
    }

    let query = 'UPDATE pages SET ';
    const params = [];

    if (title) {
        query += 'title = ?, ';
        params.push(title);
    }
    if (status) {
        query += 'status = ?, ';
        params.push(status);
    }
    if (description) {
        query += 'description = ?, ';
        params.push(description);
    }
    if (image) {
        query += 'image = ?, ';
        params.push(image);
    }
    if (menu_section) {
        query += 'menu_section = ?, ';
        params.push(menu_section);
    }

    query = query.slice(0, -2) + ' WHERE id = ?';
    params.push(pageId);

    try {
        const result = await queryPromise(query, params);

        if (result.affectedRows > 0) {
            // console.log("Page updated successfully");
            res.status(200).json({ message: 'Page updated successfully' });
        } else {
            // console.log("Page not found");
            res.status(404).json({ error: 'Page not found' });
        }
    } catch (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// Add Dummy Data Function
async function clearAndInsertDummyData() {
    try {
        // Clear existing admin users
        await db.query('DELETE FROM admin');
        // console.log('Existing admin users cleared.');
        // Insert dummy data
        await insertDummyUsers();
    } catch (err) {
        console.error('Error clearing and inserting dummy data:', err.message);
    }
}

async function insertDummyUsers() {
    const admin = [
        {
            name: "Jane Smith",
            email: "zani@example.com",
            phone: "0987654321",
            status: "inactive",
            password: "password456",
            confirm_password: "password456",
            role: "admin",
            address: "456 Maple Ave",
            country: "USA",
            state: "New York",
            city: "New York",
            zip_code: "10001"
        },
        {
            name: "Michael Johnson",
            email: "hello@example.com",
            phone: "1231231234",
            status: "active",
            password: "password789",
            confirm_password: "password789",
            role: "manager",
            address: "789 Oak Dr",
            country: "USA",
            state: "Texas",
            city: "Houston",
            zip_code: "77001"
        },
        {
            name: "Emily Davis",
            email: "sonu@example.com",
            phone: "3213214321",
            status: "active",
            password: "password101",
            confirm_password: "password101",
            role: "data entry",
            address: "321 Pine Ln",
            country: "USA",
            state: "Florida",
            city: "Miami",
            zip_code: "33101"
        },
        {
            name: "James Williams",
            email: "@example.com",
            phone: "4564564567",
            status: "active",
            password: "password102",
            confirm_password: "password102",
            role: "POS operator",
            address: "654 Elm St",
            country: "USA",
            state: "Illinois",
            city: "Chicago",
            zip_code: "60601"
        }
    ];

    try {
        const promises = admin.map(user => {
            const sql = 'INSERT INTO admin (name, email, phone, status, password, role, confirm_password, address, country, state, city, zip_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
            return db.query(sql, [
                user.name,
                user.email,
                user.phone,
                user.status,
                user.password,
                user.role,
                user.confirm_password,
                user.address,
                user.country,
                user.state,
                user.city,
                user.zip_code
            ]);
        });

        // Await all insertions
        await Promise.all(promises);
        // console.log('Dummy admin users inserted successfully');
    } catch (err) {
        console.error('Error inserting dummy admin users:', err.message);
    }
}

// Initialize the dummy data (uncomment if needed)
clearAndInsertDummyData();

// Fetch Admin Users
app.get('/api/admin', async (req, res) => {
    try {
        // Fetch users from the 'admin' table instead of 'users' table
        const [results] = await db.query('SELECT id, name, email, phone, status, role FROM admin');
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: 'Error fetching admin users: ' + err.message });
    }
});


// Add New User (Converted to promise-based)
app.post('/api/admin', async (req, res) => {
    const { name, email, phone, status, password, confirm_password, role, address, country, state, city, zip_code } = req.body;

    if (!name || !email || !phone || !status || !password || !confirm_password || !role || !address || !country || !state || !city || !zip_code) {
        return res.status(400).json({ message: "All fields are required" });
    }

    if (password !== confirm_password) {
        return res.status(400).json({ message: "Passwords do not match" });
    }

    try {
        const [existingUser] = await db.query('SELECT email FROM admin WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        const createdAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
        const sql = `INSERT INTO admin (name, email, phone, status, password, confirm_password, role, created_at, address, country, state, city, zip_code)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        await db.query(sql, [name, email, phone, status, password, confirm_password, role, createdAt, address, country, state, city, zip_code]);
        res.status(201).json({ message: 'User added successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Error adding user: ' + err.message });
    }
});
// Export Users to Excel (Converted to promise-based)
app.get('/api/admin/exportXLS', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM admin');

        // Create a new workbook and worksheet
        const workbook = xlsx.utils.book_new();
        const worksheet = xlsx.utils.json_to_sheet(results);

        // Add worksheet to workbook
        xlsx.utils.book_append_sheet(workbook, worksheet, 'Users');

        // Save the workbook to a temporary file
        const tempFilePath = path.join(__dirname, 'admin.xlsx');
        xlsx.writeFile(workbook, tempFilePath);

        // Send the file to the client
        res.download(tempFilePath, 'admin.xlsx', (err) => {
            if (err) {
                console.error('Error downloading file:', err);
            }

            // Delete the temporary file after sending it
            fs.unlink(tempFilePath, (err) => {
                if (err) {
                    console.error('Error deleting temporary file:', err);
                }
            });
        });
    } catch (err) {
        res.status(500).json({ error: 'Database error: ' + err.message });
    }
});

// Route to get user details by ID (Converted to promise-based)
app.get('/api/admin/getUserById', async (req, res) => {
    const userId = req.query.id;  // Assume user ID is sent as a query parameter
    // console.log('Fetching user ID:', userId);

    try {
        const [result] = await db.query('SELECT * FROM admin WHERE id = ?', [userId]);

        if (result.length > 0) {
            // console.log('User found:', result[0]);
            res.status(200).json(result[0]);  // Send user details as response
        } else {
            // console.log('User not found');
            res.status(404).json({ error: 'User not found' });
        }
    } catch (err) {
        console.error('Database error:', err);
        res.status(500).json({ error: 'Database error: ' + err.message });
    }
});

// API to update a user (Converted to promise-based)
app.put('/api/admin/updateUser/:id', async (req, res) => {
    const userId = req.params.id; // User ID from URL parameter
    const updatedUser = req.body; // Updated user data from the request body

    // console.log(`Updating user with ID: ${userId}`);

    // Extract user details from the request body
    const { name, email, phone, status, password, role, confirm_password } = updatedUser;

    try {
        const [result] = await db.query(
            'UPDATE admin SET name = ?, email = ?, phone = ?, status = ?, password = ?, role = ?, confirm_password = ? WHERE id = ?',
            [name, email, phone, status, password, role, confirm_password, userId]
        );

        if (result.affectedRows > 0) {
            // console.log("data update");
            res.status(200).json({ message: 'User updated successfully' });
        } else {
            // console.log("data not update");
            res.status(404).json({ error: 'User not found' });
        }
    } catch (err) {
        console.error('Database error:', err); // Log the actual error
        res.status(500).json({ error: 'Database error: ' + err.message });
    }
});

// Delete User (Converted to promise-based)
app.delete('/api/admin/:id', async (req, res) => {
    const usersId = req.params.id;
    // console.log(usersId);

    try {
        const [result] = await db.query('DELETE FROM admin WHERE id = ?', [usersId]);

        if (result.affectedRows > 0) {
            // console.log('User deleted successfully');
            res.status(200).json({ message: 'User deleted successfully' });
        } else {
            // console.log('User not found');
            res.status(404).json({ message: 'User not found' });
        }
    } catch (err) {
        console.error('Error deleting user:', err);
        res.status(500).json({ message: 'Server error: ' + err.message });
    }
});

// Change Password (promise-based)
app.post('/api/admin/changePassword', async (req, res) => {
    const { userId, currentPassword, newPassword } = req.body;

    try {
        // Check if current password is valid
        const isCurrentPasswordValid = await validateCurrentPassword(userId, currentPassword);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({ message: 'Current password is incorrect.' });
        }

        // Update the user's password in the database
        const result = await updateUserPassword(userId, newPassword);
        if (result) {
            return res.status(200).json({ message: 'Password updated successfully' });
        } else {
            return res.status(500).json({ message: 'Error updating password' });
        }
    } catch (err) {
        console.error('Error changing password:', err);
        res.status(500).json({ message: 'Error changing password: ' + err.message });
    }
});

app.get('/api/customers', async (req, res) => {
    try {
        // Fetch data from the database
        const [results] = await db.query('SELECT id, name, email, phone, status FROM customers');

        // Log the results to check the data
        // console.log(results);

        // If no customers are found, return an empty array
        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'No customers found' });
        }

        // Send the fetched data as JSON
        res.status(200).json(results);
    } catch (err) {
        // Log the error and respond with a server error status
        console.error('Error fetching customers:', err.message);
        res.status(500).json({ error: 'Error fetching customers' });
    }
});

// Add a new customer
app.post('/api/customers', async (req, res) => {
    const { name, email, phone, status, password, confirm_password, address, country, state, city, zip_code } = req.body;

    // Validate required fields
    if (!name || !email || !phone || !status || !password || !confirm_password || !country || !state || !city || !zip_code || !address) {
        return res.status(400).json({ message: "All fields are required" });
    }

    // Validate password match 
    if (password !== confirm_password) {
        return res.status(400).json({ message: "Passwords do not match" });
    }

    try {
        // Check if email already exists
        const [emailCheck] = await db.query('SELECT email FROM customers WHERE email = ?', [email]);
        if (emailCheck.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        // Prepare data for insertion
        const createdAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
        const sql = `
            INSERT INTO customers (
                name, email, phone, status, password, address, country, state, city, zip_code, created_at
            ) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        // Insert the new customer record
        const [result] = await db.query(sql, [
            name, email, phone, status, password, address, country, state, city, zip_code, createdAt
        ]);

        // Respond with success
        res.status(201).json({ message: 'User added successfully', userId: result.insertId });
    } catch (err) {
        // Log the error and send a response
        console.error('Error saving user:', err.message);
        res.status(500).json({ message: 'Error saving user', error: err.message });
    }
});

// Export customers to Excel
app.get('/api/customers/exportXLS', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM customers');
        const workbook = xlsx.utils.book_new();
        const worksheet = xlsx.utils.json_to_sheet(results);
        xlsx.utils.book_append_sheet(workbook, worksheet, 'Users');

        const tempFilePath = path.join(__dirname, 'customers.xlsx');
        xlsx.writeFile(workbook, tempFilePath);

        res.download(tempFilePath, 'customers.xlsx', (err) => {
            if (err) console.error('Error downloading file:', err);

            fs.unlink(tempFilePath, (err) => {
                if (err) console.error('Error deleting temporary file:', err);
            });
        });
    } catch (err) {
        console.error('Error exporting customers:', err.message);
        res.status(500).json({ error: 'Error exporting customers' });
    }
});

// Fetch customer by ID
app.get('/api/customers/getUserById', async (req, res) => {
    const userId = req.query.id;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required' });
    }

    try {
        const [result] = await db.query('SELECT * FROM customers WHERE id = ?', [userId]);
        if (result.length > 0) {
            res.status(200).json(result[0]);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (err) {
        console.error('Error fetching user by ID:', err.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// Update customer
app.put('/api/customers/updateUser/:id', async (req, res) => {
    const userId = req.params.id;
    const { name, email, phone, status, password, confirm_password } = req.body;

    try {
        const result = await db.query('UPDATE customers SET name = ?, email = ?, phone = ?, status = ?, password = ?, confirm_password = ? WHERE id = ?', [name, email, phone, status, password, confirm_password, userId]);
        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'User updated successfully' });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (err) {
        console.error('Error updating user:', err.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// Delete customer
app.delete('/api/customers/:id', async (req, res) => {
    const customerId = req.params.id;

    try {
        const result = await db.query('DELETE FROM customers WHERE id = ?', [customerId]);
        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'User deleted successfully' });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (err) {
        console.error('Error deleting customer:', err.message);
        res.status(500).json({ message: 'Error deleting customer' });
    }
});
app.get('/api/orderfetchbyidonreciept/:orderId', async (req, res) => {
    const orderId = req.params.orderId;

    try {
        // Fetch order from database
        const [orders] = await db.query('SELECT * FROM onlineorders WHERE order_id = ?', [orderId]);

        if (!orders.length) {
            return res.status(404).json({ message: 'Order not found' });
        }

        const order = orders[0];

        // Parse shipping address if it's stored as JSON
        try {
            const parsed = JSON.parse(order.shipping_address);

            order.shipping_address = [
                parsed.address,
                parsed.city,
                parsed.state,
                parsed.country,
                parsed.zip || parsed.zip_code || ""
            ].filter(Boolean).join(', ');

        } catch (err) {
            console.error('❌ Failed to parse address for order:', order.order_id, err);
            order.shipping_address = 'Invalid Address Data';
        }

        // Set display ID (customer ID or guest ID)
        order.display_id = order.customer_id || order.guest_id || 'N/A';

        // Return the order data
        res.status(200).json(order);

    } catch (error) {
        console.error('❌ Failed to fetch order:', error);
        res.status(500).json({ 
            message: 'Failed to fetch order', 
            error: error.message 
        });
    }
});

// Create Blogs Topic
app.post('/api/blog-topics', upload.single('image'), async (req, res) => {
    const { topic_name, slug } = req.body;
    const image = req.file ? `Uploads/${req.file.filename}` : null;

    if (!topic_name || !slug) {
        return res.status(400).json({ message: 'Topic name and slug are required' });
    }

    try {
        await db.query(
            'INSERT INTO blog_topics (topic_name, slug, image) VALUES (?, ?, ?)',
            [topic_name, slug, image]
        );
        res.json({ success: true, message: 'Topic created' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error creating topic' });
    }
});
// Update Blogs Topic
app.put('/api/blog-topics/:id', upload.single('image'), async (req, res) => {
    const { topic_name, slug } = req.body;
    const { id } = req.params;
    const newImage = req.file ? `Uploads/${req.file.filename}` : null;

    try {
        const [rows] = await db.query('SELECT * FROM blog_topics WHERE id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Topic not found' });

        const currentImage = rows[0].image;
        let updatedImage = currentImage;

        if (newImage && newImage !== currentImage) {
            updatedImage = newImage;
            // Delete old image if different
            if (currentImage && fs.existsSync(currentImage)) {
                fs.unlinkSync(currentImage);
            }
        }

        await db.query(
            'UPDATE blog_topics SET topic_name = ?, slug = ?, image = ? WHERE id = ?',
            [topic_name, slug, updatedImage, id]
        );

        res.json({ success: true, message: 'Topic updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating topic' });
    }
});
// Get Blogs Topic by ID
app.get('/api/blog-topics/id/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await db.query('SELECT * FROM blog_topics WHERE id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Topic not found' });

        res.json(rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching topic' });
    }
});
// Get Blogs Topic by Slug
app.get('/api/blog-topics/slug/:slug', async (req, res) => {
    const { slug } = req.params;

    try {
        const [rows] = await db.query('SELECT * FROM blog_topics WHERE slug = ?', [slug]);
        if (rows.length === 0) return res.status(404).json({ message: 'Topic not found' });

        res.json(rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching topic' });
    }
});
// Get All Blogs Topics
app.get('/api/blog-topics', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM blog_topics ORDER BY created_at DESC');
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching topics' });
    }
});
// Delete Topics
app.delete('/api/blog-topics/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await db.query('SELECT * FROM blog_topics WHERE id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Topic not found' });

        const image = rows[0].image;
        if (image && fs.existsSync(image)) {
            fs.unlinkSync(image);
        }

        await db.query('DELETE FROM blog_topics WHERE id = ?', [id]);
        res.json({ success: true, message: 'Topic deleted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error deleting topic' });
    }
});

// // Create Blogs Category
// app.post('/api/blog-categories', upload.single('image'), async (req, res) => {
//     const { category_name, slug, parent_id } = req.body;
//     const image = req.file ? `Uploads/${req.file.filename}` : null;

//     if (!category_name || !slug) {
//         return res.status(400).json({ message: 'Category name and slug are required' });
//     }

//     try {
//         if (parent_id) {
//             const [parentCheck] = await db.query('SELECT id FROM blog_categories WHERE id = ?', [parent_id]);
//             if (parentCheck.length === 0) {
//                 return res.status(400).json({ message: 'Parent category not found' });
//             }
//         }

//         await db.query(
//             'INSERT INTO blog_categories (category_name, slug, parent_id, image) VALUES (?, ?, ?, ?)',
//             [category_name, slug, parent_id || null, image]
//         );
//         res.json({ success: true, message: 'Category created' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error creating category' });
//     }
// });
// // Update Blogs Category
// app.put('/api/blog-categories/:id', upload.single('image'), async (req, res) => {
//     const { category_name, slug, parent_id } = req.body;
//     const id = req.params.id;

//     try {
//         const [existing] = await db.query('SELECT * FROM blog_categories WHERE id = ?', [id]);
//         if (existing.length === 0) return res.status(404).json({ message: 'Category not found' });

//         let imagePath = existing[0].image;

//         if (req.file) {
//             // Delete old image
//             if (imagePath && fs.existsSync(imagePath)) {
//                 fs.unlinkSync(imagePath);
//             }
//             imagePath = `Uploads/${req.file.filename}`;
//         }

//         await db.query(`
//             UPDATE blog_categories 
//             SET category_name = ?, slug = ?, parent_id = ?, image = ? 
//             WHERE id = ?
//         `, [category_name, slug, parent_id || null, imagePath, id]);

//         res.json({ success: true, message: 'Category updated' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error updating category' });
//     }
// });
// // Get Blogs Category by ID
// app.get('/api/blog-categories/id/:id', async (req, res) => {
//     try {
//         const [rows] = await db.query('SELECT * FROM blog_categories WHERE id = ?', [req.params.id]);
//         if (rows.length === 0) return res.status(404).json({ message: 'Category not found' });
//         res.json(rows[0]);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching category' });
//     }
// });
// // Get Blogs Category by Slug
// app.get('/api/blog-categories/slug/:slug', async (req, res) => {
//     try {
//         const [rows] = await db.query('SELECT * FROM blog_categories WHERE slug = ?', [req.params.slug]);
//         if (rows.length === 0) return res.status(404).json({ message: 'Category not found' });
//         res.json(rows[0]);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching category' });
//     }
// });
// // Get All Blog Category 
// app.get('/api/blog-categories', async (req, res) => {
//     try {
//         const [rows] = await db.query(`
//             SELECT 
//                 c.id, c.category_name, c.slug, c.image, c.created_at,
//                 p.category_name AS parent_category
//             FROM blog_categories c
//             LEFT JOIN blog_categories p ON c.parent_id = p.id
//             ORDER BY c.id DESC
//         `);
//         res.json(rows);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching categories' });
//     }
// });
// // Delete Category
// app.delete('/api/blog-categories/:id', async (req, res) => {
//     try {
//         const [rows] = await db.query('SELECT * FROM blog_categories WHERE id = ?', [req.params.id]);
//         if (rows.length === 0) return res.status(404).json({ message: 'Category not found' });

//         const image = rows[0].image;
//         if (image && fs.existsSync(image)) {
//             fs.unlinkSync(image);
//         }

//         await db.query('DELETE FROM blog_categories WHERE id = ?', [req.params.id]);
//         res.json({ success: true, message: 'Category deleted' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error deleting category' });
//     }
// });

// //  Create Blog API 
// app.post('/api/blogs', upload.single('image'), async (req, res) => {
//     const {
//         blog_name, slug, status, parent_category_id, child_category_id,
//         topic_id, blog_html, post_title, meta_description,
//         post_by, read_minutes, comments
//     } = req.body;

//     const image = req.file ? `Uploads/${req.file.filename}` : null;
//     const post_date = status === 'Live' ? new Date() : null;

//     try {
//         await db.query(`
//             INSERT INTO blogs (
//                 blog_name, slug, status, parent_category_id, child_category_id,
//                 topic_id, blog_html, post_title, meta_description,
//                 post_by, read_minutes, comments, post_date, image
//             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
//         `, [
//             blog_name, slug, status, parent_category_id || null, child_category_id || null,
//             topic_id || null, blog_html, post_title, meta_description,
//             post_by || null, read_minutes || null, comments || null,
//             post_date, image
//         ]);

//         res.json({ success: true, message: 'Blog created successfully' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error creating blog' });
//     }
// });
// //  Update Blog API (remove old image if replaced)
// app.put('/api/blogs/:id', upload.single('image'), async (req, res) => {
//     const {
//         blog_name, slug, status, parent_category_id, child_category_id,
//         topic_id, blog_html, post_title, meta_description,
//         post_by, read_minutes, comments
//     } = req.body;

//     const id = req.params.id;

//     try {
//         const [existing] = await db.query('SELECT * FROM blogs WHERE id = ?', [id]);
//         if (existing.length === 0) return res.status(404).json({ message: 'Blog not found' });

//         let image = existing[0].image;

//         if (req.file) {
//             if (image && fs.existsSync(image)) fs.unlinkSync(image);
//             image = `Uploads/${req.file.filename}`;
//         }

//         const post_date = (status === 'Live' && !existing[0].post_date)
//             ? new Date()
//             : existing[0].post_date;

//         await db.query(`
//             UPDATE blogs SET
//                 blog_name = ?, slug = ?, status = ?, parent_category_id = ?,
//                 child_category_id = ?, topic_id = ?, blog_html = ?,
//                 post_title = ?, meta_description = ?, post_by = ?,
//                 read_minutes = ?, comments = ?, post_date = ?, image = ?
//             WHERE id = ?
//         `, [
//             blog_name, slug, status, parent_category_id || null, child_category_id || null,
//             topic_id || null, blog_html, post_title, meta_description,
//             post_by || null, read_minutes || null, comments || null,
//             post_date, image, id
//         ]);

//         res.json({ success: true, message: 'Blog updated successfully' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error updating blog' });
//     }
// });
// //  Get All Blogs 
// app.get('/api/blogs', async (req, res) => {
//     try {
//         const [rows] = await db.query(`
//             SELECT b.*, 
//                    pc.category_name AS parent_category,
//                    cc.category_name AS child_category,
//                    t.topic_name,
//                    u.name AS post_by_user
//             FROM blogs b
//             LEFT JOIN blog_categories pc ON b.parent_category_id = pc.id
//             LEFT JOIN blog_categories cc ON b.child_category_id = cc.id
//             LEFT JOIN blog_topics t ON b.topic_id = t.id
//             LEFT JOIN users u ON b.post_by = u.id
//             ORDER BY b.id DESC
//         `);
//         res.json(rows);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching blogs' });
//     }
// });
// // Get Blog by ID 
// app.get('/api/blogs/:id', async (req, res) => {
//     try {
//         const [rows] = await db.query('SELECT * FROM blogs WHERE id = ?', [req.params.id]);
//         if (rows.length === 0) return res.status(404).json({ message: 'Blog not found' });
//         res.json(rows[0]);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching blog' });
//     }
// });
// // Get Blog by Slug 
// app.get('/api/blogs/slug/:slug', async (req, res) => {
//     try {
//         const [rows] = await db.query('SELECT * FROM blogs WHERE slug = ?', [req.params.slug]);
//         if (rows.length === 0) return res.status(404).json({ message: 'Blog not found' });
//         res.json(rows[0]);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching blog' });
//     }
// });
// // Delete Blog 
// app.delete('/api/blogs/:id', async (req, res) => {
//     try {
//         const [rows] = await db.query('SELECT * FROM blogs WHERE id = ?', [req.params.id]);
//         if (rows.length === 0) return res.status(404).json({ message: 'Blog not found' });

//         const { image } = rows[0];
//         if (image && fs.existsSync(image)) {
//             fs.unlinkSync(image);
//         }

//         await db.query('DELETE FROM blogs WHERE id = ?', [req.params.id]);
//         res.json({ success: true, message: 'Blog deleted successfully' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error deleting blog' });
//     }
// });

// blogs ratings 
// Admin Adds Dummy Rating for Blog Post 
app.post('/api/blog-ratings/dummy', async (req, res) => {
    const { slug, name, email, rating, review } = req.body;

    try {
        const [blogRows] = await db.query('SELECT id FROM blogs WHERE slug = ?', [slug]);
        if (blogRows.length === 0) return res.status(404).json({ message: 'Blog not found' });

        const blogId = blogRows[0].id;

        // Add the dummy rating
        await db.query(
            `INSERT INTO blog_ratings (blog_id, name, email, rating, review, approved)
             VALUES (?, ?, ?, ?, ?, 'approved')`,
            [blogId, name, email, rating, review]
        );

        res.json({ success: true, message: 'Rating added successfully.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error adding dummy rating' });
    }
});
// create blog 
app.post('/api/blog-ratings', async (req, res) => {
    const { slug, name, email, rating, review } = req.body;

    try {
        // Check if the blog exists based on the slug
        const [blogRows] = await db.query('SELECT id FROM blogs WHERE slug = ?', [slug]);
        if (blogRows.length === 0) return res.status(404).json({ message: 'Blog not found' });

        const blogId = blogRows[0].id;

        // Insert the rating and review
        await db.query(
            `INSERT INTO blog_ratings (blog_id, name, email, rating, review) VALUES (?, ?, ?, ?, ?)`,
            [blogId, name, email, rating, review]
        );

        res.json({ success: true, message: 'Review submitted, pending approval' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error submitting review' });
    }
});
// update blog 
app.put('/api/blog-ratings/:id/approve', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body; // 'approved' or 'rejected'

    try {
        await db.query(`UPDATE blog_ratings SET approved = ? WHERE id = ?`, [status, id]);
        res.json({ success: true, message: `Review ${status}` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating review status' });
    }
});
// GET API to Fetch All Ratings (Approved, Pending, Rejected for All Blog Posts)
app.get('/api/blog-ratings', async (req, res) => {
    try {
        // Fetch all ratings (approved, pending, rejected) for all blog posts
        const [ratings] = await db.query(
            `SELECT r.id, r.blog_id, r.name, r.email, r.rating, r.review, r.approved, r.created_at, b.slug
             FROM blog_ratings r
             JOIN blogs b ON r.blog_id = b.id
             ORDER BY r.created_at DESC`
        );

        res.json({ success: true, ratings });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching ratings' });
    }
});
// Get Approved Ratings for a Blog Post 
app.get('/api/blog-ratings/:slug', async (req, res) => {
    const { slug } = req.params;

    try {
        // Get blog post ID based on slug
        const [blogRows] = await db.query('SELECT id FROM blogs WHERE slug = ?', [slug]);
        if (blogRows.length === 0) return res.status(404).json({ message: 'Blog not found' });

        const blogId = blogRows[0].id;

        // Get the approved ratings
        const [ratings] = await db.query(
            `SELECT name, rating, review, created_at FROM blog_ratings WHERE blog_id = ? AND approved = 'approved' ORDER BY created_at DESC`,
            [blogId]
        );

        res.json({ success: true, ratings });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching reviews' });
    }
});
// Update Rating for Blog Post 
app.put('/api/blog-ratings/:id', async (req, res) => {
    const { id } = req.params;
    const { slug, name, email, rating, review, approved } = req.body;

    try {
        const [blogRows] = await db.query('SELECT id FROM blogs WHERE slug = ?', [slug]);
        if (blogRows.length === 0) return res.status(404).json({ message: 'Blog not found' });

        const blogId = blogRows[0].id;

        const [ratingRows] = await db.query('SELECT * FROM blog_ratings WHERE id = ?', [id]);
        if (ratingRows.length === 0) return res.status(404).json({ message: 'Rating not found' });

        // Update the rating
        await db.query(
            `UPDATE blog_ratings SET name = ?, email = ?, rating = ?, review = ?, approved = ?, blog_id = ? WHERE id = ?`,
            [name, email, rating, review, approved, blogId, id]
        );

        res.json({ success: true, message: 'Rating updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating rating' });
    }
});
// Delete Rating for Blog Post 
app.delete('/api/blog-ratings/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const [ratingRows] = await db.query('SELECT * FROM blog_ratings WHERE id = ?', [id]);
        if (ratingRows.length === 0) return res.status(404).json({ message: 'Rating not found' });

        // Delete the rating
        await db.query('DELETE FROM blog_ratings WHERE id = ?', [id]);

        res.json({ success: true, message: 'Rating deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error deleting rating' });
    }
});
// // Create Blog API (POST)
// // app.post('/api/blogs', upload.array('images', 20), async (req, res) => {
// //     const {
// //         blog_name, status, parent_category_id, child_category_id,
// //         topic_id, blog_html, post_title, meta_description,
// //         post_by, read_minutes, comments
// //     } = req.body;

// //     // Main image stored separately
// //     const mainImage = req.files[0] ? `Uploads/${req.files[0].filename}` : null;

// //     // Collect all other images into an array
// //     const additionalImages = req.files.slice(1).map(file => `Uploads/${file.filename}`);

// //     // Slug generation logic (auto-generated from blog name)
// //     let slug = req.body.slug || blog_name.toLowerCase().replace(/ /g, '-').replace(/[^\w-]+/g, '');

// //     // Fetch categories and topics
// //     try {
// //         const [categories] = await db.query('SELECT * FROM product_categories WHERE id = ?', [parent_category_id]);
// //         if (categories.length === 0) return res.status(400).json({ message: 'Invalid category' });

// //         const [topics] = await db.query('SELECT * FROM blog_topics WHERE id = ?', [topic_id]);
// //         if (topics.length === 0) return res.status(400).json({ message: 'Invalid topic' });

// //         const post_date = status === 'Live' ? new Date() : null;

// //         // Insert into the database
// //         await db.query(`
// //             INSERT INTO blogs (
// //                 blog_name, slug, status, parent_category_id, child_category_id,
// //                 topic_id, blog_html, post_title, meta_description,
// //                 post_by, read_minutes, comments, post_date, image, images
// //             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
// //         `, [
// //             blog_name, slug, status, parent_category_id || null, child_category_id || null,
// //             topic_id || null, blog_html, post_title, meta_description,
// //             post_by || null, read_minutes || null, comments || null,
// //             post_date, mainImage, JSON.stringify(additionalImages) // Store additional images as JSON string
// //         ]);

// //         res.json({ success: true, message: 'Blog created successfully' });
// //     } catch (err) {
// //         console.error(err);
// //         res.status(500).json({ message: 'Error creating blog' });
// //     }
// // });
// app.post('/api/blogs', upload.array('additional_images', 20), async (req, res) => {
//     const {
//         blog_name,
//         slug,
//         status,
//         main_category,
//         sub_category,
//         topic_id,
//         read_minutes,
//         posted_by,
//         blog_title,
//         description,
//     } = req.body;

//     // Files handling
//     const main_image = req.files && req.files.length > 0 ? `Uploads/${req.files[0].filename}` : null;
//     const additional_images = req.files.slice(1).map(file => `Uploads/${file.filename}`);

//     if (!blog_name || !slug || !status || !main_category || !sub_category || !topic_id || !posted_by || !blog_title) {
//         return res.status(400).json({ message: 'All fields are required' });
//     }

//     try {
//         // Insert blog details into MySQL
//         const result = await db.query(
//             'INSERT INTO blogs (blog_name, slug, status, main_category, sub_category, topic_id, main_image, read_minutes, posted_by, blog_title, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
//             [
//                 blog_name,
//                 slug,
//                 status,
//                 main_category,
//                 sub_category,
//                 topic_id,
//                 main_image,
//                 read_minutes,
//                 posted_by,
//                 JSON.stringify({ blog_title, additional_images, description }), // Store blog title, images, and description in JSON
//             ]
//         );
//         res.json({ success: true, message: 'Blog created successfully' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error creating blog' });
//     }
// });
// // Update Blog API
// app.put('/api/blogs/:id', upload.array('additional_images', 20), async (req, res) => {
//     const { id } = req.params;
//     const {
//         blog_name,
//         slug,
//         status,
//         main_category,
//         sub_category,
//         topic_id,
//         read_minutes,
//         posted_by,
//         blog_title,
//         description,
//     } = req.body;

//     // Files handling
//     const main_image = req.files && req.files.length > 0 ? `Uploads/${req.files[0].filename}` : null;
//     const additional_images = req.files.slice(1).map(file => `Uploads/${file.filename}`);

//     try {
//         const result = await db.query(
//             'UPDATE blogs SET blog_name = ?, slug = ?, status = ?, main_category = ?, sub_category = ?, topic_id = ?, main_image = ?, read_minutes = ?, posted_by = ?, blog_title = ?, description = ? WHERE id = ?',
//             [
//                 blog_name,
//                 slug,
//                 status,
//                 main_category,
//                 sub_category,
//                 topic_id,
//                 main_image,
//                 read_minutes,
//                 posted_by,
//                 JSON.stringify({ blog_title, additional_images, description }),
//                 id,
//             ]
//         );
//         res.json({ success: true, message: 'Blog updated successfully' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error updating blog' });
//     }
// });

// // Get All Blogs API
// app.get('/api/blogs', async (req, res) => {
//     try {
//         const [rows] = await db.query('SELECT * FROM blogs');
//         res.json(rows);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching blogs' });
//     }
// });
// // Get Blog by ID API
// app.get('/api/blogs/:id', async (req, res) => {
//     const { id } = req.params;

//     try {
//         const [rows] = await db.query('SELECT * FROM blogs WHERE id = ?', [id]);
//         if (rows.length === 0) {
//             return res.status(404).json({ message: 'Blog not found' });
//         }
//         res.json(rows[0]);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching blog' });
//     }
// });
// // Get Blog by Slug API
// app.get('/api/blogs/slug/:slug', async (req, res) => {
//     const { slug } = req.params;

//     try {
//         const [rows] = await db.query('SELECT * FROM blogs WHERE slug = ?', [slug]);
//         if (rows.length === 0) {
//             return res.status(404).json({ message: 'Blog not found' });
//         }
//         res.json(rows[0]);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching blog' });
//     }
// });
// // Delete Blog (DELETE) 
// // Delete Blog API
// app.delete('/api/blogs/:id', async (req, res) => {
//     const { id } = req.params;

//     try {
//         await db.query('DELETE FROM blogs WHERE id = ?', [id]);
//         res.json({ success: true, message: 'Blog deleted successfully' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error deleting blog' });
//     }
// });




// Allow large JSON bodies

// Create Blog API
// app.post('/api/blog', upload.array('additional_images', 20), async (req, res) => {
//     const {
//         blog_name,
//         slug,
//         status,
//         main_category_id,
//         sub_category_id,
//         topic_id,
//         read_minutes,
//         posted_by,
//         blog_title,
//         description,
//     } = req.body;

//     // Files handling
//     const main_image = req.files && req.files.length > 0 ? `Uploads/${req.files[0].filename}` : null;
//     const additional_images = req.files.slice(1).map(file => `Uploads/${file.filename}`);

//     if (!blog_name || !slug || !status || !main_category_id || !posted_by || !blog_title) {
//         return res.status(400).json({ message: 'Required fields are missing' });
//     }

//     try {
//         // Insert blog details into MySQL
//         const result = await db.query(
//             'INSERT INTO blog (blog_name, slug, status, main_category_id, sub_category_id, topic_id, main_image, read_minutes, posted_by, blog_title, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
//             [
//                 blog_name,
//                 slug,
//                 status,
//                 main_category_id,
//                 sub_category_id || null,
//                 topic_id || null,
//                 main_image,
//                 read_minutes || null,
//                 posted_by,
//                 blog_title,
//                 description || null
//             ]
//         );
        
//         // Insert additional images if any
//         if (additional_images.length > 0) {
//             await Promise.all(additional_images.map(async (image) => {
//                 await db.query(
//                     'INSERT INTO blog_images (blog_id, image_path) VALUES (?, ?)',
//                     [result.insertId, image]
//                 );
//             }));
//         }
        
//         res.json({ success: true, message: 'Blog created successfully', id: result.insertId });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error creating blog' });
//     }
// });
// // Get All Blogs API
// app.get('/api/blog', async (req, res) => {
//     try {
//         const [rows] = await db.query(`
//             SELECT b.*, 
//                    mc.category_name as main_category_name,
//                    sc.category_name as sub_category_name,
//                    t.topic_name
//             FROM blog b
//             LEFT JOIN product_categories mc ON b.main_category_id = mc.id
//             LEFT JOIN product_categories sc ON b.sub_category_id = sc.id
//             LEFT JOIN blog_topics t ON b.topic_id = t.id
//             ORDER BY b.created_at DESC
//         `);
//         res.json(rows);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching blogs' });
//     }
// });
// // Get Blog by ID API
// app.get('/api/blog/:id', async (req, res) => {
//     const { id } = req.params;

//     try {
//         const [rows] = await db.query('SELECT * FROM blog WHERE id = ?', [id]);
//         if (rows.length === 0) {
//             return res.status(404).json({ message: 'Blog not found' });
//         }
//         res.json(rows[0]);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching blog' });
//     }
// });
// // Get Blog by Slug API
// app.get('/api/blog/slug/:slug', async (req, res) => {
//     const { slug } = req.params;

//     try {
//         const [rows] = await db.query('SELECT * FROM blog WHERE slug = ?', [slug]);
//         if (rows.length === 0) {
//             return res.status(404).json({ message: 'Blog not found' });
//         }
//         res.json(rows[0]);
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error fetching blog' });
//     }
// });
// // Update Blog API
// app.put('/api/blog/:id', upload.array('additional_images', 20), async (req, res) => {
//     const { id } = req.params;
//     const {
//         blog_name,
//         slug,
//         status,
//         main_category_id,
//         sub_category_id,
//         topic_id,
//         read_minutes,
//         posted_by,
//         blog_title,
//         description,
//     } = req.body;

//     // Files handling
//     const main_image = req.files && req.files.length > 0 ? `Uploads/${req.files[0].filename}` : null;
//     const additional_images = req.files.slice(1).map(file => `Uploads/${file.filename}`);

//     try {
//         const result = await db.query(
//             'UPDATE blog SET blog_name = ?, slug = ?, status = ?, main_category_id = ?, sub_category_id = ?, topic_id = ?, main_image = ?, read_minutes = ?, posted_by = ?, blog_title = ?, description = ? WHERE id = ?',
//             [
//                 blog_name,
//                 slug,
//                 status,
//                 main_category_id,
//                 sub_category_id,
//                 topic_id,
//                 main_image,
//                 read_minutes,
//                 posted_by,
//                 JSON.stringify({ blog_title, additional_images, description }),
//                 id,
//             ]
//         );
//         res.json({ success: true, message: 'Blog updated successfully' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error updating blog' });
//     }
// });
// // Delete Blog API
// app.delete('/api/blog/:id', async (req, res) => {
//     const { id } = req.params;

//     try {
//         await db.query('DELETE FROM blog WHERE id = ?', [id]);
//         res.json({ success: true, message: 'Blog deleted successfully' });
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: 'Error deleting blog' });
//     }
// });
// GET all blogs
app.get('/api/blog', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT b.*, 
                   mc.name AS main_category_name,  -- Update this to the correct column name
                   sc.name AS sub_category_name,    -- Update this to the correct column name
                   t.topic_name
            FROM blog b
            LEFT JOIN product_categories mc ON b.main_category_id = mc.id
            LEFT JOIN product_categories sc ON b.sub_category_id = sc.id
            LEFT JOIN blog_topics t ON b.topic_id = t.id
            ORDER BY b.created_at DESC
        `);

        // Parse blog titles and other JSON fields
        const parsedRows = rows.map(row => ({
            ...row,
            blog_title: JSON.parse(row.blog_title || '[]'),
            additional_images: JSON.parse(row.additional_images || '[]'), // Assuming you want to parse this too
            descriptions: JSON.parse(row.descriptions || '[]'), // Assuming you want to parse this too
            image_captions: JSON.parse(row.image_captions || '[]') // Assuming you want to parse this too
        }));

        res.json(parsedRows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching blogs', error: err.message });
    }
});

// GET blog by ID
app.get('/api/blog/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await db.query(`
            SELECT b.*, 
                   mc.category_name AS main_category_name,
                   sc.category_name AS sub_category_name,
                   t.topic_name
            FROM blog b
            LEFT JOIN product_categories mc ON b.main_category_id = mc.id
            LEFT JOIN product_categories sc ON b.sub_category_id = sc.id
            LEFT JOIN blog_topics t ON b.topic_id = t.id
            WHERE b.id = ?
        `, [id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }
        const blog = {
            ...rows[0],
            blog_title: JSON.parse(rows[0].blog_title || '[]'), // Updated to handle array
            additional_images: JSON.parse(rows[0].additional_images || '[]'), // Assuming you want to include this
            descriptions: JSON.parse(rows[0].descriptions || '[]'), // Assuming you want to include this
            image_captions: JSON.parse(rows[0].image_captions || '[]') // Assuming you want to include this
        };
        res.json(blog);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching blog' });
    }
});
// GET blog by slug
app.get('/api/blog/slug/:slug', async (req, res) => {
    const { slug } = req.params;
    try {
        const [rows] = await db.query(`
            SELECT b.*, 
                   mc.category_name AS main_category_name,
                   sc.category_name AS sub_category_name,
                   t.topic_name
            FROM blog b
            LEFT JOIN product_categories mc ON b.main_category_id = mc.id
            LEFT JOIN product_categories sc ON b.sub_category_id = sc.id
            LEFT JOIN blog_topics t ON b.topic_id = t.id
            WHERE b.slug = ?
        `, [slug]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }
        const blog = {
            ...rows[0],
            blog_title: JSON.parse(rows[0].blog_title || '[]'), // Updated to handle array
            additional_images: JSON.parse(rows[0].additional_images || '[]'), // Assuming you want to include this
            descriptions: JSON.parse(rows[0].descriptions || '[]'), // Assuming you want to include this
            image_captions: JSON.parse(rows[0].image_captions || '[]') // Assuming you want to include this
        };
        res.json(blog);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error fetching blog' });
    }
});
// POST create blog
app.post('/api/blog', upload.array('additional_images', 20), async (req, res) => {
    const {
        blog_name,
        slug,
        status,
        main_category_id,
        sub_category_id,
        topic_id,
        read_minutes,
        posted_by,
        blog_title,
        descriptions,
        image_captions
    } = req.body;

    const main_image = req.files && req.files.length > 0 ? `Uploads/${req.files[0].filename}` : null;
    const additional_images = req.files && req.files.length > 1 ? req.files.slice(1).map(file => `Uploads/${file.filename}`) : [];

    try {
        if (!blog_name || !slug || !status || !main_category_id || !main_image) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        const blogContent = {
            blog_title: JSON.parse(blog_title || '[]'),
            additional_images,
            descriptions: JSON.parse(descriptions || '[]'),
            image_captions: JSON.parse(image_captions || '[]')
        };

        const [result] = await db.query(
            `INSERT INTO blog (
                blog_name, slug, status, main_category_id, sub_category_id, 
                topic_id, main_image, read_minutes, posted_by, blog_title, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [
                blog_name,
                slug,
                status,
                main_category_id || null,
                sub_category_id || null,
                topic_id || null,
                main_image,
                read_minutes || null,
                posted_by || null,
                JSON.stringify(blogContent),
            ]
        );

        res.json({ success: true, message: 'Blog created successfully', id: result.insertId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error creating blog' });
    }
});
// PUT update blog
app.put('/api/blog/:id', upload.array('additional_images', 20), async (req, res) => {
    const { id } = req.params;
    const {
        blog_name,
        slug,
        status,
        main_category_id,
        sub_category_id,
        topic_id,
        read_minutes,
        posted_by,
        blog_title,
        descriptions,
        image_captions
    } = req.body;

    const main_image = req.files && req.files.length > 0 ? `Uploads/${req.files[0].filename}` : null;
    const additional_images = req.files && req.files.length > 1 ? req.files.slice(1).map(file => `Uploads/${file.filename}`) : [];

    try {
        const blogContent = {
            blog_title: JSON.parse(blog_title || '[]'),
            additional_images,
            descriptions: JSON.parse(descriptions || '[]'),
            image_captions: JSON.parse(image_captions || '[]')
        };

        const [result] = await db.query(
            `UPDATE blog SET 
                blog_name = ?, 
                slug = ?, 
                status = ?, 
                main_category_id = ?, 
                sub_category_id = ?, 
                topic_id = ?, 
                main_image = IFNULL(?, main_image), 
                read_minutes = ?, 
                posted_by = ?, 
                blog_title = ?
            WHERE id = ?`,
            [
                blog_name,
                slug,
                status,
                main_category_id || null,
                sub_category_id || null,
                topic_id || null,
                main_image,
                read_minutes || null,
                posted_by || null,
                JSON.stringify(blogContent),
                id,
            ]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }

        res.json({ success: true, message: 'Blog updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error updating blog' });
    }
});
// DELETE blog
app.delete('/api/blog/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await db.query('DELETE FROM blog WHERE id = ?', [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }
        res.json({ success: true, message: 'Blog deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Error deleting blog' });
    }
});


app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Start the server 
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});