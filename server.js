const express = require('express');
const multer = require('multer');
const { exec } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();

// 🔥 BULLETPROOF CORS CONFIGURATION: Yeh browser ki har request ko explicit pass dega
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const upload = multer({ dest: 'uploads/' });

if (!fs.existsSync('uploads/')) {
    fs.mkdirSync('uploads/');
}

// Health Check Endpoint
app.get('/health', (req, res) => {
    exec('qpdf --version', (err, stdout) => {
        if (err) {
            return res.status(500).json({ status: 'unhealthy', error: 'qpdf not binary mapped' });
        }
        res.json({ status: 'healthy', version: stdout.split('\n')[0] });
    });
});

// Main Decryption Dispatcher
app.post('/decrypt', upload.single('pdfFile'), (req, res) => {
    const file = req.file;
    const password = req.body.password;

    if (!file || !password) {
        if (file && fs.existsSync(file.path)) fs.unlinkSync(file.path);
        return res.status(400).json({ error: 'Missing file or token layers.' });
    }

    // Clean password to make it shell-safe
    const cleanPassword = password.replace(/[^A-Za-z0-9@._-]/g, '');
    
    const inputPath = file.path;
    const outputPath = path.join('uploads/', `Clean_${uuidv4()}.pdf`);

    // Command string execution inside Linux bash container
    const qpdfCommand = `qpdf --password="${cleanPassword}" --decrypt "${inputPath}" "${outputPath}"`;

    exec(qpdfCommand, (err, stdout, stderr) => {
        // Source encrypted file instantly cleanup
        if (fs.existsSync(inputPath)) fs.unlinkSync(inputPath);

        if (err) {
            console.error("qpdf engine error routing:", stderr);
            if (fs.existsSync(outputPath)) fs.unlinkSync(outputPath);
            return res.status(500).json({ error: 'Wrong password or structure corruption.' });
        }

        // Send decrypted original quality vector file
        res.download(outputPath, 'Unlocked_Aadhaar_Document.pdf', (downloadErr) => {
            if (fs.existsSync(outputPath)) fs.unlinkSync(outputPath);
        });
    });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Security Stripper Pipeline live on port ${PORT}`));
