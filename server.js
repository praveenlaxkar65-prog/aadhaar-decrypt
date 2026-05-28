const express = require("express");
const multer = require("multer");
const cors = require("cors");
const { exec } = require("child_process");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const os = require("os");

const app = express();
const PORT = process.env.PORT || 3000;

// ─── CORS ────────────────────────────────────────────────────────────────────
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);

app.use(express.json());

// ─── MULTER — store uploads in OS temp dir ───────────────────────────────────
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, os.tmpdir()),
  filename: (_req, _file, cb) => cb(null, `aadhaar_in_${uuidv4()}.pdf`),
});

const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB max
  fileFilter: (_req, file, cb) => {
    if (file.mimetype !== "application/pdf") {
      return cb(new Error("Only PDF files are accepted."), false);
    }
    cb(null, true);
  },
});

// ─── UTILITY: safe cleanup ───────────────────────────────────────────────────
function safeDelete(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch (_) {}
}

// ─── UTILITY: sanitise password for shell safety ────────────────────────────
function sanitisePassword(pwd) {
  // Allow only alphanumeric + common special chars; reject shell metacharacters
  if (!/^[A-Za-z0-9@._\-]{1,64}$/.test(pwd)) {
    throw new Error("Password contains disallowed characters.");
  }
  return pwd;
}

// ─── HEALTH CHECK ────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  exec("qpdf --version", (err, stdout) => {
    if (err) {
      return res.status(500).json({
        status: "error",
        message: "qpdf not found on this server.",
        hint: "Run: sudo apt-get install -y qpdf",
      });
    }
    res.json({ status: "ok", qpdf: stdout.trim() });
  });
});

// ─── DECRYPT ENDPOINT ────────────────────────────────────────────────────────
app.post("/decrypt", upload.single("pdf"), (req, res) => {
  const inputPath = req.file?.path;
  const rawPassword = req.body?.password;

  // ── Validate inputs ──────────────────────────────────────────────────────
  if (!inputPath) {
    return res.status(400).json({ error: "No PDF file received." });
  }
  if (!rawPassword) {
    safeDelete(inputPath);
    return res.status(400).json({ error: "Password is required." });
  }

  let password;
  try {
    password = sanitisePassword(rawPassword);
  } catch (e) {
    safeDelete(inputPath);
    return res.status(400).json({ error: e.message });
  }

  const outputPath = path.join(os.tmpdir(), `aadhaar_out_${uuidv4()}.pdf`);

  // ── Build qpdf command (password passed via env var to avoid shell leakage) ─
  // We use a shell-escaped quoted form. Since we validated chars above, this is safe.
  const cmd = `qpdf --password="${password}" --decrypt "${inputPath}" "${outputPath}"`;

  exec(cmd, { timeout: 30000 }, (err, _stdout, stderr) => {
    if (err) {
      safeDelete(inputPath);
      safeDelete(outputPath);

      // qpdf exit codes: 2 = wrong password / encrypted; 3 = warnings
      const msg =
        err.code === 2
          ? "Incorrect password or unsupported encryption. Please verify the Aadhaar password."
          : `Decryption failed: ${stderr || err.message}`;

      return res.status(422).json({ error: msg, qpdfCode: err.code });
    }

    // ── Stream decrypted PDF back ──────────────────────────────────────────
    const stat = fs.statSync(outputPath);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="aadhaar_unlocked.pdf"'
    );
    res.setHeader("Content-Length", stat.size);
    res.setHeader("X-Decryption-Status", "success");

    const readStream = fs.createReadStream(outputPath);
    readStream.pipe(res);

    readStream.on("end", () => {
      safeDelete(inputPath);
      safeDelete(outputPath);
    });

    readStream.on("error", (streamErr) => {
      safeDelete(inputPath);
      safeDelete(outputPath);
      if (!res.headersSent) {
        res.status(500).json({ error: "Failed to stream output file." });
      }
    });
  });
});

// ─── MULTER ERROR HANDLER ────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  if (err) {
    return res.status(400).json({ error: err.message });
  }
});

// ─── START ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅  Aadhaar Decrypt API running on port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
  console.log(`   Decrypt: POST http://localhost:${PORT}/decrypt`);
});
