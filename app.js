const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const QRCode = require('qrcode');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Load private & public keys
const privateKey = fs.readFileSync(path.join(__dirname, 'keys/private.pem'), 'utf8');
const publicKey = fs.readFileSync(path.join(__dirname, 'keys/public.pem'), 'utf8');

// ✅ Route: Generate Signed QR
app.post('/generate', async (req, res) => {
  try {
    const studentData = req.body;
    const dataString = JSON.stringify(studentData);

    const signature = crypto.sign("sha256", Buffer.from(dataString), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    }).toString('base64');

    const payload = { data: studentData, signature };
    const qrData = JSON.stringify(payload);
    const qrCode = await QRCode.toDataURL(qrData);

    console.log(`✅ QR generated for: ${studentData.name} (${studentData.rollNo})`);
    res.json({ qrCode });
  } catch (error) {
    console.error("❌ Error generating QR:", error);
    res.status(500).json({ error: "Failed to generate QR" });
  }
});

// ✅ Route: Verify QR
app.post('/verify', (req, res) => {
  try {
    const { data, signature } = req.body;
    const dataString = JSON.stringify(data);

    const isValid = crypto.verify(
      "sha256",
      Buffer.from(dataString),
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      },
      Buffer.from(signature, 'base64')
    );

    console.log(`🔍 Verification result for ${data?.name || 'unknown'}:`, isValid);
    res.json({ valid: isValid });
  } catch (error) {
    console.error("❌ Verification error:", error);
    res.status(400).json({ valid: false, error: "Invalid QR payload" });
  }
});

// ✅ Server Running
const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
