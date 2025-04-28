const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Schema
const scanSchema = new mongoose.Schema({
  link: String,
  encryptedLink: String,
  isPhishing: Boolean,
  message: String,
  platform: String,
  risk: String,
  source: String,
  timestamp: { type: Date, default: Date.now }
});
const Scan = mongoose.model('Scan', scanSchema);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/cyberguardian', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// AES Encryption
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '0d2018fc04390383f0da06cd396a203c8b8aa192492eab3cf1ee512b27d20808';
const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Mock Phishing Detection
function detectPhishing(link) {
  const isPhishing = link.toLowerCase().includes('phish') || Math.random() > 0.8;
  return {
    isPhishing,
    message: isPhishing ? 'Phishing link detected! Do not click.' : 'Link appears safe.',
    platform: 'Web',
    risk: isPhishing ? 'High' : 'Low'
  };
}

// Google Safe Browsing
async function checkSafeBrowsing(link) {
  const apiKey = process.env.SAFE_BROWSING_API_KEY || 'your-safe-browsing-api-key';
  const url = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const body = {
    client: { clientId: 'cyberguardian', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url: link }]
    }
  };
  try {
    const response = await axios.post(url, body);
    return response.data.matches ? response.data.matches.length > 0 : false;
  } catch (error) {
    console.error('Safe Browsing error:', error.message);
    return false;
  }
}

// Source Tracing with IP-API
async function traceSource(link) {
  try {
    const url = new URL(link);
    const hostname = url.hostname;
    const ipResponse = await axios.get(`http://ip-api.com/json/${hostname}`);
    const { status, country, isp } = ipResponse.data;
    return status === 'success' ? `Server in ${country}, ISP: ${isp}` : 'Unknown source';
  } catch (error) {
    console.error('Source tracing error:', error.message);
    return 'Source tracing failed';
  }
}

// Scan API Endpoint
app.post('/api/scan', async (req, res) => {
  const { link } = req.body;
  if (!link) return res.status(400).json({ error: 'Link is required' });

  try {
    new URL(link);
    const encryptedLink = encrypt(link);
    const safeBrowsingResult = await checkSafeBrowsing(link);
    const detection = detectPhishing(link);
    const isPhishing = safeBrowsingResult || detection.isPhishing;
    const source = await traceSource(link);

    const result = {
      isPhishing,
      message: isPhishing ? 'Phishing link detected! Do not click.' : 'Link appears safe.',
      platform: detection.platform,
      risk: isPhishing ? 'High' : 'Low',
      source
    };

    const scan = new Scan({ ...result, link, encryptedLink });
    await scan.save();

    res.json(result);
  } catch (error) {
    console.error('Scan error:', error.message);
    res.status(400).json({ error: 'Invalid URL or scan failed' });
  }
});

// Get Recent Scans
app.get('/api/scans', async (req, res) => {
  try {
    const scans = await Scan.find()
      .sort({ timestamp: -1 })
      .limit(10)
      .select('-encryptedLink -link');
    res.json(scans);
  } catch (error) {
    console.error('Fetch scans error:', error.message);
    res.status(500).json({ error: 'Failed to fetch scans' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));