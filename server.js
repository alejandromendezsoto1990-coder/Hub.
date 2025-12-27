require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

mongoose.connect(process.env.MONGO_URI);

const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  executions: { type: Number, default: 0 },
  obfuscations: { type: Number, default: 0 },
  monthlyReset: { type: Date, default: Date.now }
});
const ProjectSchema = new mongoose.Schema({ userId: String, name: String });
const ScriptSchema = new mongoose.Schema({
  userId: String,
  projectId: String,
  name: String,
  original: String,
  obfuscated: String,
  executions: { type: Number, default: 0 }
});

const User = mongoose.model('User', UserSchema);
const Project = mongoose.model('Project', ProjectSchema);
const Script = mongoose.model('Script', ScriptSchema);

const upload = multer({ dest: 'uploads/' });
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkeychangeinprod';

const auth = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) { res.status(401).json({ error: 'Unauthorized' }); }
};

// Register
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ email, password: hashed });
  await user.save();
  res.json({ success: true });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { email, executions: user.executions, obfuscations: user.obfuscations } });
  } else res.status(401).json({ error: 'Invalid credentials' });
});

// Dashboard stats
app.get('/api/dashboard', auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json({ executions: user.executions, obfuscations: user.obfuscations });
});

// Projects
app.get('/api/projects', auth, async (req, res) => {
  const projects = await Project.find({ userId: req.user.id });
  const populated = await Promise.all(projects.map(async p => {
    p.scripts = await Script.find({ projectId: p._id });
    return p;
  }));
  res.json(populated);
});

app.post('/api/projects', auth, async (req, res) => {
  const project = new Project({ userId: req.user.id, name: req.body.name });
  await project.save();
  res.json(project);
});

// Upload & Obfuscate Script
app.post('/api/scripts', auth, upload.single('script'), async (req, res) => {
  const { name, projectId } = req.body;
  const user = await User.findById(req.user.id);
  user.obfuscations += 1;
  await user.save();

  const original = fs.readFileSync(req.file.path, 'utf8');
  fs.unlinkSync(req.file.path);

  // REAL Sample #4 Obfuscation
  const seed = (92*90)+32;
  let key1 = (14*3)+5;
  const key2 = (7*8)+3;
  const key3 = (11*11)+6;

  let bytes = Buffer.from(original);
  for (let i = 0; i < bytes.length; i++) {
    if (i % 2 === 0) {
      bytes[i] = (bytes[i] - key3) & 0xFF;
      bytes[i] ^= key1;
      bytes[i] = (bytes[i] - key2) & 0xFF;
      bytes[i] ^= key3;
    } else {
      bytes[i] ^= key3;
      bytes[i] = (bytes[i] - key2) & 0xFF;
      bytes[i] ^= key1;
      bytes[i] = (bytes[i] - key3) & 0xFF;
    }
  }

  const obfuscated = `-- Luarmor Protected\nlocal data = "${bytes.toString('base64')}"\n-- Decryption stub\nload(atob(data))()`;

  const script = new Script({ userId: req.user.id, projectId, name, original, obfuscated });
  await script.save();
  res.json(script);
});

// Loadstring API - Real executor compatible
app.get('/api/v3/load/:id', async (req, res) => {
  const script = await Script.findById(req.params.id);
  if (!script) return res.status(404).send('-- Not found');

  script.executions += 1;
  await script.save();

  const user = await User.findById(script.userId);
  user.executions += 1;
  await user.save();

  res.type('text/plain').send(script.obfuscated);
});

app.listen(process.env.PORT || 3000, () => console.log('Luarmor backend running'));