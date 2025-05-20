const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const app = express();
const port = 3000;
const SECRET = 'votre_clef_secrete_a_modifier';
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'tonemail@gmail.com',      // Mets ici ton email d’envoi (mot de passe d'appli recommandé)
    pass: 'motdepasse_application'  
  }
});

app.use(express.static(path.join(__dirname, '../public')));
app.use(cors());
app.use(bodyParser.json());

// Initialisation DB
const db = new sqlite3.Database('./coaching.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    passwordHash TEXT NOT NULL,
    nom TEXT,
    prenom TEXT,
    dateNaissance TEXT,
    taille INTEGER,
    poids INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    date TEXT,
    session TEXT,
    motivation INTEGER,
    fatigue INTEGER,
    preNote TEXT,
    postFatigue INTEGER,
    postNote TEXT,
    exercices TEXT,
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);

  db.run(`ALTER TABLE users ADD COLUMN resetToken TEXT`, () => {});
  db.run(`ALTER TABLE users ADD COLUMN resetTokenExpire INTEGER`, () => {});
});

// Enregistrement
app.post('/api/register', async (req, res) => {
  const { email, password, nom, prenom, dateNaissance, taille, poids } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);

  db.run('INSERT INTO users (email, passwordHash, nom, prenom, dateNaissance, taille, poids) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [email, passwordHash, nom, prenom, dateNaissance, taille, poids],
    function(err) {
      if (err) {
        console.log('[register] Erreur SQL:', err);
        return res.status(400).json({ message: 'Utilisateur déjà existant' });
      }
      console.log('[register] Nouvel utilisateur :', email, nom, prenom, dateNaissance, taille, poids);
      res.json({ message: 'Inscription réussie' });
    }
  );
});


// Connexion
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: 'Utilisateur non trouvé' });
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ message: 'Mot de passe incorrect' });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '7d' });
    res.json({ token });
  });
});

// Middleware d’auth
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Mise à jour du compte utilisateur
app.post('/api/updateMe', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { nom, prenom, dateNaissance, taille, poids } = req.body;
  db.run(
    'UPDATE users SET nom=?, prenom=?, dateNaissance=?, taille=?, poids=? WHERE id=?',
    [nom, prenom, dateNaissance, taille, poids, userId],
    function(err) {
      if (err) {
        console.log('[updateMe] Erreur SQL :', err);
        return res.status(500).json({ message: "Erreur serveur lors de la mise à jour." });
      }
      console.log('[updateMe] Modifié user', userId, nom, prenom, dateNaissance, taille, poids);
      res.json({ message: "Modifications enregistrées !" });
    }
  );
});

// Ajout d'une séance
app.post('/api/logs', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const {
    date,
    session,
    motivation,
    fatigue,
    preNote,
    postFatigue,
    postNote,
    exercices
  } = req.body;

  const sql = `INSERT INTO logs (userId, date, session, motivation, fatigue, preNote, postFatigue, postNote, exercices)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  db.run(sql, [
    userId,
    date,
    session,
    motivation,
    fatigue,
    preNote,
    postFatigue,
    postNote,
    JSON.stringify(exercices)
  ], function(err) {
    if (err) return res.status(500).json({ message: 'Erreur serveur lors de l\'insertion' });
    console.log('[logs] Nouvelle séance user', userId, '->', session, date, exercices.length, 'exercices');
    res.json({ message: 'Séance enregistrée avec succès', id: this.lastID });
  });
});

// Mot de passe oublié (envoi mail)
app.post('/api/forgot', (req, res) => {
  const { email } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) {
      return res.status(400).json({ message: "Si ce compte existe, un email a été envoyé." });
    }

    const token = crypto.randomBytes(24).toString('hex');
    const expire = Date.now() + 3600000; // 1 heure

    db.run('UPDATE users SET resetToken = ?, resetTokenExpire = ? WHERE email = ?', [token, expire, email], function(err) {
      const resetUrl = `http://localhost:3000/reset.html?token=${token}`;
      const mailOptions = {
        to: email,
        subject: 'Réinitialisation de mot de passe',
        text: `Clique sur ce lien pour changer ton mot de passe : ${resetUrl}`,
        html: `<p>Pour réinitialiser ton mot de passe, clique ici :</p>
               <a href="${resetUrl}">${resetUrl}</a>
               <p>Ce lien est valable 1 heure.</p>`
      };

      transporter.sendMail(mailOptions, function (error, info) {
        return res.json({ message: "Si ce compte existe, un email a été envoyé." });
      });
    });
  });
});

// Réinitialisation du mot de passe
app.post('/api/reset', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ message: "Lien ou mot de passe manquant." });
  }

  db.get('SELECT * FROM users WHERE resetToken = ? AND resetTokenExpire > ?', [token, Date.now()], async (err, user) => {
    if (err || !user) {
      return res.status(400).json({ message: "Lien invalide ou expiré." });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    db.run('UPDATE users SET passwordHash = ?, resetToken = NULL, resetTokenExpire = NULL WHERE id = ?', [passwordHash, user.id], function (err) {
      if (err) return res.status(500).json({ message: "Erreur lors de la mise à jour." });
      res.json({ message: "Mot de passe modifié avec succès ! Tu peux te reconnecter." });
    });
  });
});

// Voir toutes les séances
app.get('/api/logs', authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.all('SELECT * FROM logs WHERE userId = ? ORDER BY date DESC', [userId], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Erreur lors de la récupération des séances' });
    const logs = rows.map(row => ({
      ...row,
      exercices: JSON.parse(row.exercices)
    }));
    res.json(logs);
  });
});

// Voir infos utilisateur (pour “compte”)
app.get('/api/me', authenticateToken, (req, res) => {
  db.get('SELECT email, nom, prenom, dateNaissance, taille, poids FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ message: 'Utilisateur non trouvé' });
    res.json(user);
  });
});

app.listen(port, () => {
  console.log(`Serveur démarré sur http://localhost:${port}`);
});
