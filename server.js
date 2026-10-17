const express = require('express');
const path = require('path');
const db = require('./server/db');
const auth = require('./server/auth');
const avatar = require('./server/avatar');

const app = express();
const PORT = process.env.PORT || 3000;

// Body parsers: json up to 10MB to support base64 avatars
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Diagnostic endpoint for browser audits
app.post('/api/debug-log', (req, res) => {
  console.log('CLIENT DIAGNOSTIC:', JSON.stringify(req.body));
  res.json({ status: 'ok' });
});

// Serve uploaded avatars
app.use('/uploads/avatars', express.static(path.join(__dirname, 'uploads', 'avatars'), {
  etag: false,
  maxAge: '1h'
}));

// Serve static frontend assets
app.use(express.static(path.join(__dirname), {
  etag: false,
  maxAge: 0
}));

// ============================================================================
// AUTHENTICATION API ROUTES
// ============================================================================

// 1. Registration
app.post('/api/auth/register', (req, res) => {
  try {
    const { fullName, email, password, passwordConfirm, terms } = req.body;

    // Strict Validations
    if (!fullName || typeof fullName !== 'string' || fullName.trim().length < 2) {
      return res.status(400).json({ error: 'Veuillez saisir votre nom complet (au moins 2 caractères).' });
    }

    if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      return res.status(400).json({ error: 'Veuillez fournir une adresse e-mail valide.' });
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Le mot de passe doit comporter au moins 8 caractères.' });
    }

    if (passwordConfirm !== undefined && password !== passwordConfirm) {
      return res.status(400).json({ error: 'La confirmation du mot de passe ne correspond pas.' });
    }

    if (terms === false || terms === 'false') {
      return res.status(400).json({ error: 'Vous devez accepter les conditions d\'utilisation pour continuer.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const existing = db.getUserByEmail(cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'Un compte existe déjà avec cette adresse e-mail. Veuillez vous connecter.' });
    }

    // Secure salt and hash
    const salt = auth.generateSalt();
    const passwordHash = auth.hashPassword(password, salt);

    // Create user and profile atomically
    const { user, profile, entitlement, preferences } = db.createUser({
      fullName: fullName.trim(),
      email: cleanEmail,
      passwordHash,
      salt
    });

    // Create persistent session
    const token = auth.generateToken();
    db.createSession(token, user.id);

    // Set secure cookie
    res.cookie('vydeora_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    return res.status(201).json({
      success: true,
      message: 'Compte créé avec succès ! 100 crédits de bienvenue ont été ajoutés.',
      token,
      user: {
        id: profile.userId,
        fullName: profile.fullName,
        email: profile.email,
        avatarUrl: profile.avatarUrl,
        preferredLanguage: profile.preferredLanguage,
        timeZone: profile.timeZone
      },
      profile,
      entitlement
    });

  } catch (err) {
    console.error('Registration error:', err.message);
    if (err.code === 'USER_EXISTS') {
      return res.status(409).json({ error: err.message });
    }
    return res.status(500).json({ error: 'Une erreur interne est survenue lors de l\'inscription.' });
  }
});

// 2. Login
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Veuillez renseigner votre adresse e-mail et votre mot de passe.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = db.getUserByEmail(cleanEmail);

    if (!user) {
      return res.status(401).json({ error: 'Adresse e-mail ou mot de passe incorrect.' });
    }

    const isMatch = auth.verifyPassword(password, user.salt, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Adresse e-mail ou mot de passe incorrect.' });
    }

    // Create session
    const token = auth.generateToken();
    db.createSession(token, user.id);

    // Set cookie
    res.cookie('vydeora_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    const profile = db.getProfile(user.id);
    const entitlement = db.getEntitlement(user.id);

    return res.json({
      success: true,
      message: 'Connexion réussie.',
      token,
      user: {
        id: user.id,
        fullName: profile ? profile.fullName : 'Créateur VYDEORA',
        email: user.email,
        avatarUrl: profile ? profile.avatarUrl : null,
        preferredLanguage: profile ? profile.preferredLanguage : 'fr',
        timeZone: profile ? profile.timeZone : 'Europe/Paris'
      },
      entitlement
    });

  } catch (err) {
    console.error('Login error:', err.message);
    return res.status(500).json({ error: 'Une erreur est survenue lors de la tentative de connexion.' });
  }
});

// 3. Logout
app.post('/api/auth/logout', (req, res) => {
  try {
    const token = auth.extractToken(req);
    if (token) {
      db.deleteSession(token);
    }
    res.clearCookie('vydeora_session', { path: '/' });
    return res.json({ success: true, message: 'Déconnexion effectuée.' });
  } catch (err) {
    console.error('Logout error:', err.message);
    return res.status(500).json({ error: 'Erreur lors de la déconnexion.' });
  }
});

// 4. Current Authenticated User Data (Me)
app.get('/api/auth/me', auth.requireAuth, (req, res) => {
  try {
    const profile = db.getProfile(req.userId);
    const preferences = db.getPreferences(req.userId);
    const entitlement = db.getEntitlement(req.userId);
    const projects = db.getProjects(req.userId);
    const notifications = db.getNotifications(req.userId);
    const activity = db.getActivity(req.userId);

    return res.json({
      success: true,
      user: {
        id: req.userId,
        fullName: profile ? profile.fullName : 'Créateur VYDEORA',
        email: req.user.email,
        avatarUrl: profile ? profile.avatarUrl : null,
        preferredLanguage: profile ? profile.preferredLanguage : 'fr',
        timeZone: profile ? profile.timeZone : 'Europe/Paris',
        createdAt: profile ? profile.createdAt : req.user.createdAt
      },
      preferences,
      entitlement,
      projects,
      notifications,
      activity
    });
  } catch (err) {
    console.error('/api/auth/me error:', err.message);
    return res.status(500).json({ error: 'Impossible de charger les données du profil.' });
  }
});

// ============================================================================
// PROFILE & SETTINGS API ROUTES
// ============================================================================

// 5. Update Profile
app.put('/api/user/profile', auth.requireAuth, (req, res) => {
  try {
    const { fullName, preferredLanguage, timeZone } = req.body;
    if (fullName !== undefined && fullName.trim().length < 2) {
      return res.status(400).json({ error: 'Le nom doit comporter au moins 2 caractères.' });
    }

    const updated = db.updateProfile(req.userId, {
      fullName,
      preferredLanguage,
      timeZone
    });

    return res.json({
      success: true,
      message: 'Profil mis à jour avec succès.',
      profile: updated
    });
  } catch (err) {
    console.error('Update profile error:', err.message);
    return res.status(500).json({ error: 'Erreur lors de la mise à jour du profil.' });
  }
});

// 6. Update Preferences
app.put('/api/user/preferences', auth.requireAuth, (req, res) => {
  try {
    const { defaultFormat, preferredVoiceLang, emailNotifications, productUpdates } = req.body;
    const updated = db.updatePreferences(req.userId, {
      defaultFormat,
      preferredVoiceLang,
      emailNotifications,
      productUpdates
    });

    return res.json({
      success: true,
      message: 'Préférences enregistrées.',
      preferences: updated
    });
  } catch (err) {
    console.error('Update preferences error:', err.message);
    return res.status(500).json({ error: 'Erreur lors de l\'enregistrement des préférences.' });
  }
});

// 7. Update Password
app.put('/api/user/password', auth.requireAuth, (req, res) => {
  try {
    const { currentPassword, newPassword, newPasswordConfirm } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Veuillez saisir le mot de passe actuel et le nouveau mot de passe.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Le nouveau mot de passe doit comporter au moins 8 caractères.' });
    }

    if (newPasswordConfirm !== undefined && newPassword !== newPasswordConfirm) {
      return res.status(400).json({ error: 'La confirmation du nouveau mot de passe ne correspond pas.' });
    }

    const user = req.user;
    const isCurrentValid = auth.verifyPassword(currentPassword, user.salt, user.passwordHash);
    if (!isCurrentValid) {
      return res.status(401).json({ error: 'Le mot de passe actuel est incorrect.' });
    }

    const newSalt = auth.generateSalt();
    const newHash = auth.hashPassword(newPassword, newSalt);

    db.updatePassword(req.userId, newHash, newSalt);

    return res.json({
      success: true,
      message: 'Votre mot de passe a été modifié avec succès.'
    });
  } catch (err) {
    console.error('Password update error:', err.message);
    return res.status(500).json({ error: 'Erreur lors du changement de mot de passe.' });
  }
});

// 8. Upload Profile Avatar
app.post('/api/user/avatar', auth.requireAuth, (req, res) => {
  try {
    const { image } = req.body;
    if (!image) {
      return res.status(400).json({ error: 'Aucune donnée d\'image fournie.' });
    }

    const result = avatar.handleAvatarUpload(req.userId, image);
    return res.json({
      success: true,
      message: 'Photo de profil mise à jour avec succès.',
      avatarUrl: result.avatarUrl,
      profile: result.profile
    });
  } catch (err) {
    console.error('Avatar upload error:', err.message);
    return res.status(400).json({ error: err.message || 'Erreur lors du téléversement de la photo.' });
  }
});

// 9. Delete Profile Avatar
app.delete('/api/user/avatar', auth.requireAuth, (req, res) => {
  try {
    const result = avatar.handleAvatarDelete(req.userId);
    return res.json({
      success: true,
      message: 'Photo de profil supprimée.',
      avatarUrl: null,
      profile: result.profile
    });
  } catch (err) {
    console.error('Avatar delete error:', err.message);
    return res.status(500).json({ error: 'Erreur lors de la suppression de la photo.' });
  }
});

// ============================================================================
// PROJECTS API (STRICT DATA ISOLATION PER USER)
// ============================================================================

// 10. Get User Projects
app.get('/api/user/projects', auth.requireAuth, (req, res) => {
  try {
    const projects = db.getProjects(req.userId);
    return res.json({ success: true, projects });
  } catch (err) {
    console.error('Get projects error:', err.message);
    return res.status(500).json({ error: 'Impossible de récupérer les projets.' });
  }
});

// 11. Create Project
app.post('/api/user/projects', auth.requireAuth, (req, res) => {
  try {
    const { title, duration, category, thumb, status, statusClass } = req.body;
    const project = db.createProject({
      userId: req.userId,
      title: title || 'Nouvelle vidéo IA',
      duration: duration || '0:45',
      category: category || 'TikTok | Shorts',
      thumb: thumb || 'assets/images/creator-card.jpg',
      status: status || 'Terminée',
      statusClass: statusClass || 'badge-success'
    });

    return res.status(201).json({
      success: true,
      message: 'Projet créé avec succès.',
      project
    });
  } catch (err) {
    console.error('Create project error:', err.message);
    return res.status(500).json({ error: 'Erreur lors de la création du projet.' });
  }
});

// 12. Delete Project
app.delete('/api/user/projects/:id', auth.requireAuth, (req, res) => {
  try {
    const projectId = req.params.id;
    const deleted = db.deleteProject(req.userId, projectId);
    if (!deleted) {
      return res.status(404).json({ error: 'Projet introuvable ou vous n\'avez pas l\'autorisation de le supprimer.' });
    }
    return res.json({ success: true, message: 'Projet supprimé.' });
  } catch (err) {
    console.error('Delete project error:', err.message);
    return res.status(500).json({ error: 'Erreur lors de la suppression du projet.' });
  }
});

// ============================================================================
// NOTIFICATIONS API
// ============================================================================

// 13. Get Notifications
app.get('/api/user/notifications', auth.requireAuth, (req, res) => {
  try {
    const notifications = db.getNotifications(req.userId);
    return res.json({ success: true, notifications });
  } catch (err) {
    console.error('Get notifications error:', err.message);
    return res.status(500).json({ error: 'Impossible de récupérer les notifications.' });
  }
});

// 14. Mark All Notifications as Read
app.put('/api/user/notifications/mark-read', auth.requireAuth, (req, res) => {
  try {
    db.markNotificationsRead(req.userId);
    return res.json({ success: true, message: 'Toutes les notifications sont marquées comme lues.' });
  } catch (err) {
    console.error('Mark notifications read error:', err.message);
    return res.status(500).json({ error: 'Erreur lors de la mise à jour des notifications.' });
  }
});

// ============================================================================
// ROUTING GUARDS & APPLICATION VIEWS
// ============================================================================

// Protected Application Route
app.get(['/app', '/dashboard', '/dashboard.html'], (req, res) => {
  const authState = auth.optionalAuth(req);
  if (!authState) {
    // Unauthenticated: redirect to login on public landing page
    return res.redirect('/?auth=login&redirect=/app');
  }
  // Authenticated: serve dashboard
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Root & Landing Page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 VYDEORA Server running at http://localhost:${PORT}`);
});
