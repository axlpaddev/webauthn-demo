// backend/server.js
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  isoUint8Array,
} = require('@simplewebauthn/server');
const { isoUint8Array: isoHelpers } = require('@simplewebauthn/server/helpers');
const path = require('path');
const fs = require('fs');

const app = express();

const FRONTEND_ORIGIN = 'https://axltest.lat';
app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json({ limit: '10mb' }));

// === Rutas de API (WebAuthn) ===
const users = new Map();

const sendError = (res, status, message) => {
  console.warn(`⚠️ Error ${status}:`, message);
  return res.status(status).json({ error: message });
};

app.post('/generate-registration-options', (req, res) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string') {
      return sendError(res, 400, 'Email válido es requerido');
    }

    const userId = uuidv4();
    const options = generateRegistrationOptions({
      rpName: 'Mi App Web',
      rpID: 'axltest.lat',
      userID: isoHelpers.fromUTF8String(userId),
      userName: email,
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials: users.has(email)
        ? users.get(email).devices.map(dev => ({
            id: dev.credentialID,
            type: 'public-key',
          }))
        : [],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        requireResidentKey: true,
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    if (!users.has(email)) {
      users.set(email, { id: userId, email, devices: [], currentChallenge: options.challenge });
    } else {
      users.get(email).currentChallenge = options.challenge;
    }

    res.json(options);
  } catch (err) {
    console.error('💥 Error en /generate-registration-options:', err);
    sendError(res, 500, 'Error interno al generar opciones');
  }
});

app.post('/verify-registration', async (req, res) => {
  try {
    const { email, response } = req.body;
    if (!email || !response) return sendError(res, 400, 'Faltan datos');
    const user = users.get(email);
    if (!user) return sendError(res, 404, 'Usuario no encontrado');
    const expectedChallenge = user.currentChallenge;
    if (!expectedChallenge) return sendError(res, 400, 'No hay desafío');

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: 'https://axltest.lat',
      expectedRPID: 'axltest.lat',
      requireUserVerification: true,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
      user.devices.push({
        credentialID: isoUint8Array.toBuffer(credentialID),
        credentialPublicKey: isoUint8Array.toBuffer(credentialPublicKey),
        counter,
      });
      delete user.currentChallenge;
      res.json({ verified: true });
    } else {
      sendError(res, 400, 'Verificación fallida');
    }
  } catch (err) {
    console.error('💥 Error en /verify-registration:', err);
    sendError(res, 500, 'Error al verificar registro');
  }
});

app.post('/generate-authentication-options', (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return sendError(res, 400, 'Email requerido');
    const user = users.get(email);
    if (!user || user.devices.length === 0) {
      return sendError(res, 404, 'Usuario no registrado');
    }

    const options = generateAuthenticationOptions({
      timeout: 60000,
      userVerification: 'required',
      allowCredentials: user.devices.map(dev => ({
        id: dev.credentialID,
        type: 'public-key',
      })),
      rpID: 'axltest.lat',
    });

    user.currentChallenge = options.challenge;
    res.json(options);
  } catch (err) {
    console.error('💥 Error en /generate-authentication-options:', err);
    sendError(res, 500, 'Error al generar desafío');
  }
});

app.post('/verify-authentication', async (req, res) => {
  try {
    const { email, response } = req.body;
    if (!email || !response) return sendError(res, 400, 'Faltan datos');
    const user = users.get(email);
    if (!user) return sendError(res, 404, 'Usuario no encontrado');
    const expectedChallenge = user.currentChallenge;
    if (!expectedChallenge) return sendError(res, 400, 'No hay desafío');

    const device = user.devices.find(d => Buffer.compare(d.credentialID, response.id) === 0);
    if (!device) return sendError(res, 400, 'Dispositivo desconocido');

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: 'https://axltest.lat',
      expectedRPID: 'axltest.lat',
      authenticator: {
        credentialID: device.credentialID,
        credentialPublicKey: device.credentialPublicKey,
        counter: device.counter,
      },
      requireUserVerification: true,
    });

    if (verification.verified) {
      device.counter = verification.authenticationInfo.newCounter;
      delete user.currentChallenge;
      res.json({ verified: true, user: { email } });
    } else {
      sendError(res, 400, 'Autenticación fallida');
    }
  } catch (err) {
    console.error('💥 Error en /verify-authentication:', err);
    sendError(res, 500, 'Error al verificar autenticación');
  }
});

// Ruta de salud
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// === Servir frontend en producción ===
// === Servir frontend en producción ===
if (process.env.NODE_ENV === 'production') {
  const DIST_DIR = path.resolve(__dirname, '..', 'frontend', 'dist');
  const INDEX_FILE = path.join(DIST_DIR, 'index.html');

  console.log('📁 __dirname:', __dirname);
  console.log('📁 DIST_DIR:', DIST_DIR);
  console.log('📁 INDEX_FILE:', INDEX_FILE);

  if (fs.existsSync(DIST_DIR)) {
    console.log('✅ Carpeta dist encontrada. Sirviendo frontend estático.');
    app.use(express.static(DIST_DIR));

    // Middleware de fallback (DEBE estar al final)
    app.use((req, res, next) => {
      const apiRoutes = [
        '/generate-registration-options',
        '/verify-registration',
        '/generate-authentication-options',
        '/verify-authentication',
        '/api/health'
      ];
      if (apiRoutes.some(route => req.url.startsWith(route))) {
        return next(); // permite que Express responda 404 JSON si la ruta no existe
      }
      res.sendFile(INDEX_FILE, err => {
        if (err) {
          console.error('❌ Error al servir index.html:', err);
          res.status(500).send('Error interno');
        }
      });
    });
  } else {
    console.error('❌ ERROR: Carpeta dist NO encontrada en:', DIST_DIR);
    app.use((req, res, next) => {
      const apiRoutes = [
        '/generate-registration-options',
        '/verify-registration',
        '/generate-authentication-options',
        '/verify-authentication',
        '/api/health'
      ];
      if (apiRoutes.some(route => req.url.startsWith(route))) {
        return next();
      }
      res.status(500).send('Error: frontend no construido.');
    });
  }
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ App corriendo en puerto ${PORT}`);
});