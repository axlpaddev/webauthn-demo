// backend/server.js
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { 
  isoUint8Array,
  isoBase64URL 
} = require('@simplewebauthn/server/helpers');
const path = require('path');
const fs = require('fs');

const app = express();
const FRONTEND_ORIGIN = 'https://axltest.dev';
app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json({ limit: '10mb' }));

// === Rutas de API (WebAuthn) ===
const users = new Map();

const sendError = (res, status, message) => {
  console.warn(`⚠️ Error ${status}:`, message);
  return res.status(status).json({ error: message });
};

// ✅ VERSIÓN 8.x PROBADA - MÉTODOS QUE SÍ FUNCIONAN
app.post('/generate-registration-options', async (req, res) => {
  try {
    const { email } = req.body;
    console.log('📧 Email recibido:', email);
    
    if (!email) return sendError(res, 400, 'Email requerido');

    const userId = uuidv4();
    console.log('🆕 UserID generado:', userId);

    const options = await generateRegistrationOptions({
      rpName: 'AxlTest App',
      rpID: 'axltest.dev',
      userID: userId, // ← EN v8.x acepta string directamente
      userName: email,
      timeout: 60000,
      attestationType: 'none',
      authenticatorSelection: {
        userVerification: 'preferred',
        requireResidentKey: false,
      },
    });

    console.log('✅ Challenge generado:', options.challenge);

    users.set(email, { 
      id: userId, 
      email, 
      devices: [], 
      currentChallenge: options.challenge 
    });

    console.log('🎉 Opciones generadas correctamente');
    res.json(options);
  } catch (err) {
    console.error('💥 Error:', err);
    sendError(res, 500, `Error interno: ${err.message}`);
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
      expectedOrigin: 'https://axltest.dev',
      expectedRPID: 'axltest.dev',
      requireUserVerification: true,
    });

    console.log('🔍 Verificación resultado:', verification.verified);

    if (verification.verified && verification.registrationInfo) {
      const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
      
      user.devices.push({
        credentialID: isoBase64URL.fromBuffer(credentialID),
        credentialPublicKey: credentialPublicKey,
        counter,
      });
      
      delete user.currentChallenge;
      console.log('✅ Registro exitoso para:', email);
      res.json({ verified: true });
    } else {
      sendError(res, 400, 'Verificación fallida');
    }
  } catch (err) {
    console.error('💥 Error:', err);
    sendError(res, 500, 'Error al verificar registro');
  }
});

app.post('/generate-authentication-options', async (req, res) => {
  try {
    const { email } = req.body;
    console.log(`📧 Email recibido para auth: ${email}`);
    
    // SOLO esta línea - usando Map.get()
    const user = users.get(email);
    
    if (!user) {
      console.log('❌ Usuario no encontrado para auth');
      return res.status(404).json({ error: 'Usuario no registrado' });
    }
    
    console.log(`👤 Usuario encontrado: ${user.email}`);
    console.log(`📱 Dispositivos registrados: ${user.devices.length}`);
    
    // Esta validación extra por seguridad
    if (user.devices.length === 0) {
      return res.status(404).json({ error: 'Usuario no tiene dispositivos registrados' });
    }

    const allowCredentials = user.devices.map(dev => ({
      id: dev.credentialID,
      type: 'public-key',
      transports: ['internal'],
    }));

    const options = await generateAuthenticationOptions({
      timeout: 60000,
      userVerification: 'required',
      allowCredentials,
      rpID: 'axltest.dev',
    });

    user.currentChallenge = options.challenge;
    console.log('✅ Opciones de auth generadas');
    res.json(options);
  } catch (err) {
    console.error('💥 Error:', err);
    res.status(500).json({ error: 'Error al generar desafío' });
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

    const device = user.devices.find(d => d.credentialID === response.id);
    if (!device) return sendError(res, 400, 'Dispositivo desconocido');

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: 'https://axltest.dev',
      expectedRPID: 'axltest.dev',
      authenticator: {
        credentialID: isoBase64URL.toBuffer(device.credentialID),
        credentialPublicKey: device.credentialPublicKey,
        counter: device.counter,
      },
      requireUserVerification: true,
    });

    if (verification.verified) {
      device.counter = verification.authenticationInfo.newCounter;
      delete user.currentChallenge;
      console.log('✅ Autenticación exitosa para:', email);
      res.json({ verified: true, user: { email } });
    } else {
      sendError(res, 400, 'Autenticación fallida');
    }
  } catch (err) {
    console.error('💥 Error:', err);
    sendError(res, 500, 'Error al verificar autenticación');
  }
});

// Ruta de salud
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Servir frontend
if (process.env.NODE_ENV === 'production') {
  const DIST_DIR = path.resolve(__dirname, '..', 'frontend', 'dist');
  const INDEX_FILE = path.join(DIST_DIR, 'index.html');

  if (fs.existsSync(DIST_DIR)) {
    app.use(express.static(DIST_DIR));
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
      res.sendFile(INDEX_FILE);
    });
  }
}

const PORT = process.env.PORT; 
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ App corriendo en puerto ${PORT}`);
});