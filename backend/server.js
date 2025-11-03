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
const FRONTEND_ORIGIN = 'https://axltest.dev';
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
    console.log('📧 Email recibido:', email);
    
    if (!email) {
      return sendError(res, 400, 'Email requerido');
    }

    const userId = uuidv4();
    console.log('🆕 UserID generado:', userId);

    // CONFIGURACIÓN MÍNIMA ABSOLUTA - SIN parámetros opcionales
    console.log('🚀 Llamando a generateRegistrationOptions con configuración mínima...');
    
    const options = generateRegistrationOptions({
      rpName: 'AxlTest App',
      rpID: 'axltest.dev',
      userID: isoHelpers.fromUTF8String(userId),
      userName: email,
      // ELIMINAR TODOS los parámetros opcionales temporalmente
    });

    console.log('✅ Options recibidas:', options);
    console.log('✅ Challenge generado:', options.challenge);
    console.log('✅ ¿Tiene challenge?:', !!options.challenge);

    if (!options.challenge) {
      console.error('❌ generateRegistrationOptions devolvió objeto vacío o sin challenge');
      throw new Error('La librería WebAuthn devolvió objeto vacío - verificar configuración');
    }

    // Guardar usuario
    users.set(email, { 
      id: userId, 
      email, 
      devices: [], 
      currentChallenge: options.challenge 
    });

    console.log('🎉 ÉXITO: Opciones generadas correctamente');
    res.json(options);
  } catch (err) {
    console.error('💥 Error CAPTURADO en generate-registration-options:');
    console.error('💥 Mensaje:', err.message);
    console.error('💥 Stack:', err.stack);
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
      expectedOrigin: 'https://axltest.dev',
      expectedRPID: 'axltest.dev',
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
app.post('/generate-authentication-options', (req, res) => {
  console.log('🔍 Origin recibido:', req.get('Origin'));
  console.log('🔍 Host recibido:', req.get('Host'));
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
      rpID: 'axltest.dev',
    });

    user.currentChallenge = options.challenge;
    res.json(options);
  } catch (err) {
    console.error('💥 Error en /generate-authentication-options:', err);
    sendError(res, 500, 'Error al generar desafío');
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

const PORT = process.env.PORT; 
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ App corriendo en puerto ${PORT}`);
});