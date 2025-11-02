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

// ✅ CORREGIDO: importar helpers desde la ruta específica
const { isoUint8Array } = require('@simplewebauthn/server/helpers');

const app = express();

const FRONTEND_ORIGIN = 'https://axltest.lat';
app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json({ limit: '10mb' }));

const users = new Map();

// Helper: responder con error
const sendError = (res, status, message) => {
  console.warn(`⚠️ Error ${status}:`, message);
  return res.status(status).json({ error: message });
};

// 1. Registro: generar desafío
app.post('/generate-registration-options', (req, res) => {
  try {
    const { email } = req.body;
    console.log('📩 Registro solicitado para:', email);

    if (!email || typeof email !== 'string') {
      return sendError(res, 400, 'Email válido es requerido');
    }

    const userId = uuidv4();
    const options = generateRegistrationOptions({
      rpName: 'Mi App Web',
      rpID: 'axltest.lat',
      userID: isoUint8Array.fromUTF8String(userId), // ✅ CORREGIDO: string → Uint8Array
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

    console.log('✅ Opciones generadas para:', email);
    res.json(options);
  } catch (err) {
    console.error('💥 Error en /generate-registration-options:', err);
    sendError(res, 500, 'Error interno al generar opciones');
  }
});

// 2. Verificar registro
app.post('/verify-registration', async (req, res) => {
  try {
    const { email, response } = req.body;
    if (!email || !response) {
      return sendError(res, 400, 'Email y respuesta son requeridos');
    }

    const user = users.get(email);
    if (!user) return sendError(res, 404, 'Usuario no encontrado');

    const expectedChallenge = user.currentChallenge;
    if (!expectedChallenge) {
      return sendError(res, 400, 'No hay desafío pendiente para este usuario');
    }

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
      console.log('✅ Registro verificado para:', email);
      return res.json({ verified: true });
    } else {
      return sendError(res, 400, 'Verificación fallida');
    }
  } catch (err) {
    console.error('💥 Error en /verify-registration:', err);
    sendError(res, 500, 'Error al verificar registro');
  }
});

// 3. Autenticación: generar desafío
app.post('/generate-authentication-options', (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return sendError(res, 400, 'Email requerido');

    const user = users.get(email);
    if (!user || user.devices.length === 0) {
      return sendError(res, 404, 'Usuario no registrado o sin dispositivos');
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
    console.log('🔑 Desafío de autenticación generado para:', email);
    res.json(options);
  } catch (err) {
    console.error('💥 Error en /generate-authentication-options:', err);
    sendError(res, 500, 'Error al generar desafío de autenticación');
  }
});

// 4. Verificar autenticación
app.post('/verify-authentication', async (req, res) => {
  try {
    const { email, response } = req.body;
    if (!email || !response) {
      return sendError(res, 400, 'Email y respuesta son requeridos');
    }

    const user = users.get(email);
    if (!user) return sendError(res, 404, 'Usuario no encontrado');

    const expectedChallenge = user.currentChallenge;
    if (!expectedChallenge) {
      return sendError(res, 400, 'No hay desafío pendiente');
    }

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
      console.log('✅ Autenticación exitosa para:', email);
      return res.json({ verified: true, user: { email } });
    } else {
      return sendError(res, 400, 'Autenticación fallida');
    }
  } catch (err) {
    console.error('💥 Error en /verify-authentication:', err);
    sendError(res, 500, 'Error al verificar autenticación');
  }
});

// Manejo de rutas no encontradas
app.use((req, res) => {
  console.warn('⚠️ Ruta no encontrada:', req.method, req.url);
  res.status(404).json({ error: 'Ruta no encontrada' });
});

// Manejo global de errores
app.use((err, req, res, next) => {
  console.error('🔥 Error no controlado:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

const PORT = 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Backend listo en http://localhost:${PORT}`);
  console.log(`🌍 Origen permitido: ${FRONTEND_ORIGIN}`);
});