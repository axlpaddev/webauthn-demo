import React, { useState, useEffect } from 'react';
import {
  startRegistration,
  startAuthentication,
} from '@simplewebauthn/browser';

// ✅ En producción, usamos rutas relativas (mismo dominio)
//const API_URL = '/api';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState('');
  const [webAuthnSupported, setWebAuthnSupported] = useState(null);
  const [webAuthnAvailable, setWebAuthnAvailable] = useState(false);
  const [usePassword, setUsePassword] = useState(false);

  useEffect(() => {
    const checkWebAuthnSupport = async () => {
      if (!window.PublicKeyCredential) {
        setWebAuthnSupported(false);
        return;
      }
      setWebAuthnSupported(true);
      try {
        const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        setWebAuthnAvailable(available);
      } catch (err) {
        setWebAuthnAvailable(false);
      }
    };
    checkWebAuthnSupport();
  }, []);

  const registerWebAuthn = async () => {
  try {
    // ✅ Validación y limpieza del email
    const cleanEmail = email.trim();
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      setStatus('❌ Por favor ingresa un email válido');
      return;
    }

    setStatus('1️⃣ Generando opciones de registro...');
    const response = await fetch('/generate-registration-options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: cleanEmail }), // ✅ usa el email limpio
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`HTTP ${response.status}: ${text.substring(0, 100)}`);
    }

    const regOptions = await response.json();
    if (!regOptions.challenge) {
      throw new Error('La respuesta no contiene "challenge"');
    }

    setStatus('2️⃣ Esperando autenticación biométrica...');
    const regResponse = await startRegistration(regOptions);

    setStatus('3️⃣ Verificando registro...');
    const verifyRes = await fetch('/verify-registration', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: cleanEmail, response: regResponse }),
    }).then(r => r.json());

    if (verifyRes.verified) {
      setStatus('✅ Registro biométrico exitoso!');
    } else {
      setStatus('❌ Verificación fallida');
    }
  } catch (err) {
    console.error(err);
    setStatus(`🚨 ERROR: ${err.message || 'Desconocido'}`);
  }
};

  const loginWebAuthn = async () => {
    try {
      setStatus('1️⃣ Generando desafío de autenticación...');
      const response = await fetch(`/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`HTTP ${response.status}: ${text.substring(0, 100)}`);
      }

      const authOptions = await response.json();
      if (!authOptions.challenge) {
        throw new Error('Respuesta sin "challenge"');
      }

      setStatus('2️⃣ Esperando autenticación biométrica...');
      const authResponse = await startAuthentication(authOptions);

      setStatus('3️⃣ Verificando...');
      const verifyRes = await fetch(`/verify-authentication`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, response: authResponse }),
      }).then(r => r.json());

      if (verifyRes.verified) {
        setStatus(`✅ Bienvenido, ${email}!`);
      } else {
        setStatus('❌ Autenticación fallida');
      }
    } catch (err) {
      console.error(err);
      setStatus(`🚨 ERROR: ${err.message || 'Desconocido'}`);
    }
  };

  const registerPassword = () => {
    setStatus('⚠️ Registro con contraseña no implementado');
  };

  const loginPassword = () => {
    if (password === '123456') {
      setStatus(`✅ Bienvenido (con contraseña), ${email}!`);
    } else {
      setStatus('❌ Contraseña incorrecta');
    }
  };

  return (
    <div style={{ padding: '2rem', maxWidth: '500px', margin: '0 auto', fontFamily: 'sans-serif' }}>
      <h1>🔐 Login con Biométrica o Contraseña</h1>

      <input
        type="email"
        placeholder="tu@email.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        style={{ width: '100%', padding: '0.5rem', marginBottom: '1rem' }}
      />

      <div style={{ marginBottom: '1rem' }}>
        <button
          onClick={() => setUsePassword(false)}
          disabled={webAuthnSupported === null}
          style={{
            marginRight: '0.5rem',
            backgroundColor: !usePassword ? '#007bff' : '#ddd',
            color: !usePassword ? 'white' : 'black',
          }}
        >
          Biométrica / Passkey
        </button>
        <button
          onClick={() => setUsePassword(true)}
          style={{
            backgroundColor: usePassword ? '#28a745' : '#ddd',
            color: usePassword ? 'white' : 'black',
          }}
        >
          Contraseña
        </button>
      </div>

      {usePassword ? (
        <>
          <input
            type="password"
            placeholder="Contraseña"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ width: '100%', padding: '0.5rem', marginBottom: '1rem' }}
          />
          <div>
            <button onClick={registerPassword} style={{ marginRight: '1rem' }}>
              📝 Registrarse
            </button>
            <button onClick={loginPassword}>🔓 Iniciar sesión</button>
          </div>
        </>
      ) : (
        <>
          {webAuthnSupported === null && <p>Detectando soporte biométrico...</p>}
          {webAuthnSupported === false && (
            <p style={{ color: 'orange' }}>
              ⚠️ Tu navegador no soporta autenticación biométrica.
            </p>
          )}
          {webAuthnSupported === true && !webAuthnAvailable && (
            <p style={{ color: 'orange' }}>
              ℹ️ Puede usar PIN o clave de seguridad.
            </p>
          )}
          <div>
            <button
              onClick={registerWebAuthn}
              disabled={!webAuthnSupported}
              style={{ marginRight: '1rem' }}
            >
              📝 Registrarse con biométrica
            </button>
            <button
              onClick={loginWebAuthn}
              disabled={!webAuthnSupported}
            >
              🔓 Iniciar sesión con biométrica
            </button>
          </div>
        </>
      )}

      <p style={{ marginTop: '1.5rem', minHeight: '2rem', color: '#333', backgroundColor: '#f8f9fa', padding: '0.5rem', borderRadius: '4px' }}>
        {status}
      </p>

      <small style={{ display: 'block', marginTop: '2rem', color: '#777' }}>
        💡 Usa un email válido. Funciona en móviles con huella/rostro.
      </small>
    </div>
  );
}

export default App;