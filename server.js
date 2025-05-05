import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let fakeDB = {};
console.log('\n::: >> 1.5');

// Registro - paso 1
app.post('/generate-registration-options', (req, res) => {
  console.log('\n---- Iniciam /generate-registration-options');
  const { userID } = req.body;
  console.log(`[server] userID recibido: ${userID}`);

  if (!userID) {
    console.warn(`[server] ❌ Falta userID`);
    return res.status(400).json({ error: 'Falta userID' });
  }

  const options = generateRegistrationOptions({
    rpName: 'Sistema de Votación',
    userID,
    userName: `${userID}@ejemplo.com`,
  });

  fakeDB[userID] = { registrationOptions: options };
  console.log(`[server] ✅ Opciones generadas para ${userID}`);
  res.json(options);
});

// Registro - paso 2
app.post('/verify-registration', async (req, res) => {
  console.log('\n---- Iniciam /verify-registration');
  const { credential, userID } = req.body;
  const origin = req.headers.origin;
  console.log(`[server] userID recibido: ${userID}`);
  console.log(`[server] credential recibida:`, credential);
  console.log(`[server] 🧭 Origin recibido: ${origin}`);

  if (!fakeDB[userID]) {
    console.warn(`[server] ❌ No existe userID en fakeDB`);
    return res.status(400).json({ error: 'Usuario no registrado' });
  }

  const hostname = req.hostname;
  const rpidValido = ['auth.sivote.neuron.com.mx', 'validar-huella-production.up.railway.app'];

  if (!rpidValido.includes(hostname)) {
    return res.status(400).json({ error: 'RPID no válido' });
  }

  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge: fakeDB[userID].registrationOptions.challenge,
    expectedOrigin: origin,
    expectedRPID: hostname, // ← ahora usa el que realmente se usó
  });

  if (verification.verified && verification.registrationInfo) {
    fakeDB[userID].credential = verification.registrationInfo;
    console.log(`✔️ Credencial registrada para ${userID}`);
  } else {
    console.log(`❌ Registro fallido para ${userID}`);
  }

  res.json({ success: verification.verified });
});

// Autenticación - paso 1
app.post('/generate-authentication-options', (req, res) => {
  console.log('\n---- Iniciam /generate-authentication-options');
  const { userID } = req.body;
  console.log(`[server] userID recibido: ${userID}`);

  if (!fakeDB[userID] || !fakeDB[userID].credential) {
    console.warn(`[server] ❌ No hay credencial registrada para ${userID}`);
    return res.status(400).json({ error: 'No hay huella registrada para este usuario' });
  }

  const options = generateAuthenticationOptions({
    allowCredentials: [{
      id: fakeDB[userID].credential.credentialID,
      type: 'public-key',
    }],
  });

  fakeDB[userID].authOptions = options;
  console.log(`[server] ✅ Opciones de autenticación generadas para ${userID}`);
  res.json(options);
});

// Autenticación - paso 2
app.post('/verify-authentication', async (req, res) => {
  console.log('\n---- Iniciam /verify-authentication');
  const { assertion, userID } = req.body;
  const origin = req.headers.origin;
  console.log(`[server] userID recibido: ${userID}`);
  console.log(`[server] assertion recibida:`, assertion);
  console.log(`[server] 🧭 Origin recibido: ${origin}`);

  if (!fakeDB[userID]) {
    console.warn(`[server] ❌ Usuario no registrado`);
    return res.status(400).json({ error: 'Usuario no registrado' });
  }

  const verification = await verifyAuthenticationResponse({
    response: assertion,
    expectedChallenge: fakeDB[userID].authOptions.challenge,
    expectedOrigin: origin,
    expectedRPID: 'auth.sivote.neuron.com.mx',
    authenticator: fakeDB[userID].credential,
  });

  if (verification.verified) {
    console.log(`🎉 Validación exitosa para ${userID}`);
  } else {
    console.warn(`❌ Falló la validación para ${userID}`);
  }

  res.json({ success: verification.verified });
});

// Prueba de conexión
app.post('/prueba-conexion', (req, res) => {
  console.log('✅ [server] Recibida prueba de conexión.');
  res.json({ ok: true, mensaje: 'Servidor operativo', hora: new Date().toISOString() });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
