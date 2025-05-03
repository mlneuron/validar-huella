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

// Generar opciones de registro
app.post('/generate-registration-options', (req, res) => {
  const { userID } = req.body;
  if (!userID) return res.status(400).json({ error: 'Falta userID' });

  const options = generateRegistrationOptions({
    rpName: 'Sistema de Votación',
    userID,
    userName: `${userID}@ejemplo.com`,
  });

  fakeDB[userID] = { registrationOptions: options };
  res.json(options);
});

// Verificar registro
app.post('/verify-registration', async (req, res) => {
  const { credential, userID } = req.body;
  if (!fakeDB[userID]) return res.status(400).json({ error: 'Usuario no registrado' });

  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge: fakeDB[userID].registrationOptions.challenge,
    expectedOrigin: 'https://validar-huella-production.up.railway.app',
    expectedRPID: 'validar-huella-production.up.railway.app',
  });

  if (verification.verified && verification.registrationInfo) {
    fakeDB[userID].credential = verification.registrationInfo;
    console.log(`✔️ Credencial registrada para ${userID}`);
  } else {
    console.log(`❌ Registro fallido para ${userID}`);
  }

  res.json({ success: verification.verified });
});

// Generar opciones de autenticación
app.post('/generate-authentication-options', (req, res) => {
  const { userID } = req.body;
  if (!fakeDB[userID] || !fakeDB[userID].credential) {
    return res.status(400).json({ error: 'No hay huella registrada para este usuario' });
  }

  const options = generateAuthenticationOptions({
    allowCredentials: [{
      id: fakeDB[userID].credential.credentialID,
      type: 'public-key',
    }],
  });

  fakeDB[userID].authOptions = options;
  res.json(options);
});

// Verificar autenticación
app.post('/verify-authentication', async (req, res) => {
  const { assertion, userID } = req.body;
  if (!fakeDB[userID]) return res.status(400).json({ error: 'Usuario no registrado' });

  const verification = await verifyAuthenticationResponse({
    response: assertion,
    expectedChallenge: fakeDB[userID].authOptions.challenge,
    expectedOrigin: 'https://validar-huella-production.up.railway.app',
    expectedRPID: 'validar-huella-production.up.railway.app',
    authenticator: fakeDB[userID].credential,
  });

  if (verification.verified) {
    console.log(`🎉 Validación exitosa para ${userID}`);
  } else {
    console.log(`❌ Falló la validación para ${userID}`);
  }

  res.json({ success: verification.verified });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
