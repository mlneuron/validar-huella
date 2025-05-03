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

const userID = 'diputado-test';
let fakeDB = {};

// Registro
app.get('/generate-registration-options', (req, res) => {
  const options = generateRegistrationOptions({
    rpName: 'Sistema de Votación',
    userID,
    userName: 'diputado@ejemplo.com',
  });
  fakeDB[userID] = { registrationOptions: options };
  res.json(options);
});

app.post('/verify-registration', async (req, res) => {
  const { credential } = req.body;
  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge: fakeDB[userID].registrationOptions.challenge,
    expectedOrigin: 'https://validar-huella-production.up.railway.app',
    expectedRPID: 'validar-huella-production.up.railway.app',
  });
  if (verification.verified) {
    fakeDB[userID].credential = verification.registrationInfo;
  }
  res.json({ success: verification.verified });
});

// Autenticación
app.get('/generate-authentication-options', (req, res) => {
  const options = generateAuthenticationOptions({
    allowCredentials: [{
      id: fakeDB[userID].credential.credentialID,
      type: 'public-key',
    }],
  });
  fakeDB[userID].authOptions = options;
  res.json(options);
});

app.post('/verify-authentication', async (req, res) => {
  const { assertion } = req.body;
  const verification = await verifyAuthenticationResponse({
    response: assertion,
    expectedChallenge: fakeDB[userID].authOptions.challenge,
    expectedOrigin: 'https://auth-voto.up.railway.app',
    expectedRPID: 'auth-voto.up.railway.app',
    authenticator: fakeDB[userID].credential,
  });
  res.json({ success: verification.verified });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));