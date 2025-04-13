import express from 'express';
import https from 'https';
import cors from 'cors';
import { CONFIG } from './config/network';
import fs from 'fs';
import { execSync } from 'child_process';

const app = express();

// CORS configuration
app.use(cors({
    origin: CONFIG.CLIENT.ALLOWED_ORIGINS,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

app.use(express.json());

// Basic test route
app.get('/', (req, res) => {
    res.send('Server is running with HTTPS!');
});

// Generate SSL certificates if they don't exist
let key, cert;
try {
    key = fs.readFileSync(CONFIG.SERVER.SSL.key);
    cert = fs.readFileSync(CONFIG.SERVER.SSL.cert);
} catch (error) {
    console.warn('Certificate files not found, generating self-signed certificates...');
    try {
        if (!fs.existsSync('./certs')) {
            fs.mkdirSync('./certs');
        }
        // Create OpenSSL config file for SAN
        const opensslConfig = `
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = evoting.local

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = evoting.local
DNS.2 = auth.evoting.local
DNS.3 = localhost
        `;
        fs.writeFileSync('./certs/openssl.cnf', opensslConfig);
        
        // Generate certificate with SAN
        execSync('openssl req -x509 -newkey rsa:2048 -keyout ./certs/server.key -out ./certs/server.crt -days 365 -nodes -config ./certs/openssl.cnf -extensions v3_req');
        key = fs.readFileSync(CONFIG.SERVER.SSL.key);
        cert = fs.readFileSync(CONFIG.SERVER.SSL.cert);
        
        // Clean up config file
        fs.unlinkSync('./certs/openssl.cnf');
    } catch (opensslError) {
        console.error('Error generating certificates:', opensslError);
        process.exit(1);
    }
}

// Create HTTPS server
const server = https.createServer({
    key: key,
    cert: cert
}, app);

server.listen(CONFIG.SERVER.PORT, CONFIG.SERVER.HOST, () => {
    console.log(`Server running on https://${CONFIG.SERVER.HOST}:${CONFIG.SERVER.PORT}`);
}); 