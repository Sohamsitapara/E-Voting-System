import forge from 'node-forge';
import axios from 'axios';
import https from 'https';
import { CertificateAuthority } from './crypto/ca.js';

interface RegistrationResult {
    voterId: string;
    privateKey: string;
    publicKey: string;
    certificate: string;
}

export async function registerVoter(voterName: string): Promise<RegistrationResult> {
    try {
        console.log('Starting voter registration for:', voterName);
        
        // First get the election state to ensure we're in registration phase
        const stateResponse = await axios.get('https://localhost:3000/election-state', {
            httpsAgent: new https.Agent({ rejectUnauthorized: false })
        });
        console.log('Current election phase:', stateResponse.data.phase);

        if (!stateResponse.data.phase) {
            throw new Error('Invalid election state received');
        }

        if (stateResponse.data.phase !== 'REGISTRATION') {
            throw new Error(`Cannot register voters in ${stateResponse.data.phase} phase`);
        }

        // Generate RSA key pair
        console.log('Generating RSA key pair...');
        const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
        console.log('Key pair generated successfully');
        
        // Convert keys to PEM format
        const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);
        const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
        
        // Generate a unique voter ID
        const voterId = forge.util.encode64(forge.random.getBytesSync(16));
        console.log('Generated voter ID:', voterId);
        
        // Register with the voting server and get certificate
        console.log('Sending registration request to server...');
        const response = await axios.post('https://localhost:3000/register', {
            voterId,
            publicKey: publicKeyPem
        }, {
            headers: {
                'Content-Type': 'application/json',
            },
            httpsAgent: new https.Agent({ 
                rejectUnauthorized: false
            })
        });

        if (!response.data || !response.data.certificate) {
            throw new Error('No certificate received from server');
        }

        const { certificate } = response.data;
        console.log('Received certificate from server');

        // Initialize CA with server's certificate
        if (!stateResponse.data.caCertificate) {
            throw new Error('No CA certificate available from server');
        }

        console.log('Initializing CA with server certificate...');
        const ca = new CertificateAuthority(stateResponse.data.caCertificate);
        
        // Verify the certificate locally
        console.log('Verifying received certificate...');
        const isValid = ca.verifyCertificate(certificate);
        
        if (!isValid) {
            throw new Error('Server provided invalid certificate');
        }
        
        console.log('Certificate verified successfully for voter:', voterId);
        
        return {
            voterId,
            privateKey: privateKeyPem,
            publicKey: publicKeyPem,
            certificate
        };
    } catch (error) {
        if (axios.isAxiosError(error)) {
            const errorMsg = error.response?.data?.error || error.message;
            console.error('Registration error:', errorMsg);
            throw new Error(`Registration failed: ${errorMsg}`);
        }
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        console.error('Registration error:', errorMsg);
        throw new Error(`Registration failed: ${errorMsg}`);
    }
} 