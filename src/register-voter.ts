import axios from 'axios';
import https from 'https';
import forge from 'node-forge';

async function registerVoter(voterId: string) {
    // Generate RSA key pair
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    
    // Convert public key to PEM format
    const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
    
    try {
        const response = await axios.post('https://localhost:3000/register', {
            voterId,
            publicKey: publicKeyPem
        }, {
            httpsAgent: new https.Agent({ rejectUnauthorized: false })
        });

        // Save these securely
        console.log('Registration successful!');
        console.log('Certificate:', response.data.certificate);
        console.log('Private Key:', forge.pki.privateKeyToPem(keypair.privateKey));

    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Registration failed';
        console.error(errorMessage);
    }
}

// Usage
registerVoter('voter123'); 