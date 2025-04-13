import axios from 'axios';
import https from 'https';
import forge from 'node-forge';
import { ElGamal } from './crypto/elgamal.js';
import { registerVoter } from './voter-registration.js';
import { CertificateAuthority } from './crypto/ca.js';
import crypto from 'crypto';

interface VoteOptions {
    voterId: string;
    privateKey: string;
    certificate: string;
    choice: number;
}

interface VoteReceipt {
    receiptId: string;
    voterId: string;
    voteHash: string;
    timestamp: number;
}

export async function castVote({ voterId, privateKey, certificate, choice }: VoteOptions): Promise<VoteReceipt> {
    try {
        // First get the election state to get ElGamal parameters and CA certificate
        const stateResponse = await axios.get('https://localhost:3000/election-state', {
            httpsAgent: new https.Agent({ rejectUnauthorized: false })
        });
        
        // Initialize ElGamal with server's parameters
        const elgamal = ElGamal.fromPublicParams(stateResponse.data.elgamalParams);
        
        // Initialize CA with server's certificate
        const ca = new CertificateAuthority(stateResponse.data.caCertificate);
        
        // Verify our certificate with server's CA
        console.log('Verifying voter certificate...');
        const certValid = ca.verifyCertificate(certificate);
        if (!certValid) {
            console.error('Certificate verification failed locally');
            throw new Error('Invalid certificate');
        }
        console.log('Certificate verified successfully');
        
        // Validate vote choice
        if (typeof choice !== 'number' || choice < 0) {
            throw new Error('Invalid vote choice');
        }

        // For ElGamal, we encrypt 1 for the chosen option, 0 for others
        const vote = BigInt(1);  // We always encrypt 1 to represent a vote
        console.log('Encrypting vote for choice:', choice);
        const encryptedVote = elgamal.encrypt(vote);
        
        // Generate ZKP to prove vote is valid (0 or 1)
        const zkp = elgamal.generateZKP(vote, encryptedVote.k);

        // Generate vote hash for receipt
        const voteData = encryptedVote.c1.toString() + encryptedVote.c2.toString() + choice.toString();
        const voteHash = crypto.createHash('sha256').update(voteData).digest('hex');
        const receiptId = crypto.randomBytes(16).toString('hex');
        const timestamp = Date.now();

        // Sign the encrypted vote and choice
        const privateKeyObj = forge.pki.privateKeyFromPem(privateKey);
        const md = forge.md.sha256.create();
        md.update(voteData);
        const signature = forge.util.encode64(privateKeyObj.sign(md));

        // Send the vote request
        console.log('Sending vote request...');
        const response = await axios.post('https://localhost:3000/vote', {
            voterId,
            choice,
            encryptedVote: {
                c1: encryptedVote.c1.toString(),
                c2: encryptedVote.c2.toString()
            },
            signature,
            certificate,
            zkp: {
                commitment: zkp.commitment.toString(),
                challenge: zkp.challenge.toString(),
                response: zkp.response.toString()
            },
            receiptId,
            voteHash
        }, {
            httpsAgent: new https.Agent({ rejectUnauthorized: false })
        });

        if (response.data.success) {
            const receipt: VoteReceipt = {
                receiptId,
                voterId,
                voteHash,
                timestamp
            };
            console.log('Vote cast successfully. Receipt:', receipt);
            return receipt;
        }

        throw new Error('Vote casting failed');
    } catch (error) {
        console.error('Vote casting error:', error);
        const errorMessage = error instanceof Error ? error.message : 'Voting failed';
        throw new Error(`Failed to cast vote: ${errorMessage}`);
    }
}

// Example usage with proper registration flow
async function example() {
    try {
        // First register the voter
        const registration = await registerVoter("Alice");
        
        // Then cast their vote
        const result = await castVote({
            voterId: registration.voterId,
            privateKey: registration.privateKey,
            certificate: registration.certificate,
            choice: 1
        });
        
        console.log('Vote cast successfully:', result);
    } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : 'Unknown error');
    }
} 

example();