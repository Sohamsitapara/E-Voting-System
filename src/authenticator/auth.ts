import forge from 'node-forge';

export async function verifyVoterCredentials(voterId: string, certificate: string, signature: string): Promise<boolean> {
    try {
        const cert = forge.pki.certificateFromPem(certificate);
        const publicKey = cert.publicKey as forge.pki.rsa.PublicKey;
        const md = forge.md.sha256.create();
        md.update(voterId, 'utf8');
        return publicKey.verify(md.digest().bytes(), forge.util.decode64(signature));
    } catch (error) {
        console.error('Voter credential verification failed:', error);
        return false;
    }
}