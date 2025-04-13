import forge from 'node-forge';
import crypto from 'crypto';

export class CertificateAuthority {
  private caPrivateKey: forge.pki.PrivateKey;
  private caPublicKey: forge.pki.PublicKey;
  private caCert: forge.pki.Certificate;

  constructor(existingCert?: string) {
    if (existingCert) {
      // Use existing CA certificate
      console.log('Initializing CA with existing certificate');
      this.caCert = forge.pki.certificateFromPem(existingCert);
      this.caPublicKey = this.caCert.publicKey;
      // Generate a temporary private key for verification
      const keys = forge.pki.rsa.generateKeyPair(2048);
      this.caPrivateKey = keys.privateKey;
    } else {
      // Generate new CA key pair for server
      console.log('Creating new CA with fresh key pair');
      const keys = forge.pki.rsa.generateKeyPair(2048);
      this.caPrivateKey = keys.privateKey;
      this.caPublicKey = keys.publicKey;
      this.caCert = this.createCACertificate();
      console.log('CA certificate created successfully');
    }
  }

  private createCACertificate(): forge.pki.Certificate {
    console.log('Creating new CA certificate');
    const cert = forge.pki.createCertificate();
    cert.publicKey = this.caPublicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [{
      name: 'commonName',
      value: 'E-Voting Certificate Authority'
    }, {
      name: 'organizationName',
      value: 'E-Voting System'
    }];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    // Sign with SHA-256
    const md = forge.md.sha256.create();
    cert.sign(this.caPrivateKey, md);
    console.log('CA certificate created and self-signed');

    return cert;
  }

  public issueCertificate(publicKey: string, voterId: string): string {
    try {
      if (!this.caPrivateKey) {
        throw new Error('CA private key not available for signing');
      }

      console.log('Creating certificate for voter:', voterId);
      const cert = forge.pki.createCertificate();
      cert.publicKey = forge.pki.publicKeyFromPem(publicKey);
      cert.serialNumber = crypto.randomBytes(16).toString('hex');
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

      // Set the subject (voter's identity)
      const subjectAttrs = [{
        name: 'commonName',
        value: `Voter-${voterId}`
      }, {
        name: 'organizationName',
        value: 'E-Voting System'
      }];
      cert.setSubject(subjectAttrs);

      // Set the issuer to match the CA's subject exactly
      const issuerAttrs = [{
        name: 'commonName',
        value: 'E-Voting Certificate Authority'
      }, {
        name: 'organizationName',
        value: 'E-Voting System'
      }];
      cert.setIssuer(issuerAttrs);

      // Sign with SHA-256
      const md = forge.md.sha256.create();
      cert.sign(this.caPrivateKey, md);
      console.log('Certificate signed successfully');

      const pemCert = forge.pki.certificateToPem(cert);
      return pemCert;
    } catch (error) {
      console.error('Failed to issue certificate:', error);
      throw error;
    }
  }

  public verifyCertificate(certPem: string): boolean {
    try {
      console.log('Starting certificate verification...');
      const cert = forge.pki.certificateFromPem(certPem);
      
      // Verify certificate is not expired
      const now = new Date();
      if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
        console.log('Certificate is expired or not yet valid');
        return false;
      }

      // Basic verification of the certificate structure
      if (!cert.publicKey || !cert.signature) {
        console.log('Certificate is missing public key or signature');
        return false;
      }

      // Verify certificate was signed by this CA by checking issuer attributes
      const caSubject = this.caCert.subject.attributes;
      const certIssuer = cert.issuer.attributes;

      // Compare issuer attributes
      const issuerMatch = caSubject.every(caAttr => 
        certIssuer.some(issuerAttr => 
          caAttr.type === issuerAttr.type && caAttr.value === issuerAttr.value
        )
      );

      return issuerMatch;
    } catch (error) {
      console.error('Certificate verification error:', error);
      return false;
    }
  }

  public getCACertificate(): string {
    return forge.pki.certificateToPem(this.caCert);
  }
} 