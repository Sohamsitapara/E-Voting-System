import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export async function setupSSL(): Promise<void> {
  const certsDir = path.join(process.cwd(), 'certs');

  if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir, { recursive: true });
  }

  const privateKeyPath = path.join(certsDir, 'private-key.pem');
  const certificatePath = path.join(certsDir, 'certificate.pem');

  // Check if OpenSSL is installed
  try {
    await executeCommand('openssl version');
  } catch (error) {
    throw new Error('OpenSSL is not installed on this system');
  }

  const command = os.platform() === 'win32' 
    ? `openssl req -x509 -newkey rsa:4096 -keyout "${privateKeyPath}" -out "${certificatePath}" -days 365 -nodes -subj "/CN=localhost"`
    : `openssl req -x509 -newkey rsa:4096 -keyout "${privateKeyPath}" -out "${certificatePath}" -days 365 -nodes -subj "/CN=localhost"`;

  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error('Error generating SSL certificates:', error);
        reject(error);
        return;
      }

      if (!fs.existsSync(privateKeyPath) || !fs.existsSync(certificatePath)) {
        reject(new Error('SSL certificate files were not created successfully'));
        return;
      }

      // Set proper permissions
      try {
        fs.chmodSync(privateKeyPath, 0o600);
        fs.chmodSync(certificatePath, 0o644);
      } catch (err) {
        console.warn('Could not set certificate file permissions');
      }

      resolve();
    });
  });
}

function executeCommand(command: string): Promise<void> {
  return new Promise((resolve, reject) => {
    exec(command, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
} 