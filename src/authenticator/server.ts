import express from "express";
import https from "https";
import fs from "fs";
import cors from "cors";
import { CONFIG } from "../config/network";
import { verifyVoterCredentials } from "./auth";
import { execSync } from "child_process";

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

app.post("/verify", async (req, res) => {
  try {
    const { voterId, certificate, signature } = req.body;
    // Verify voter credentials
    const isValid = await verifyVoterCredentials(
      voterId,
      certificate,
      signature
    );
    res.json({ valid: isValid });
  } catch (error) {
    res.status(500).json({ error: "Verification failed" });
  }
});

let key, cert;
try {
  key = fs.readFileSync("./certs/auth.key");
  cert = fs.readFileSync("./certs/auth.crt");
} catch (error) {
  console.warn(
    "Certificate files not found, generating self-signed certificates using OpenSSL..."
  );
  try {
    if (!fs.existsSync("./certs")) {
      fs.mkdirSync("./certs");
    }
    execSync(
      'openssl req -x509 -newkey rsa:2048 -keyout ./certs/auth.key -out ./certs/auth.crt -days 365 -nodes -subj "/CN=localhost"'
    );
    key = fs.readFileSync("./certs/auth.key");
    cert = fs.readFileSync("./certs/auth.crt");
  } catch (opensslError) {
    console.error("Error generating certificates with OpenSSL:", opensslError);
    process.exit(1);
  }
}

https
  .createServer(
    {
      key,
      cert,
    },
    app
  )
  .listen(CONFIG.AUTHENTICATOR.PORT, CONFIG.AUTHENTICATOR.HOST);
