export const CONFIG = {
    SERVER: {
        HOST: '0.0.0.0',  // Listen on all network interfaces
        PORT: 3000,
        PROTOCOL: 'https',
        SSL: {
            enabled: true,
            key: './certs/server.key',
            cert: './certs/server.crt'
        }
    },
    AUTHENTICATOR: {
        HOST: '0.0.0.0',  // Listen on all network interfaces
        PORT: 3001,
        PROTOCOL: 'https',
        SSL: {
            enabled: true,
            key: './certs/auth.key',
            cert: './certs/auth.crt'
        }
    },
    CLIENT: {
        ALLOWED_ORIGINS: [
            'https://localhost:3000',
            'https://localhost:3001',
            'https://localhost:3002',
            'https://192.168.29.193:3002',  // Client laptop
            'https://192.168.29.202:3000',  // Main server
            'https://192.168.29.180:3001'   // Auth server
        ]
    }
};

// URLs for client-side use
export const URLS = {
    MAIN_SERVER: `${CONFIG.SERVER.PROTOCOL}://${CONFIG.SERVER.HOST}:${CONFIG.SERVER.PORT}`,
    AUTH_SERVER: `${CONFIG.AUTHENTICATOR.PROTOCOL}://${CONFIG.AUTHENTICATOR.HOST}:${CONFIG.AUTHENTICATOR.PORT}`
}; 
