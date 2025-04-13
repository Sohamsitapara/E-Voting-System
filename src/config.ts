export const config = {
    server: {
      port: process.env.PORT ? parseInt(process.env.PORT) : 3000,
      host: process.env.HOST || 'localhost'
    },
    security: {
      keySize: 2048,
      certificateValidityDays: 365
    },
    voting: {
      minOptions: 2,
      maxOptions: 10,
      minDurationHours: 1,
      maxDurationHours: 168 // 1 week
    },
    trustees: {
      urls: {
        1: process.env.TRUSTEE1_URL || "https://trustee1:3001",
        2: process.env.TRUSTEE2_URL || "https://trustee2:3002",
        3: process.env.TRUSTEE3_URL || "https://trustee3:3003"
      },
      threshold: 3,
      total: 3
    }
  };