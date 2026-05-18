module.exports = {
  apps: [{
    name: "infra-monitor",
    script: "./backend/src/server.js",
    instances: 1,
    exec_mode: "fork",
    watch: false,
    max_memory_restart: "250M", // Hard limit: Restart gracefully if it exceeds 250MB RAM
    env: {
      NODE_ENV: "production",
      PORT: 3000
    },
    error_file: "logs/err.log",
    out_file: "logs/out.log",
    time: true
  }]
};
