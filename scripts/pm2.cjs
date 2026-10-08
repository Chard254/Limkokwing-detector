const path = require('node:path');

process.env.PM2_HOME = path.resolve(__dirname, '..', '.pm2');
require('pm2/bin/pm2');
