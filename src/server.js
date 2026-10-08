import { app } from './app.js';
import { config } from './config.js';
import { closeDatabase } from './database.js';

const server = app.listen(config.port, () => {
  console.info(`PhishGuard Node API listening on port ${config.port}`);
  console.info(`SQLite database: ${config.sqlitePath}`);
});

function shutdown() {
  server.close(() => {
    closeDatabase();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
