import express from 'express';
import http from 'http';
import path from 'path';
import { TrackerServer } from './TrackerServer';

const PORT = 3000;
const app = express();
const server = http.createServer(app);

// クライアントのビルド済みファイルを静的に配信
const clientPath = path.join(__dirname, '../../client/dist');
app.use(express.static(clientPath));

// シグナリングサーバーをHTTPサーバーにアタッチ
const tracker = new TrackerServer(server);

console.log(`[TrackerServer] Serving UI from ${clientPath}`);
console.log(`[TrackerServer] Listening on http://localhost:${PORT}`);

server.listen(PORT);

process.on('SIGINT', () => {
  console.log('Shutting down...');
  tracker.shutdown();
  process.exit(0);
});
