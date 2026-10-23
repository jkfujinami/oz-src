import React from 'react';
import ReactDOM from 'react-dom/client';
import { OzApp } from '@oz/ui';
import { DEFAULT_TRACKER_URL, GUARD_TRUST, ICE_SERVERS } from './appConfig';
import '@oz/ui/styles.css';
import { sodiumReady } from '@oz/core';

window.addEventListener('error', (e) => {
  console.error('[UNCAUGHT ERROR]', e.error ? (e.error.stack || e.error) : e.message);
});

window.addEventListener('unhandledrejection', (e) => {
  console.error('[UNHANDLED REJECTION]', e.reason ? (e.reason.stack || e.reason) : e.reason);
});

async function bootstrap() {
  try {
    await sodiumReady;
    const rootEl = document.getElementById('root');
    if (!rootEl) return;
    ReactDOM.createRoot(rootEl).render(
      <React.StrictMode>
        <OzApp badge="Desktop Full Node" defaultTrackerUrl={DEFAULT_TRACKER_URL} trust={GUARD_TRUST} iceServers={ICE_SERVERS} />
      </React.StrictMode>,
    );
  } catch (err) {
    console.error('Failed to initialize libsodium or mount UI:', err);
  }
}

bootstrap();
