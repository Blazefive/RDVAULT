// src/index.js
import React from 'react';
import ReactDOM from 'react-dom/client';
import { I18nProvider } from './i18n';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <I18nProvider defaultLang="en">
    <App />
  </I18nProvider>
);
