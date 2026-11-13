import React, { useState, useEffect } from 'react';

export default function App() {
  const [health, setHealth] = useState({ status: 'cargando...', message: 'Conectando con la API...' });

  useEffect(() => {
    fetch('http://localhost:4000/api/health')
      .then(res => res.json())
      .then(data => setHealth(data))
      .catch(err => setHealth({ status: 'error', message: 'No se pudo conectar al Backend' }));
  }, []);

  return (
    <div style={{ padding: '40px', fontFamily: 'var(--font-family-base)' }}>
      <header style={{ marginBottom: '24px' }}>
        <h1 style={{ color: 'var(--button-primary-bg)' }}>SportCorp Perú | Portal E-commerce & ERP</h1>
        <p>Infraestructura inicial desplegada con éxito bajo estándares Shift Left y Licenciamiento $0.</p>
      </header>
      <div style={{ padding: '20px', background: 'var(--surface-card)', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
        <h3>Estado de Conectividad del Sistema:</h3>
        <p><strong>Estado API:</strong> {health.status}</p>
        <p><strong>Mensaje:</strong> {health.message}</p>
        {health.database_time && <p><strong>Base de Datos PostgreSQL (Hora Servidor):</strong> {health.database_time}</p>}
      </div>
    </div>
  );
}
