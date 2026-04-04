const express = require('express');
const cors = require('cors');
const facturasRouter = require('./routes/facturas');

const app = express();
const PORT = process.env.PORT || 3001;

// Middlewares
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Montar rutas
app.use('/', facturasRouter);

// Handler global para errores inesperados (HTTP 500)
app.use((err, req, res, next) => {
    console.error('💥 Error inesperado:', err);
    res.status(500).json({ ok: false, error: 'Error interno del servidor' });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Arca Service running on port ${PORT}`);
});
