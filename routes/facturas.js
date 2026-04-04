const express = require('express');
const router = express.Router();
const { getArcaInstance } = require('../arca-cache');

// Helper para manejo centralizado de errores de Arca
const handleArcaError = (e, res) => {
    console.error('💥 ERROR Arca:', e);
    
    if (e.name === 'ArcaWSFEError') {
        return res.json({ 
            ok: false, 
            error: e.errors[0]?.msg || 'Error en validación WSFE', 
            codigos: e.errors.map(x => x.code) 
        });
    }
    
    if (e.name === 'ArcaAuthError') {
        return res.json({ 
            ok: false, 
            error: "Error de autenticación", 
            detalle: e.message 
        });
    }
    
    res.json({ ok: false, error: e.message || 'Error desconocido' });
};

// POST /facturar
router.post('/facturar', async (req, res) => {
    try {
        const { cuit, cert, key, production, ...datos } = req.body;
        const arca = getArcaInstance({ cuit, cert, key, production });
        
        const result = await arca.facturar(datos);
        
        res.json({ 
            ok: true, 
            cae: result.cae, 
            caeVencimiento: result.caeVencimiento, 
            cbteNro: result.cbteNro, 
            importes: result.importes 
        });
    } catch (e) {
        handleArcaError(e, res);
    }
});

// POST /nota-credito
router.post('/nota-credito', async (req, res) => {
    try {
        const { cuit, cert, key, production, ...datos } = req.body;
        const arca = getArcaInstance({ cuit, cert, key, production });
        
        const result = await arca.notaCredito(datos);
        
        res.json({ 
            ok: true, 
            cae: result.cae, 
            caeVencimiento: result.caeVencimiento, 
            cbteNro: result.cbteNro, 
            importes: result.importes 
        });
    } catch (e) {
        handleArcaError(e, res);
    }
});

// POST /nota-debito
router.post('/nota-debito', async (req, res) => {
    try {
        const { cuit, cert, key, production, ...datos } = req.body;
        const arca = getArcaInstance({ cuit, cert, key, production });
        
        const result = await arca.notaDebito(datos);
        
        res.json({ 
            ok: true, 
            cae: result.cae, 
            caeVencimiento: result.caeVencimiento, 
            cbteNro: result.cbteNro, 
            importes: result.importes 
        });
    } catch (e) {
        handleArcaError(e, res);
    }
});

// GET /ultimo-comprobante
router.get('/ultimo-comprobante', async (req, res) => {
    try {
        const { cuit, cert, key, production, ptoVta, cbteTipo } = req.query;
        const arca = getArcaInstance({ cuit, cert, key, production });
        
        const ultimo = await arca.ultimoComprobante(Number(ptoVta), Number(cbteTipo));
        
        res.json({ ok: true, ultimo });
    } catch (e) {
        handleArcaError(e, res);
    }
});

// GET /puntos-venta
router.get('/puntos-venta', async (req, res) => {
    try {
        const { cuit, cert, key, production } = req.query;
        const arca = getArcaInstance({ cuit, cert, key, production });
        
        const puntosVenta = await arca.getPuntosVenta();
        
        res.json({ ok: true, puntosVenta });
    } catch (e) {
        handleArcaError(e, res);
    }
});

// GET /health
router.get('/health', (req, res) => {
    res.json({ ok: true, service: "arca-service", ts: Date.now() });
});

module.exports = router;
