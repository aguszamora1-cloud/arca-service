console.log('VERSION: arcasdk-v1-' + new Date().toISOString());
const express = require('express');
const cors = require('cors');

const app = express();
app.use(process.env.NODE_ENV === 'production' ? cors() : cors({ origin: '*' }));
app.use(express.json());

const PORT = process.env.PORT || 3001;

// ────────────────────────────────────────────────────────────
//  Inicializar Arca SDK con credenciales desde env vars
//  (el SDK maneja WSAA internamente — no hace falta ningún
//   código de login, token, ni firma CMS)
// ────────────────────────────────────────────────────────────
let arca = null;

function getArcaInstance() {
    if (arca) return arca;

    const cuit = process.env.AFIP_CUIT;
    const cert = process.env.AFIP_CERT;
    const key  = process.env.AFIP_KEY;

    console.log('AFIP_CUIT:', process.env.AFIP_CUIT ? 'OK (' + process.env.AFIP_CUIT + ')' : 'VACÍO');
    console.log('AFIP_CERT length:', process.env.AFIP_CERT ? process.env.AFIP_CERT.length : 'VACÍO');
    console.log('AFIP_KEY length:', process.env.AFIP_KEY ? process.env.AFIP_KEY.length : 'VACÍO');

    if (!cuit || !cert || !key) {
        throw new Error(
            'Faltan variables de entorno: AFIP_CUIT, AFIP_CERT y/o AFIP_KEY no están definidas en Railway.'
        );
    }

    // Importación dinámica compatible con CJS
    const { Arca } = require('@arcasdk/core');

    arca = new Arca({
        cuit:  Number(cuit),
        cert:  cert,   // PEM string desde env var
        key:   key,    // PEM string desde env var
    });

    console.log(`✅ Arca SDK inicializado para CUIT ${cuit}`);
    return arca;
}

// ────────────────────────────────────────────────────────────
//  Health check
// ────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.send('ARCA SDK Service Online 🚀'));

// ────────────────────────────────────────────────────────────
//  POST /facturar
// ────────────────────────────────────────────────────────────
app.post('/facturar', async (req, res) => {
    try {
        const {
            tipoComprobante = 6,   // 6 = Factura B, 11 = Factura C, 1 = Factura A
            ptoVta          = 1,
            concepto        = 1,   // 1 = Productos
            docTipo         = 99,  // 99 = Consumidor final
            docNro          = 0,
            total,
        } = req.body;

        if (!total) {
            return res.status(400).json({ success: false, error: 'Falta el campo "total"' });
        }

        const sdk = getArcaInstance();

        // ── 1. Obtener el próximo número de comprobante ──────
        console.log(`📡 Consultando último comprobante (PtoVta=${ptoVta}, CbteTipo=${tipoComprobante})...`);
        const lastVoucher = await sdk.electronicBillingService.getLastVoucher({
            PtoVta:   Number(ptoVta),
            CbteTipo: Number(tipoComprobante),
        });
        const nextNumber = lastVoucher.CbteNro + 1;
        console.log(`📋 Próximo comprobante: ${nextNumber}`);

        // ── 2. Calcular importes ─────────────────────────────
        const totalAmount  = parseFloat(total);
        const isMonotributo = Number(tipoComprobante) === 11; // Factura C → sin IVA discriminado
        const impNeto      = isMonotributo
            ? totalAmount
            : parseFloat((totalAmount / 1.21).toFixed(2));
        const impIVA       = isMonotributo
            ? 0
            : parseFloat((totalAmount - impNeto).toFixed(2));

        // Fecha actual en formato YYYYMMDD
        const now   = new Date();
        const fecha = parseInt(
            now.toISOString().split('T')[0].replace(/-/g, ''),
            10
        );

        // ── 3. Construir payload de la factura ───────────────
        const payload = {
            CantReg:    1,
            PtoVta:     Number(ptoVta),
            CbteTipo:   Number(tipoComprobante),
            Concepto:   Number(concepto),
            DocTipo:    Number(docTipo),
            DocNro:     Number(docNro),
            CbteDesde:  nextNumber,
            CbteHasta:  nextNumber,
            CbteFch:    fecha,
            ImpTotal:   totalAmount,
            ImpTotConc: 0,
            ImpNeto:    impNeto,
            ImpOpEx:    0,
            ImpIVA:     impIVA,
            ImpTrib:    0,
            MonId:      'PES',
            MonCotiz:   1,
            CondicionIVAReceptorId: 1,
            ...(isMonotributo ? {} : {
                Iva: [{ Id: 5, BaseImp: impNeto, Importe: impIVA }],
            }),
        };

        // ── 4. Emitir la factura ─────────────────────────────
        console.log(`🚀 Solicitando CAE para Factura ${nextNumber}...`, payload);
        const result = await sdk.electronicBillingService.createInvoice(payload);

        console.log(`✅ CAE obtenido: ${result.CAE} — Vto: ${result.CAEFchVto}`);

        res.json({
            success:        true,
            cae:            result.CAE,
            caeFchVto:      result.CAEFchVto,
            nroComprobante: nextNumber,
        });

    } catch (err) {
        console.error('💥 ERROR ARCA SDK:', err?.message || err);
        res.status(500).json({ success: false, error: err?.message || 'Error desconocido' });
    }
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`));
