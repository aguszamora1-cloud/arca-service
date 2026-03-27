/**
 * Microservicio de Facturacion Electronica AFIP (ARCA)
 * Basado en Express + @afipsdk/afip.js para maxima fiabilidad.
 */
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const Afip = require('@afipsdk/afip.js');

const app = express();
app.use(process.env.NODE_ENV === 'production' ? cors() : cors({ origin: '*' }));
app.use(express.json());

const PORT = process.env.PORT || 3001;
const TMP_DIR = '/tmp'; // Estándar para Serverless/Railway

app.get('/', (req, res) => res.send('ARCA Service Online 🚀'));

app.post('/facturar', async (req, res) => {
    try {
        const { 
            cuit, certificate, privateKey, production,
            tipoComprobante, ptoVta, concepto, 
            docTipo, docNro, total, payload, credentials 
        } = req.body;

        // Validacion basica
        if (!cuit || !certificate || !privateKey) {
            return res.status(400).json({ success: false, error: 'Credenciales incompletas en la peticion' });
        }

        // 1. Preparar rutas de archivos temporales para el SDK
        const timestamp = Date.now();
        const certPath = path.join(TMP_DIR, `cert_${timestamp}.crt`);
        const keyPath = path.join(TMP_DIR, `key_${timestamp}.key`);
        const resFolder = path.join(TMP_DIR, `afip_res_${timestamp}`);

        if (!fs.existsSync(resFolder)) fs.mkdirSync(resFolder, { recursive: true });

        // Escribir credenciales a disco (el SDK de Mauro Ordoñez las lee de archivos)
        fs.writeFileSync(certPath, certificate);
        fs.writeFileSync(keyPath, privateKey);

        // 2. Inicializar SDK
        const afip = new Afip({
            CUIT: parseInt(String(cuit).replace(/-/g, '')),
            cert: certPath,
            key: keyPath,
            production: production === true,
            res_folder: resFolder
        });

        console.log(`🚀 Iniciando solicitud para CUIT ${cuit} (PTO: ${ptoVta}, TIPO: ${tipoComprobante})`);

        // 3. Obtener ultimo numero autorizado
        const lastVoucher = await afip.ElectronicBilling.getLastVoucher(ptoVta, tipoComprobante);
        const nextVoucher = lastVoucher + 1;

        // 4. Preparar datos del voucher
        const totalAmount = parseFloat(total || 0);
        const isMonotributo = parseInt(tipoComprobante) === 11;
        const impNeto = isMonotributo ? totalAmount : parseFloat((totalAmount / 1.21).toFixed(2));
        const impIVA = isMonotributo ? 0 : parseFloat((totalAmount - impNeto).toFixed(2));

        const date = new Date().toISOString().split('T')[0].replace(/-/g, '');

        const voucherData = {
            'CantReg': 1,
            'PtoVta': ptoVta,
            'CbteTipo': tipoComprobante,
            'Concepto': concepto || 1,
            'DocTipo': docTipo || 96,
            'DocNro': docNro || 0,
            'CbteDesde': nextVoucher,
            'CbteHasta': nextVoucher,
            'CbteFch': date,
            'ImpTotal': totalAmount,
            'ImpTotConc': 0,
            'ImpNeto': impNeto,
            'ImpOpEx': 0,
            'ImpIVA': impIVA,
            'ImpTrib': 0,
            'MonId': 'PES',
            'MonCotiz': 1
        };

        // Si no es monotributista (Factura A o B), agregar detalles de IVA
        if (!isMonotributo) {
            voucherData['Iva'] = [{
                'Id': 5, // 21%
                'BaseImp': impNeto,
                'Importe': impIVA
            }];
        }

        // 5. Solicitar CAE
        const result = await afip.ElectronicBilling.createVoucher(voucherData);

        // Limpieza de archivos temporales
        try {
            fs.unlinkSync(certPath);
            fs.unlinkSync(keyPath);
        } catch (e) { console.warn('Error cleanup:', e); }

        console.log(`✅ EXITO: Factura ${nextVoucher} autorizada. CAE: ${result.CAE}`);

        res.json({
            success: true,
            cae: result.CAE,
            caeFchVto: result.CAEFchVto,
            nroComprobante: nextVoucher
        });

    } catch (error) {
        console.error('💥 Error ARCA SDK:', error.message);
        res.status(500).json({ 
            success: false, 
            error: error.message || 'Error desconocido procesando la factura' 
        });
    }
});

app.listen(PORT, () => console.log(`ARCA Microservice running on port ${PORT}`));
