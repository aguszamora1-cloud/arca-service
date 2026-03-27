const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const soap = require('soap');
const forge = require('node-forge');
const moment = require('moment');

const app = express();
app.use(process.env.NODE_ENV === 'production' ? cors() : cors({ origin: '*' }));
app.use(express.json());

const PORT = process.env.PORT || 3001;

// Configuración de URLs AFIP (Producción por defecto según solicitud)
const URL_WSAA = 'https://wsaa.afip.gob.ar/ws/services/LoginCms?wsdl';
const URL_WSFE = 'https://servicios1.afip.gob.ar/wsfev1/service.asmx?WSDL';

// Cache simple para evitar LoginCMS en cada request (AFIP tiene límites)
let authCache = {
    token: null,
    sign: null,
    expiration: null,
    cuit: null
};

/**
 * Genera el CMS (PKCS#7) firmado manualmente para evitar problemas de orden en AFIP.
 * Reemplaza a forge.pkcs7.createSignedData() según requerimiento.
 */
function createCMS(tra, certPem, keyPem) {
    const cert = forge.pki.certificateFromPem(certPem);
    const privateKey = forge.pki.privateKeyFromPem(keyPem);

    // 1. Digest del XML
    const md = forge.md.sha256.create();
    md.update(tra, 'utf8');
    const digest = md.digest().getBytes();

    // 2. Authenticated Attributes (ASN.1)
    // El orden de los OIDs es CRÍTICO para AFIP (Java backend)
    const signingTime = new Date();
    const attrs = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
        // Content Type
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.9.3').getBytes()),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.7.1').getBytes())
            ])
        ]),
        // Message Digest
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.9.4').getBytes()),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, digest)
            ])
        ]),
        // Signing Time
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.9.5').getBytes()),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTCTIME, false, forge.util.dateToUtcTime(signingTime))
            ])
        ])
    ]);

    // 3. Firmar Atributos
    const bytes = forge.asn1.toDer(attrs).getBytes();
    const signature = privateKey.sign(forge.md.sha256.create().update(bytes));

    // 4. Construir estructura Completa (ContentInfo -> SignedData)
    // Esta estructura sigue estrictamente el RFC 2315
    const pkcs7 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.7.2').getBytes()),
        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, forge.util.hexToBytes('01')),
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes()),
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')
                    ])
                ]),
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.7.1').getBytes())
                ]),
                forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                    forge.pki.certificateToAsn1(cert)
                ]),
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
                    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, forge.util.hexToBytes('01')),
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                            cert.asn1.children[0].children[3], // Issuer
                            cert.asn1.children[0].children[1]  // SerialNumber
                        ]),
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes()),
                            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')
                        ]),
                        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, attrs.children),
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.1.1').getBytes()),
                            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')
                        ]),
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, signature)
                    ])
                ])
            ])
        ])
    ]);

    return forge.util.encode64(forge.asn1.toDer(pkcs7).getBytes());
}

/**
 * Obtener Token y Sign de WSAA
 */
async function getAuth(certPem, keyPem, cuit) {
    if (authCache.token && authCache.sign && authCache.expiration > new Date() && authCache.cuit === cuit) {
        return authCache;
    }

    const genTime = moment().subtract(10, 'minutes');
    const expTime = moment().add(10, 'hours');
    const tra = `<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>${Math.floor(Date.now() / 1000)}</uniqueId>
    <generationTime>${genTime.format('YYYY-MM-DDTHH:mm:ssZ')}</generationTime>
    <expirationTime>${expTime.format('YYYY-MM-DDTHH:mm:ssZ')}</expirationTime>
  </header>
  <service>wsfe</service>
</loginTicketRequest>`;

    const cms = createCMS(tra, certPem, keyPem);
    const client = await soap.createClientAsync(URL_WSAA);
    const [result] = await client.loginCmsAsync({ in0: cms });

    const loginTicketResponse = result.loginCmsReturn;
    const token = loginTicketResponse.match(/<token>([^<]+)<\/token>/)[1];
    const sign = loginTicketResponse.match(/<sign>([^<]+)<\/sign>/)[1];
    const expiration = loginTicketResponse.match(/<expirationTime>([^<]+)<\/expirationTime>/)[1];

    authCache = {
        token,
        sign,
        expiration: new Date(expiration),
        cuit
    };

    return authCache;
}

app.get('/', (req, res) => res.send('ARCA Stable-SOAP Service Online 🚀'));

app.post('/facturar', async (req, res) => {
    try {
        const { cuit, certificate, privateKey, tipoComprobante, ptoVta, concepto, docTipo, docNro, total } = req.body;

        if (!cuit || !certificate || !privateKey) {
            return res.status(400).json({ success: false, error: 'Credenciales incompletas (requiere cuit, certificate y privateKey)' });
        }

        // 1. Obtener Autenticación
        console.log(`📡 Solicitando acceso a WSAA para CUIT: ${cuit}`);
        const auth = await getAuth(certificate, privateKey, cuit);

        // 2. Conectar a WSFE
        const client = await soap.createClientAsync(URL_WSFE);

        // 3. Consultar Último Comprobante
        const feCompUltimoAutorizadoRequest = {
            Auth: {
                Token: auth.token,
                Sign: auth.sign,
                Cuit: cuit
            },
            PtoVta: ptoVta,
            CbteTipo: tipoComprobante
        };

        const [ultimoResult] = await client.FECompUltimoAutorizadoAsync(feCompUltimoAutorizadoRequest);
        const lastVoucher = ultimoResult.FECompUltimoAutorizadoResult.CbteNro;
        const nextVoucher = lastVoucher + 1;

        // 4. Calcular importes
        const totalAmount = parseFloat(total || 0);
        const isMonotributo = parseInt(tipoComprobante) === 11;
        const impNeto = isMonotributo ? totalAmount : parseFloat((totalAmount / 1.21).toFixed(2));
        const impIVA = isMonotributo ? 0 : parseFloat((totalAmount - impNeto).toFixed(2));
        const date = moment().format('YYYYMMDD');

        // 5. Preparar Voucher para Solicitud
        const request = {
            Auth: {
                Token: auth.token,
                Sign: auth.sign,
                Cuit: cuit
            },
            FeCAEReq: {
                FeCabReq: {
                    CantReg: 1,
                    PtoVta: ptoVta,
                    CbteTipo: tipoComprobante
                },
                FeDetReq: {
                    FECAEDetRequest: {
                        Concepto: concepto || 1,
                        DocTipo: docTipo || 96,
                        DocNro: docNro || 0,
                        CbteDesde: nextVoucher,
                        CbteHasta: nextVoucher,
                        CbteFch: date,
                        ImpTotal: totalAmount,
                        ImpTotConc: 0,
                        ImpNeto: impNeto,
                        ImpOpEx: 0,
                        ImpIVA: impIVA,
                        ImpTrib: 0,
                        MonId: 'PES',
                        MonCotiz: 1
                    }
                }
            }
        };

        if (!isMonotributo) {
            request.FeCAEReq.FeDetReq.FECAEDetRequest.Iva = {
                AlicIva: [{
                    Id: 5, // 21%
                    BaseImp: impNeto,
                    Importe: impIVA
                }]
            };
        }

        // 6. Enviar a AFIP
        console.log(`🚀 Solicitando CAE para Factura ${nextVoucher}...`);
        const [result] = await client.FECAESolicitarAsync(request);
        const data = result.FECAESolicitarResult;

        if (data.Errors) {
            const errorMsg = Array.isArray(data.Errors.Err) ? data.Errors.Err[0].Msg : data.Errors.Err.Msg;
            throw new Error(errorMsg);
        }

        const details = data.FeDetResp.FECAEDetResponse[0] || data.FeDetResp.FECAEDetResponse;

        if (details.Resultado === 'R') {
            const obsMsg = details.Observaciones.Obs[0]?.Msg || details.Observaciones.Obs.Msg;
            throw new Error(`Rechazado por AFIP: ${obsMsg}`);
        }

        console.log(`✅ EXITO: Comprobante ${nextVoucher} autorizado. CAE: ${details.CAE}`);

        res.json({
            success: true,
            cae: details.CAE,
            caeFchVto: details.CAEFchVto,
            nroComprobante: nextVoucher
        });

    } catch (err) {
        console.error('💥 ERROR ESTABLE-SOAP:', err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ARCA Stable-SOAP Microservice running on port ${PORT}`);
});
