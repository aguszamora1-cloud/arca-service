console.log('VERSION: axios-v2-' + new Date().toISOString());
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const xml2js = require('xml2js');
const forge = require('node-forge');
const moment = require('moment');

const app = express();
app.use(process.env.NODE_ENV === 'production' ? cors() : cors({ origin: '*' }));
app.use(express.json());

const PORT = process.env.PORT || 3001;

// Configuración de URLs AFIP (Producción)
const URL_WSAA = 'https://wsaa.afip.gob.ar/ws/services/LoginCms';
const URL_WSFE = 'https://servicios1.afip.gob.ar/wsfev1/service.asmx';

// Parser de XML a JS
const xmlParser = new xml2js.Parser({ 
    explicitArray: false, 
    ignoreAttrs: true,
    tagNameProcessors: [xml2js.processors.stripPrefix] 
});

// Cache simple para evitar LoginCMS en cada request (AFIP tiene límites)
let authCache = {
    token: null,
    sign: null,
    expiration: null,
    cuit: null
};

function dateToUtcTime(date) {
    const pad = (n) => n.toString().padStart(2, '0');
    const yy = date.getUTCFullYear().toString().slice(2);
    const mm = pad(date.getUTCMonth() + 1);
    const dd = pad(date.getUTCDate());
    const hh = pad(date.getUTCHours());
    const mn = pad(date.getUTCMinutes());
    const ss = pad(date.getUTCSeconds());
    return `${yy}${mm}${dd}${hh}${mn}${ss}Z`;
}

function normalizePem(pem) {
    if (!pem) return '';
    const typeMatch = pem.match(/-----BEGIN ([^-]+)-----/);
    if (!typeMatch) return pem;
    const type = typeMatch[1];
    const content = pem
        .replace(/-----BEGIN [^-]+-----/, '')
        .replace(/-----END [^-]+-----/, '')
        .replace(/\\n/g, '')
        .replace(/\s/g, '');
    const wrapped = content.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${type}-----\n${wrapped}\n-----END ${type}-----\n`;
}

function createCMS(tra, certPem, keyPem) {
    const normalizedCert = normalizePem(certPem);
    const normalizedKey = normalizePem(keyPem);
    const cert = forge.pki.certificateFromPem(normalizedCert);
    const privateKey = forge.pki.privateKeyFromPem(normalizedKey);

    const md = forge.md.sha256.create();
    md.update(tra, 'utf8');
    const digest = md.digest().getBytes();

    const signingTime = new Date();
    const attrs = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.9.3').getBytes()),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.7.1').getBytes())
            ])
        ]),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.9.4').getBytes()),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, digest)
            ])
        ]),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('1.2.840.113549.1.9.5').getBytes()),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTCTIME, false, dateToUtcTime(signingTime))
            ])
        ])
    ]);

    const bytes = forge.asn1.toDer(attrs).getBytes();
    const signature = privateKey.sign(forge.md.sha256.create().update(bytes));

    const tbsCertificate = cert?.asn1?.children?.[0];
    const issuer = tbsCertificate.children.find(child => child.tagClass === forge.asn1.Class.UNIVERSAL && child.type === forge.asn1.Type.SEQUENCE);
    const serialNumber = tbsCertificate.children.find(child => child.tagClass === forge.asn1.Class.UNIVERSAL && child.type === forge.asn1.Type.INTEGER);

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
                            cert?.asn1?.children?.[0]?.children?.[3] || issuer,
                            cert?.asn1?.children?.[0]?.children?.[1] || serialNumber 
                        ]),
                        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes()),
                            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, '')
                        ]),
                        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, attrs.children || []),
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

    const wsaaBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsaa="http://wsaa.view.sua.dvadac.desein.afip.gov.ar">
  <soapenv:Header/>
  <soapenv:Body>
    <wsaa:loginCms>
      <wsaa:in0>${cms}</wsaa:in0>
    </wsaa:loginCms>
  </soapenv:Body>
</soapenv:Envelope>`;

    console.log('📡 Solicitando Token a WSAA (vía Axios)...');
    const response = await axios.post(URL_WSAA, wsaaBody, {
        headers: { 'Content-Type': 'text/xml;charset=UTF-8', 'SOAPAction': '""' },
        timeout: 30000
    });

    const parsed = await xmlParser.parseStringPromise(response.data);
    const loginReturn = parsed.Envelope.Body.loginCmsResponse.loginCmsReturn;
    
    const tokenMatch = loginReturn.match(/<token>([^<]+)<\/token>/);
    const signMatch = loginReturn.match(/<sign>([^<]+)<\/sign>/);
    const expirationMatch = loginReturn.match(/<expirationTime>([^<]+)<\/expirationTime>/);

    if (!tokenMatch || !signMatch || !expirationMatch) {
        throw new Error('Respuesta de WSAA malformada');
    }

    authCache = {
        token: tokenMatch[1],
        sign: signMatch[1],
        expiration: new Date(expirationMatch[1]),
        cuit: cuit
    };

    return authCache;
}

app.get('/', (req, res) => res.send('ARCA Axios-SOAP Service Online 🚀'));

app.post('/facturar', async (req, res) => {
    try {
        const { cuit, certificate, privateKey, tipoComprobante, ptoVta, concepto, docTipo, docNro, total } = req.body;

        if (!cuit || !certificate || !privateKey) {
            return res.status(400).json({ success: false, error: 'Credenciales incompletas' });
        }

        const auth = await getAuth(certificate, privateKey, cuit);

        // 1. FECompUltimoAutorizado
        const ultimoBody = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soap:Body>
    <ar:FECompUltimoAutorizado>
      <ar:Auth>
        <ar:Token>${auth.token}</ar:Token>
        <ar:Sign>${auth.sign}</ar:Sign>
        <ar:Cuit>${cuit}</ar:Cuit>
      </ar:Auth>
      <ar:PtoVta>${ptoVta}</ar:PtoVta>
      <ar:CbteTipo>${tipoComprobante}</ar:CbteTipo>
    </ar:FECompUltimoAutorizado>
  </soap:Body>
</soap:Envelope>`;

        console.log(`📡 Consultando último comprobante para PtoVta ${ptoVta}...`);
        const resUltimo = await axios.post(URL_WSFE, ultimoBody, {
            headers: { 'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': 'http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado' }
        });

        const parsedUltimo = await xmlParser.parseStringPromise(resUltimo.data);
        const resultUltimo = parsedUltimo.Envelope.Body.FECompUltimoAutorizadoResponse.FECompUltimoAutorizadoResult;
        
        if (resultUltimo.Errors) {
            throw new Error(resultUltimo.Errors.Err.Msg || 'Error al consultar último comprobante');
        }

        const nextVoucher = parseInt(resultUltimo.CbteNro) + 1;

        // 2. FECAESolicitar
        const totalAmount = parseFloat(total || 0);
        const isMonotributo = parseInt(tipoComprobante) === 11;
        const impNeto = isMonotributo ? totalAmount : parseFloat((totalAmount / 1.21).toFixed(2));
        const impIVA = isMonotributo ? 0 : parseFloat((totalAmount - impNeto).toFixed(2));
        const date = moment().format('YYYYMMDD');

        let ivaXml = '';
        if (!isMonotributo) {
            ivaXml = `<ar:Iva>
          <ar:AlicIva>
            <ar:Id>5</ar:Id>
            <ar:BaseImp>${impNeto}</ar:BaseImp>
            <ar:Importe>${impIVA}</ar:Importe>
          </ar:AlicIva>
        </ar:Iva>`;
        }

        const solicitarBody = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="http://ar.gov.afip.dif.FEV1/">
  <soap:Body>
    <ar:FECAESolicitar>
      <ar:Auth>
        <ar:Token>${auth.token}</ar:Token>
        <ar:Sign>${auth.sign}</ar:Sign>
        <ar:Cuit>${cuit}</ar:Cuit>
      </ar:Auth>
      <ar:FeCAEReq>
        <ar:FeCabReq>
          <ar:CantReg>1</ar:CantReg>
          <ar:PtoVta>${ptoVta}</ar:PtoVta>
          <ar:CbteTipo>${tipoComprobante}</ar:CbteTipo>
        </ar:FeCabReq>
        <ar:FeDetReq>
          <ar:FECAEDetRequest>
            <ar:Concepto>${concepto || 1}</ar:Concepto>
            <ar:DocTipo>${docTipo || 96}</ar:DocTipo>
            <ar:DocNro>${docNro || 0}</ar:DocNro>
            <ar:CbteDesde>${nextVoucher}</ar:CbteDesde>
            <ar:CbteHasta>${nextVoucher}</ar:CbteHasta>
            <ar:CbteFch>${date}</ar:CbteFch>
            <ar:ImpTotal>${totalAmount}</ar:ImpTotal>
            <ar:ImpTotConc>0</ar:ImpTotConc>
            <ar:ImpNeto>${impNeto}</ar:ImpNeto>
            <ar:ImpOpEx>0</ar:ImpOpEx>
            <ar:ImpIVA>${impIVA}</ar:ImpIVA>
            <ar:ImpTrib>0</ar:ImpTrib>
            <ar:MonId>PES</ar:MonId>
            <ar:MonCotiz>1</ar:MonCotiz>
            ${ivaXml}
          </ar:FECAEDetRequest>
        </ar:FeDetReq>
      </ar:FeCAEReq>
    </ar:FECAESolicitar>
  </soap:Body>
</soap:Envelope>`;

        console.log(`🚀 Solicitando CAE para Factura ${nextVoucher}...`);
        const resSolicitar = await axios.post(URL_WSFE, solicitarBody, {
            headers: { 'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': 'http://ar.gov.afip.dif.FEV1/FECAESolicitar' }
        });

        const parsedSolicitar = await xmlParser.parseStringPromise(resSolicitar.data);
        const resultSolicitar = parsedSolicitar.Envelope.Body.FECAESolicitarResponse.FECAESolicitarResult;

        if (resultSolicitar.Errors) {
            const msg = resultSolicitar.Errors.Err.Msg || 'Error de AFIP';
            throw new Error(msg);
        }

        const details = resultSolicitar.FeDetResp.FECAEDetResponse;
        if (details.Resultado === 'R') {
            const obs = details.Observaciones?.Obs?.Msg || 'Rechazo sin observaciones';
            throw new Error(`AFIP Rechazó: ${obs}`);
        }

        res.json({
            success: true,
            cae: details.CAE,
            caeFchVto: details.CAEFchVto,
            nroComprobante: nextVoucher
        });

    } catch (err) {
        console.error('💥 ERROR WSAA-AXIOS:', err.response?.data || err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`));
