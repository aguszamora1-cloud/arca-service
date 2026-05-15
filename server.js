import express from 'express';
import { Arca, CbteTipo, CondicionIva } from '@ramiidv/arca-facturacion';
import { WsaaClient } from '@ramiidv/arca-common';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Monkey-patch: el signTRA original del SDK usa node-forge.pkcs7 que falla con
// "Only 8, 16, 24, or 32 bits supported: N" para certs de ARCA cuando intenta
// codificar enteros ASN.1 mayores a 32 bits. Reemplazamos por openssl CLI
// (mismo método que usan los ejemplos PHP oficiales de AFIP). Sincrónico para
// no romper la firma de performLogin que llama signTRA sin await.
WsaaClient.prototype.signTRA = function signTRAOpenssl(traXml) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsaa-'));
  try {
    const traPath = path.join(tmpDir, 'tra.xml');
    const certPath = path.join(tmpDir, 'cert.pem');
    const keyPath = path.join(tmpDir, 'key.pem');
    const cmsPath = path.join(tmpDir, 'tra.cms');

    fs.writeFileSync(traPath, traXml, { encoding: 'utf8', mode: 0o600 });
    fs.writeFileSync(certPath, this.cert, { encoding: 'utf8', mode: 0o600 });
    fs.writeFileSync(keyPath, this.key, { encoding: 'utf8', mode: 0o600 });

    // -binary: NO traducir LF<->CRLF en el contenido antes de firmar.
    //   Sin esto, openssl normaliza newlines y la firma se computa contra
    //   un contenido distinto al original, así ARCA rechaza con HTTP 500.
    // Capturamos stderr para que cualquier error futuro venga con detalle.
    try {
      execFileSync(
        'openssl',
        [
          'smime', '-sign',
          '-in', traPath,
          '-out', cmsPath,
          '-outform', 'DER',
          '-inkey', keyPath,
          '-signer', certPath,
          '-nodetach',
          '-nosmimecap',
          '-binary',
        ],
        { stdio: ['ignore', 'pipe', 'pipe'] }
      );
    } catch (e) {
      const stderr = e?.stderr ? Buffer.from(e.stderr).toString('utf8') : '';
      const stdout = e?.stdout ? Buffer.from(e.stdout).toString('utf8') : '';
      throw new Error(`openssl smime failed: ${e.message} | stderr: ${stderr.trim()} | stdout: ${stdout.trim()}`);
    }

    return fs.readFileSync(cmsPath).toString('base64');
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
};

const app = express();
app.use(express.json({ limit: '1mb' }));

// Auth middleware - verificar API key
const API_KEY = process.env.ARCA_API_KEY || 'default-key';
app.use((req, res, next) => {
  if (req.path === '/health') return next();
  const key = req.headers['x-api-key'];
  if (key !== API_KEY) return res.status(401).json({ ok: false, error: 'API key inválida' });
  next();
});

// Health check
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// Endpoint principal
app.post('/arca', async (req, res) => {
  try {
    const { action, cert, key, cuit, production, ...params } = req.body;

    if (!action || !cert || !key || !cuit) {
      return res.status(400).json({ ok: false, error: 'Faltan campos: action, cert, key, cuit' });
    }

    const arca = new Arca({
      cuit: Number(cuit),
      cert: cert.replace(/\\n/g, '\n'),
      key: key.replace(/\\n/g, '\n'),
      production: production === true || production === 'true',
    });

    let result;

    switch (action) {
      case 'facturar': {
        const { pto_vta, cbte_tipo, items, doc_tipo, doc_nro, condicion_iva, servicio, moneda, cotizacion } = params;
        
        const sdkItems = items.map(i => ({
          neto: Number(i.neto),
          ...(i.iva !== undefined && { iva: Number(i.iva) }),
          ...(i.exento && { exento: true }),
        }));

        const opts = {
          ptoVta: Number(pto_vta),
          cbteTipo: Number(cbte_tipo),
          items: sdkItems,
        };

        if (doc_tipo !== undefined) opts.docTipo = Number(doc_tipo);
        if (doc_nro !== undefined) opts.docNro = Number(doc_nro);
        if (moneda) opts.moneda = moneda;
        if (cotizacion) opts.cotizacion = Number(cotizacion);

        // condicionIva obligatorio desde abril 2026
        if (condicion_iva !== undefined) {
          opts.condicionIva = Number(condicion_iva);
        } else {
          const tipoA = [1, 2, 3];
          opts.condicionIva = tipoA.includes(Number(cbte_tipo))
            ? CondicionIva.RESPONSABLE_INSCRIPTO
            : CondicionIva.CONSUMIDOR_FINAL;
        }

        if (servicio) {
          opts.servicio = {
            desde: new Date(servicio.desde),
            hasta: new Date(servicio.hasta),
            vtoPago: new Date(servicio.vto_pago),
          };
        }

        result = await arca.facturar(opts);
        break;
      }

      case 'nota_credito': {
        const { pto_vta, items, doc_tipo, doc_nro, condicion_iva, comprobante_original } = params;
        
        const sdkItems = items.map(i => ({
          neto: Number(i.neto),
          ...(i.iva !== undefined && { iva: Number(i.iva) }),
          ...(i.exento && { exento: true }),
        }));

        const opts = {
          ptoVta: Number(pto_vta),
          comprobanteOriginal: {
            tipo: Number(comprobante_original.tipo),
            ptoVta: Number(comprobante_original.pto_vta),
            nro: Number(comprobante_original.nro),
          },
          items: sdkItems,
        };

        if (doc_tipo !== undefined) opts.docTipo = Number(doc_tipo);
        if (doc_nro !== undefined) opts.docNro = Number(doc_nro);
        if (condicion_iva !== undefined) {
          opts.condicionIva = Number(condicion_iva);
        } else {
          const tipoA = [1, 2, 3];
          opts.condicionIva = tipoA.includes(Number(comprobante_original.tipo))
            ? CondicionIva.RESPONSABLE_INSCRIPTO
            : CondicionIva.CONSUMIDOR_FINAL;
        }

        result = await arca.notaCredito(opts);
        break;
      }

      case 'nota_debito': {
        const { pto_vta, items, doc_tipo, doc_nro, condicion_iva, comprobante_original } = params;
        
        const sdkItems = items.map(i => ({
          neto: Number(i.neto),
          ...(i.iva !== undefined && { iva: Number(i.iva) }),
          ...(i.exento && { exento: true }),
        }));

        const opts = {
          ptoVta: Number(pto_vta),
          comprobanteOriginal: {
            tipo: Number(comprobante_original.tipo),
            ptoVta: Number(comprobante_original.pto_vta),
            nro: Number(comprobante_original.nro),
          },
          items: sdkItems,
        };

        if (doc_tipo !== undefined) opts.docTipo = Number(doc_tipo);
        if (doc_nro !== undefined) opts.docNro = Number(doc_nro);
        if (condicion_iva !== undefined) {
          opts.condicionIva = Number(condicion_iva);
        } else {
          const tipoA = [1, 2, 3];
          opts.condicionIva = tipoA.includes(Number(comprobante_original.tipo))
            ? CondicionIva.RESPONSABLE_INSCRIPTO
            : CondicionIva.CONSUMIDOR_FINAL;
        }

        result = await arca.notaDebito(opts);
        break;
      }

      case 'ultimo_comprobante': {
        const { pto_vta, cbte_tipo } = params;
        result = { ultimoComprobante: await arca.ultimoComprobante(Number(pto_vta), Number(cbte_tipo)) };
        break;
      }

      case 'consultar_comprobante': {
        const { cbte_tipo, pto_vta, cbte_nro } = params;
        result = await arca.consultarComprobante(Number(cbte_tipo), Number(pto_vta), Number(cbte_nro));
        break;
      }

      case 'consultar_cuit': {
        const { cuit: cuitConsulta } = params;
        result = await arca.consultarCuit(Number(cuitConsulta));
        break;
      }

      case 'server_status': {
        result = await arca.serverStatus();
        break;
      }

      case 'puntos_venta': {
        // Smoke test de credenciales: ejercita WSAA + WSFEv1 consultando el último
        // comprobante de un PV/tipo conocido. Si el cert/key están mal, falla acá.
        const ptoVta = Number(params.pto_vta || 1);
        const cbteTipo = Number(params.cbte_tipo || CbteTipo.FACTURA_B);
        const ultimo = await arca.ultimoComprobante(ptoVta, cbteTipo);
        result = {
          ok: true,
          pto_vta: ptoVta,
          cbte_tipo: cbteTipo,
          ultimo_comprobante: ultimo,
          msg: `WSAA + WSFE OK. Último comprobante PV ${ptoVta} tipo ${cbteTipo}: ${ultimo}`,
        };
        break;
      }

      default:
        return res.status(400).json({ ok: false, error: `Acción desconocida: ${action}` });
    }

    res.json({ ok: true, data: result });
  } catch (error) {
    console.error('ARCA Error:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
      tipo: error.constructor?.name || 'unknown',
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ARCA service running on port ${PORT}`));
