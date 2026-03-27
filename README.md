# ARCA Microservice (AFIP) 🚀 [BUILD_TRIGGER_2024_03_27_15_03]

Servicio independiente para procesar facturación electrónica de AFIP (Argentina) utilizando el SDK oficial `@afipsdk/afip.js`. Este servicio resuelve los problemas de firma CMS y cifrado XML presentes en entornos Serverless como Deno/Supabase Edge Functions.

## Requerimientos
- Node.js 18+
- Un certificado (`.crt`) y clave privada (`.key`) registrados en AFIP.

## Endpoints

### `POST /facturar`
Toda la lógica de WSAA (autenticación) y WSFE (factura) en una sola llamada.

**Request Body:**
```json
{
  "cuit": "20XXXXXXXX3",
  "certificate": "---BEGIN CERTIFICATE---\n...",
  "privateKey": "---BEGIN PRIVATE KEY---\n...",
  "production": false,
  "tipoComprobante": 11,
  "ptoVta": 1,
  "total": 1500.50,
  "docTipo": 99,
  "docNro": 0
}
```

**Response:**
```json
{
  "success": true,
  "cae": "12345678901234",
  "caeFchVto": "20240327",
  "nroComprobante": 123
}
```

## Despliegue en Railway

1. Instalar Railway CLI: `npm i -g @railway/cli`
2. Login: `railway login`
3. Inicializar: `railway init`
4. Subir: `railway up`

Una vez deployado, obtené la URL de Railway (ej: `https://arca-service.up.railway.app`) y configurala como variable de entorno `ARCA_SERVICE_URL` en Supabase.
