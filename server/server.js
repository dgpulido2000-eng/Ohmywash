import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID, createHmac, createHash, timingSafeEqual } from 'node:crypto';
import pkg from 'square';
const { Client, Environment } = pkg;

const app = express();

// Necesario en Render (detrás de proxy) para que req.protocol devuelva
// "https" correctamente al armar los links de aprobación del correo.
app.set('trust proxy', true);

// cors() sin opciones responde con "Access-Control-Allow-Origin: *",
// lo que también satisface peticiones fetch() hechas desde un archivo
// abierto como file:// (origen "null" en el navegador).
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Por defecto usa producción (dinero real). Para volver a pruebas sin tocar
// código, pon SQUARE_ENVIRONMENT=sandbox en las variables de entorno de Render
// (y usa credenciales de sandbox en SQUARE_ACCESS_TOKEN, etc.).
const squareEnvironment = process.env.SQUARE_ENVIRONMENT === 'sandbox' ? Environment.Sandbox : Environment.Production;

const squareClient = new Client({
  accessToken: process.env.SQUARE_ACCESS_TOKEN,
  environment: squareEnvironment,
});

// --- Correo de aprobación manual de citas ---
// Las citas creadas por la API con el token del negocio quedan ACCEPTED
// automáticamente en Square (Square no permite forzar otro status al
// crearlas así) — por eso, en vez de crear la cita al instante, se manda
// este correo con botones de Aceptar/Rechazar, y la cita real en Square
// solo se crea cuando el dueño la acepta.
//
// El correo se manda por la API HTTP de Resend (no por SMTP): el plan
// gratuito de Render bloquea las conexiones SMTP salientes (a Gmail o a
// cualquier otro), así que un envío por SMTP se queda colgado para
// siempre sin avisar del error. La API de Resend usa HTTPS normal, que sí
// funciona en Render.
const APPROVAL_SECRET = process.env.APPROVAL_SECRET;
const BOOKING_REQUEST_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 días

// Firma sin estado (sin base de datos): el token trae los datos de la
// reserva codificados + una firma HMAC, así que el link del correo por sí
// solo es suficiente para crear la cita al aprobarla, sin depender de que
// el servidor siga "recordando" la solicitud (Render puede reiniciarse).
function signBookingToken(payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = createHmac('sha256', APPROVAL_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyBookingToken(token, kind = 'request') {
  if (!APPROVAL_SECRET || !token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expectedSig = createHmac('sha256', APPROVAL_SECRET).update(body).digest('base64url');
  const sigBuf = Buffer.from(sig || '', 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    if ((payload.kind ?? 'request') !== kind) return null;
    return payload;
  } catch {
    return null;
  }
}

// Los datos del cliente (nombre, teléfono, dirección...) vienen del
// formulario público y se insertan en HTML (correo y páginas de
// aprobación) — hay que escaparlos para que un nombre con "<script>" no
// se ejecute en el navegador del dueño.
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// lang: 'es' para las páginas del dueño, 'en' para las que ve el cliente.
function approvalHtmlPage(title, message, extraHtml = '', lang = 'es') {
  return `<!DOCTYPE html><html lang="${lang}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title}</title>
<style>
  body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#f4fafb;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:24px;box-sizing:border-box;}
  .card{max-width:420px;background:#fff;border-radius:20px;padding:36px 30px;box-shadow:0 20px 50px rgba(20,50,55,.12);text-align:center;}
  h1{font-size:1.3rem;margin:0 0 12px;color:#12191a;}
  p{color:#5c6b6e;line-height:1.6;margin:0;}
  .btn{display:inline-block;margin-top:22px;padding:14px 26px;border-radius:100px;border:none;background:#e2574c;color:#fff;font-weight:bold;font-size:1rem;cursor:pointer;text-decoration:none;}
  .btn-secondary{background:#2ec4b6;}
</style></head><body><div class="card"><h1>${title}</h1><p>${message}</p>${extraHtml}</div></body></html>`;
}

function formatApptDate(startAt) {
  return new Date(startAt).toLocaleString('es-US', {
    timeZone: 'America/New_York', weekday: 'long', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit',
  });
}

// Versión en inglés para todo lo que ve el cliente (correos y páginas).
function formatApptDateEn(startAt) {
  return new Date(startAt).toLocaleString('en-US', {
    timeZone: 'America/New_York', weekday: 'long', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit',
  });
}

// Clave de idempotencia para Resend: si el mismo correo se intenta mandar
// dos veces (doble clic en Aceptar, el navegador reintentando mientras
// Render "despierta", o el escáner de links del correo abriendo el enlace),
// Resend solo lo entrega una vez. Las claves duran 24 horas en Resend.
function emailKey(kind, seed) {
  return `${kind}:${createHash('sha256').update(String(seed)).digest('hex').slice(0, 40)}`;
}

// Resend responde 409 cuando la clave ya se usó (correo ya enviado o en
// proceso) — eso cuenta como enviado, no como error.
const resendAccepted = (resp) => resp.ok || resp.status === 409;

async function sendApprovalEmail(req, payload, token, idempotencyKey = emailKey('approval', token)) {
  if (!process.env.RESEND_API_KEY || !process.env.NOTIFY_EMAIL) {
    throw new Error('El correo de aprobación no está configurado (faltan RESEND_API_KEY / NOTIFY_EMAIL en el servidor).');
  }
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const approveUrl = `${baseUrl}/approve-booking?token=${encodeURIComponent(token)}`;
  const declineUrl = `${baseUrl}/decline-booking?token=${encodeURIComponent(token)}`;
  const addressStr = payload.address
    ? [payload.address.addressLine1, payload.address.locality, payload.address.administrativeDistrictLevel1, payload.address.postalCode].filter(Boolean).join(', ')
    : 'No especificada';

  const emailResp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
      'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify({
      // "onboarding@resend.dev" funciona sin verificar un dominio propio,
      // pero solo puede mandar al correo con el que se creó la cuenta de
      // Resend — por eso NOTIFY_EMAIL debe ser esa misma cuenta.
      from: process.env.NOTIFY_FROM || 'Oh My Wash <onboarding@resend.dev>',
      to: [process.env.NOTIFY_EMAIL],
      subject: `Nueva solicitud de cita — ${payload.customerName}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
          <h2 style="color:#0f6a62;">Nueva solicitud de cita</h2>
          <p><strong>Cliente:</strong> ${escapeHtml(payload.customerName)}</p>
          <p><strong>Teléfono:</strong> ${escapeHtml(payload.customerPhone) || '—'}</p>
          <p><strong>Correo:</strong> ${escapeHtml(payload.customerEmail) || '—'}</p>
          <p><strong>Dirección:</strong> ${escapeHtml(addressStr)}</p>
          <p><strong>Servicio(s):</strong> ${escapeHtml(payload.serviceSummary) || '—'}</p>
          <p><strong>Técnico:</strong> ${escapeHtml(payload.staffName) || '—'}</p>
          <p><strong>Depósito pagado (20%):</strong> ${payload.depositPaid != null ? '$' + Number(payload.depositPaid).toFixed(2) : '—'}</p>
          <p><strong>Saldo a cobrar en sitio:</strong> ${payload.balanceDue != null ? '$' + Number(payload.balanceDue).toFixed(2) : '—'}</p>
          <p><strong>Fecha y hora:</strong> ${formatApptDate(payload.startAt)}</p>
          <div style="margin-top:24px;">
            <a href="${approveUrl}" style="display:inline-block;background:#2ec4b6;color:#fff;padding:14px 26px;border-radius:100px;text-decoration:none;font-weight:bold;margin-right:12px;">✅ Aceptar cita</a>
            <a href="${declineUrl}" style="display:inline-block;background:#e2574c;color:#fff;padding:14px 26px;border-radius:100px;text-decoration:none;font-weight:bold;">❌ Rechazar</a>
          </div>
          <p style="margin-top:20px;color:#8b9a9c;font-size:.8rem;">Este enlace vence en 7 días.</p>
        </div>
      `,
    }),
  });

  if (!resendAccepted(emailResp)) {
    const errText = await emailResp.text().catch(() => '');
    throw new Error(`No se pudo enviar el correo de aprobación (Resend respondió ${emailResp.status}): ${errText}`);
  }
}

function bigIntSafe(value) {
  return typeof value === 'bigint' ? Number(value) : value;
}

// Convierte recursivamente cualquier BigInt dentro de un objeto/array a Number,
// para que se pueda mandar con res.json() sin que truene la serialización.
function deepBigIntToNumber(value) {
  if (typeof value === 'bigint') return Number(value);
  if (Array.isArray(value)) return value.map(deepBigIntToNumber);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) out[key] = deepBigIntToNumber(value[key]);
    return out;
  }
  return value;
}

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'oh-my-wash-server' });
});

// Diagnóstico de solo lectura: confirma si las variables de entorno del
// correo de aprobación quedaron configuradas en Render, sin exponer sus
// valores (solo true/false).
app.get('/debug/approval-config', (req, res) => {
  res.json({
    resendApiKeySet: !!process.env.RESEND_API_KEY,
    notifyEmailSet: !!process.env.NOTIFY_EMAIL,
    approvalSecretSet: !!process.env.APPROVAL_SECRET,
  });
});

app.post('/create-payment', async (req, res) => {
  const { sourceId, amount } = req.body || {};

  if (!sourceId || !amount) {
    return res.status(400).json({ success: false, error: 'sourceId y amount (en centavos) son requeridos' });
  }

  try {
    const response = await squareClient.paymentsApi.createPayment({
      sourceId,
      idempotencyKey: randomUUID(),
      amountMoney: {
        amount: BigInt(amount),
        currency: 'USD',
      },
      locationId: process.env.SQUARE_LOCATION_ID,
    });

    const payment = response.result?.payment ?? response.payment ?? response;

    res.json({
      success: true,
      paymentId: payment.id,
      status: payment.status,
      amount: bigIntSafe(payment.amountMoney?.amount),
      currency: payment.amountMoney?.currency,
      receiptUrl: payment.receiptUrl ?? null,
    });
  } catch (err) {
    console.error('Error creando el pago:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido al procesar el pago';
    res.status(500).json({ success: false, error: detail });
  }
});

// --- Reservas (Bookings API) ---

// Lista los servicios reservables tal como están configurados en Square
// (Items & services -> tipo Appointment), para que el frontend no tenga
// que tener los IDs de Square hardcodeados.
app.get('/services', async (req, res) => {
  try {
    const response = await squareClient.catalogApi.listCatalog(undefined, 'ITEM');
    const objects = response.result?.objects ?? response.objects ?? [];

    const services = [];
    for (const obj of objects) {
      const itemData = obj.itemData;
      if (!itemData || itemData.productType !== 'APPOINTMENTS_SERVICE') continue;
      for (const variation of itemData.variations || []) {
        const v = variation.itemVariationData;
        if (!v?.availableForBooking) continue;
        // La duración es obligatoria: Square la necesita para reservar el espacio
        // en el calendario. El precio es opcional (puede ser variable/a cotizar).
        if (!v.serviceDuration) continue;
        services.push({
          serviceName: itemData.name,
          variationName: v.name,
          serviceVariationId: variation.id,
          serviceVariationVersion: bigIntSafe(variation.version),
          price: v.priceMoney ? bigIntSafe(v.priceMoney.amount) / 100 : null,
          durationMinutes: Math.round(bigIntSafe(v.serviceDuration) / 60000),
          teamMemberIds: v.teamMemberIds || [],
        });
      }
    }

    res.json({ success: true, services });
  } catch (err) {
    console.error('Error listando servicios:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).json({ success: false, error: detail });
  }
});

// Diagnóstico de solo lectura para depurar por qué un técnico específico no
// tiene horarios en cierta fecha. Devuelve solo metadatos de la reserva
// (fecha/hora, estado, técnico, servicio) — nunca nombre, correo, teléfono
// ni customerId del cliente.
app.get('/debug/bookings', async (req, res) => {
  const { teamMemberId, startAt, endAt } = req.query;
  if (!startAt || !endAt) {
    return res.status(400).json({ success: false, error: 'startAt y endAt son requeridos (query params)' });
  }
  try {
    const response = await squareClient.bookingsApi.listBookings(
      undefined, undefined, undefined, teamMemberId || undefined,
      process.env.SQUARE_LOCATION_ID, startAt, endAt,
    );
    const bookings = response.result?.bookings ?? response.bookings ?? [];
    const sanitized = bookings.map(b => ({
      id: b.id,
      status: b.status,
      startAt: b.startAt,
      segments: (b.appointmentSegments || []).map(s => ({
        teamMemberId: s.teamMemberId,
        serviceVariationId: s.serviceVariationId,
        durationMinutes: s.durationMinutes,
      })),
    }));
    res.json({ success: true, bookings: deepBigIntToNumber(sanitized) });
  } catch (err) {
    console.error('Error listando reservas (debug):', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).json({ success: false, error: detail });
  }
});

// Diagnóstico de solo lectura (sin datos de clientes) para depurar problemas
// de disponibilidad: perfil de horario del negocio y de cada miembro del equipo.
app.get('/debug/booking-setup', async (req, res) => {
  try {
    const [businessResp, teamResp, locationResp] = await Promise.all([
      squareClient.bookingsApi.retrieveBusinessBookingProfile(),
      squareClient.bookingsApi.listTeamMemberBookingProfiles(true),
      squareClient.locationsApi.retrieveLocation(process.env.SQUARE_LOCATION_ID),
    ]);

    const business = businessResp.result?.businessBookingProfile ?? businessResp.businessBookingProfile;
    const teamProfiles = teamResp.result?.teamMemberBookingProfiles ?? teamResp.teamMemberBookingProfiles ?? [];
    const location = locationResp.result?.location ?? locationResp.location;

    res.json({
      success: true,
      businessBookingProfile: deepBigIntToNumber(business),
      teamMemberBookingProfiles: deepBigIntToNumber(teamProfiles),
      locationBusinessHours: deepBigIntToNumber(location?.businessHours) ?? null,
      locationTimezone: location?.timezone ?? null,
    });
  } catch (err) {
    console.error('Error en diagnóstico de reservas:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).json({ success: false, error: detail });
  }
});

// Busca horarios disponibles para uno o varios servicios (una sola visita) en un rango de fechas.
app.post('/availability', async (req, res) => {
  const { serviceVariationId, serviceVariationIds, teamMemberId, startAt, endAt } = req.body || {};

  const ids = serviceVariationIds && serviceVariationIds.length ? serviceVariationIds : (serviceVariationId ? [serviceVariationId] : []);

  if (!ids.length || !startAt || !endAt) {
    return res.status(400).json({ success: false, error: 'serviceVariationIds, startAt y endAt son requeridos' });
  }

  try {
    const segmentFilters = ids.map(id => {
      const filter = { serviceVariationId: id };
      if (teamMemberId) filter.teamMemberIdFilter = { any: [teamMemberId] };
      return filter;
    });

    const response = await squareClient.bookingsApi.searchAvailability({
      query: {
        filter: {
          startAtRange: { startAt, endAt },
          locationId: process.env.SQUARE_LOCATION_ID,
          segmentFilters,
        },
      },
    });

    const availabilities = response.result?.availabilities ?? response.availabilities ?? [];
    res.json({ success: true, availabilities: deepBigIntToNumber(availabilities) });
  } catch (err) {
    console.error('Error buscando disponibilidad:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).json({ success: false, error: detail });
  }
});

// Crea el cliente en Square si no existe (la cita en sí NO se crea aquí —
// se manda a aprobación manual por correo, ver sendApprovalEmail más abajo).
// Acepta "segments" (varios servicios en una sola visita) o los campos sueltos de un solo servicio, por compatibilidad.
app.post('/create-booking', async (req, res) => {
  const {
    segments,
    serviceVariationId,
    serviceVariationVersion,
    teamMemberId,
    durationMinutes,
    startAt,
    customerName,
    customerEmail,
    customerPhone,
    addressLine1,
    locality,
    administrativeDistrictLevel1,
    postalCode,
    serviceSummary,
    staffName,
    depositPaid,
    balanceDue,
    paymentId,
    termsAccepted,
    marketingOptIn,
  } = req.body || {};

  // Square solo acepta estos sub-campos en address (ni booking.address ni
  // customer.address admiten "country" como en otras APIs de Square).
  const address = addressLine1
    ? { addressLine1, locality, administrativeDistrictLevel1, postalCode }
    : undefined;

  const segmentList = segments && segments.length
    ? segments
    : (serviceVariationId ? [{ serviceVariationId, serviceVariationVersion, teamMemberId, durationMinutes }] : []);

  if (!segmentList.length || !startAt || !customerName) {
    return res.status(400).json({ success: false, error: 'Faltan datos requeridos para la reserva' });
  }
  if (termsAccepted !== true) {
    return res.status(400).json({ success: false, error: 'Debes aceptar los términos de servicio y la política de privacidad' });
  }
  if (segmentList.some(s => !s.serviceVariationId || !s.teamMemberId)) {
    return res.status(400).json({ success: false, error: 'Cada servicio de la reserva necesita serviceVariationId y teamMemberId' });
  }

  try {
    let customerId;

    if (customerEmail) {
      const searchResp = await squareClient.customersApi.searchCustomers({
        query: { filter: { emailAddress: { exact: customerEmail } } },
      });
      customerId = (searchResp.result?.customers ?? searchResp.customers ?? [])[0]?.id;

      // Si ya existía un cliente con ese correo (de una reserva anterior),
      // se actualiza con el nombre/teléfono/dirección que se acaba de
      // escribir en el formulario — si no, la reserva quedaba a nombre de
      // quien reservó la primera vez con ese correo, sin importar el nombre
      // que se pusiera esta vez.
      if (customerId) {
        await squareClient.customersApi.updateCustomer(customerId, {
          givenName: customerName,
          phoneNumber: customerPhone || undefined,
          address,
          ...(marketingOptIn === true ? { preferences: { emailUnsubscribed: false } } : {}),
        });
      }
    }

    if (!customerId) {
      const createResp = await squareClient.customersApi.createCustomer({
        givenName: customerName,
        emailAddress: customerEmail || undefined,
        phoneNumber: customerPhone || undefined,
        address,
        preferences: { emailUnsubscribed: marketingOptIn !== true },
        note: `Aceptó términos y política de privacidad el ${new Date().toISOString().slice(0, 10)}`,
      });
      customerId = (createResp.result?.customer ?? createResp.customer)?.id;
    }

    // La cita NO se crea en Square todavía — solo se firma un token con
    // todos los datos y se manda por correo con Aceptar/Rechazar. Square
    // solo se entera (y le manda confirmación al cliente) cuando el equipo
    // acepta — así nadie recibe un "confirmado" de algo que puede rechazarse.
    const pendingPayload = {
      segments: segmentList.map(s => ({
        serviceVariationId: s.serviceVariationId,
        serviceVariationVersion: s.serviceVariationVersion,
        teamMemberId: s.teamMemberId,
        durationMinutes: s.durationMinutes,
      })),
      startAt,
      customerId,
      customerName,
      customerEmail: customerEmail || null,
      customerPhone: customerPhone || null,
      address: address || null,
      serviceSummary: serviceSummary || null,
      staffName: staffName || null,
      depositPaid: depositPaid ?? null,
      balanceDue: balanceDue ?? null,
      paymentId: paymentId || null,
      kind: 'request',
      exp: Date.now() + BOOKING_REQUEST_TTL_MS,
    };

    const token = signBookingToken(pendingPayload);
    // Un mismo pago solo puede generar una solicitud para ese horario.
    await sendApprovalEmail(req, pendingPayload, token, paymentId ? emailKey('approval-checkout', `${paymentId}|${startAt}`) : undefined);

    res.json({ success: true, pending: true });
  } catch (err) {
    console.error('Error creando la solicitud de cita:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).json({ success: false, error: detail });
  }
});

const DEPOSIT_REFUND_MIN_HOURS = 24;
const TOKEN_LONG_TTL_MS = 365 * 24 * 60 * 60 * 1000;

function depositCentsOf(payload) {
  return Math.round(Number(payload.depositPaid || 0) * 100);
}

function idempotencyFrom(seed) {
  return createHash('sha256').update(seed).digest('hex').slice(0, 45);
}

async function refundDeposit(paymentId, amountCents, reason, seed) {
  await squareClient.refundsApi.refundPayment({
    idempotencyKey: idempotencyFrom(seed),
    paymentId,
    amountMoney: { amount: BigInt(amountCents), currency: 'USD' },
    reason,
  });
}

async function sendEmail(to, subject, html, idempotencyKey) {
  if (!process.env.RESEND_API_KEY || !to) return false;
  const headers = { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' };
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      from: process.env.NOTIFY_FROM || 'Oh My Wash <onboarding@resend.dev>',
      to: [to],
      subject,
      html,
    }),
  });
  return resendAccepted(resp);
}

async function sendOwnerEmail(subject, html, idempotencyKey) {
  await sendEmail(process.env.NOTIFY_EMAIL, subject, html, idempotencyKey);
}

// Solo funciona de verdad una vez que se verifique un dominio propio en
// Resend — con el remitente genérico "onboarding@resend.dev" (sin dominio
// verificado) Resend solo entrega al correo dueño de la cuenta, así que
// esto fallará en silencio (devuelve false) hasta entonces. Por eso el
// correo al dueño SIEMPRE incluye los mismos links, como respaldo manual.
async function sendCustomerEmail(to, subject, html, idempotencyKey) {
  return sendEmail(to, subject, html, idempotencyKey);
}

// Mismo horario de técnicos que usa checkout.html (STAFF_SCHEDULE) — debe
// mantenerse igual en los dos archivos. Se usa para proponerle al cliente
// horarios alternativos cuando se rechaza su solicitud.
const STAFF_SCHEDULE = {
  'TMqtFAlpFqDV-l_j': { name: 'JP', days: [0, 1, 2, 3, 4, 5, 6], startMin: 9 * 60, endMin: 17 * 60 },
  'TMP0GRLy0FkLW_bt': { name: 'Jose Castro', days: [6], startMin: 9 * 60, endMin: 17 * 60 },
  'TMhQVvzCRfnsr5Bf': { name: 'Miguel Alvarado', days: [5], startMin: 9 * 60, endMin: 14 * 60 },
};

function nyMinutesOfDay(date) {
  const fmt = new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', hour: '2-digit', minute: '2-digit', hour12: false });
  const parts = fmt.formatToParts(date);
  const h = parseInt(parts.find(p => p.type === 'hour').value, 10) % 24;
  const m = parseInt(parts.find(p => p.type === 'minute').value, 10);
  return h * 60 + m;
}

function nyDateKey(iso) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/New_York', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(iso));
}

// Busca hasta `limit` horarios alternativos, en cualquiera de los 3
// técnicos, para los mismos servicios de una solicitud rechazada — se
// usan para ofrecérselos al cliente y que pueda reagendar sin tener que
// volver a buscar nada ni pagar el depósito otra vez.
async function findAlternativeSlots(serviceVariationIds, totalDurationMin, excludeStartAt, limit) {
  const start = new Date(Date.now() + 60 * 60 * 1000); // desde dentro de 1 hora
  const end = new Date(start.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 días

  const perStaff = await Promise.all(Object.entries(STAFF_SCHEDULE).map(async ([staffId, cfg]) => {
    try {
      const segmentFilters = serviceVariationIds.map(id => ({ serviceVariationId: id, teamMemberIdFilter: { any: [staffId] } }));
      const response = await squareClient.bookingsApi.searchAvailability({
        query: { filter: { startAtRange: { startAt: start.toISOString(), endAt: end.toISOString() }, locationId: process.env.SQUARE_LOCATION_ID, segmentFilters } },
      });
      const availabilities = response.result?.availabilities ?? response.availabilities ?? [];
      return availabilities
        .filter(a => a.startAt !== excludeStartAt)
        .filter(a => nyMinutesOfDay(new Date(new Date(a.startAt).getTime() + totalDurationMin * 60000)) <= cfg.endMin)
        .filter(a => cfg.days.includes(new Date(nyDateKey(a.startAt) + 'T12:00:00').getDay()))
        .map(a => ({ startAt: a.startAt, staffId }));
    } catch (err) {
      console.error(`Error buscando horarios alternativos para ${staffId}:`, err);
      return [];
    }
  }));

  const seen = new Set();
  const all = perStaff.flat().sort((a, b) => new Date(a.startAt) - new Date(b.startAt));
  const picked = [];
  for (const slot of all) {
    if (seen.has(slot.startAt)) continue;
    seen.add(slot.startAt);
    picked.push(slot);
    if (picked.length >= limit) break;
  }
  return picked;
}

// El dueño hace clic en este link desde el correo para aceptar la cita —
// aquí sí se crea la cita real en Square. idempotencyKey se deriva del
// token para que hacer clic dos veces (o recargar la página) no cree dos
// citas duplicadas.
app.get('/approve-booking', async (req, res) => {
  const payload = verifyBookingToken(req.query.token, 'request');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Enlace inválido o vencido', 'Este enlace de aprobación ya no es válido (venció a los 7 días, o el token está mal formado).'));
  }

  try {
    // La cita se crea en Square justo aquí, al aceptar — es el único
    // momento en que el horario queda bloqueado y el cliente recibe la
    // confirmación automática de Square.
    let bookingId = payload.bookingId;
    if (!bookingId) {
      const bookingResp = await squareClient.bookingsApi.createBooking({
        idempotencyKey: idempotencyFrom(String(req.query.token)),
        booking: {
          locationId: process.env.SQUARE_LOCATION_ID,
          startAt: payload.startAt,
          customerId: payload.customerId,
          locationType: payload.address ? 'CUSTOMER_LOCATION' : undefined,
          address: payload.address || undefined,
          appointmentSegments: payload.segments.map(s => ({
            teamMemberId: s.teamMemberId,
            serviceVariationId: s.serviceVariationId,
            serviceVariationVersion: s.serviceVariationVersion != null ? BigInt(s.serviceVariationVersion) : undefined,
            durationMinutes: s.durationMinutes,
          })),
        },
      });
      bookingId = (bookingResp.result?.booking ?? bookingResp.booking).id;
    }

    // Si este depósito ya se había reembolsado (ej. el cliente pidió el
    // reembolso después de pedir que lo reagendaran, o al revés), hay que
    // avisarlo aquí — es el último momento antes de confirmar la cita sin
    // depósito asegurado.
    let depositWarning = '';
    if (payload.paymentId) {
      try {
        const paymentResp = await squareClient.paymentsApi.getPayment(payload.paymentId);
        const payment = paymentResp.result?.payment ?? paymentResp.payment;
        const refundedCents = payment?.refundedMoney?.amount != null ? Number(payment.refundedMoney.amount) : 0;
        if (refundedCents > 0) {
          depositWarning = `⚠️ Ojo: el depósito de esta cita ya fue reembolsado ($${(refundedCents / 100).toFixed(2)}). Es posible que el cliente también haya pedido el reembolso por otro link. Considera pedirle que pague el depósito de nuevo.`;
        }
      } catch (err) {
        console.error('Error revisando el estado del pago al aceptar:', err);
      }
    }

    const cancelToken = signBookingToken({
      kind: 'cancel',
      bookingId,
      paymentId: payload.paymentId || null,
      depositCents: depositCentsOf(payload),
      startAt: payload.startAt,
      customerName: payload.customerName,
      customerEmail: payload.customerEmail || null,
      exp: Date.now() + TOKEN_LONG_TTL_MS,
    });
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const cancelUrl = `${baseUrl}/cancel-booking?token=${encodeURIComponent(cancelToken)}`;
    const customerCancelToken = signBookingToken({
      kind: 'customer-cancel',
      bookingId,
      paymentId: payload.paymentId || null,
      depositCents: depositCentsOf(payload),
      startAt: payload.startAt,
      customerName: payload.customerName,
      customerEmail: payload.customerEmail || null,
      exp: Date.now() + TOKEN_LONG_TTL_MS,
    });
    const customerCancelUrl = `${baseUrl}/cancel-appointment?token=${encodeURIComponent(customerCancelToken)}`;

    // Square no le avisa al cliente de citas creadas por API con el token
    // del negocio, así que la confirmación se la mandamos nosotros.
    const addressStr = payload.address
      ? [payload.address.addressLine1, payload.address.locality, payload.address.administrativeDistrictLevel1, payload.address.postalCode].filter(Boolean).join(', ')
      : '';
    const customerEmailSent = payload.customerEmail
      ? await sendCustomerEmail(
          payload.customerEmail,
          'Your Oh My Wash appointment is confirmed',
          `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
            <h2 style="color:#0f6a62;">Your appointment is confirmed!</h2>
            <p>Hi ${escapeHtml(payload.customerName)}, your appointment is confirmed for <strong>${formatApptDateEn(payload.startAt)}</strong>.</p>
            ${payload.serviceSummary ? `<p><strong>Service(s):</strong> ${escapeHtml(payload.serviceSummary)}</p>` : ''}
            ${addressStr ? `<p><strong>Address:</strong> ${escapeHtml(addressStr)}</p>` : ''}
            ${payload.depositPaid != null ? `<p><strong>Deposit paid:</strong> $${Number(payload.depositPaid).toFixed(2)}</p>` : ''}
            ${payload.balanceDue != null ? `<p><strong>Balance due on the day of service:</strong> $${Number(payload.balanceDue).toFixed(2)}</p>` : ''}
            <p style="margin-top:20px;">Need to cancel? You can do it online. Your deposit is refunded automatically if you cancel more than 24 hours before your appointment; cancellations made less than 24 hours in advance are non-refundable.</p>
            <p><a href="${customerCancelUrl}" style="display:inline-block;background:#fff;color:#c0392b;border:2px solid #e2574c;padding:12px 22px;border-radius:100px;text-decoration:none;font-weight:bold;">Cancel appointment &amp; request refund</a></p>
            <p style="color:#8b9a9c;font-size:.85rem;">To change your appointment instead, please contact us.</p>
          </div>`,
          emailKey('confirmed', req.query.token),
        ).catch(() => false)
      : false;

    await sendOwnerEmail(
      `Cita aceptada — ${escapeHtml(payload.customerName)}`,
      `${depositWarning ? `<p style="color:#b45309;"><strong>${escapeHtml(depositWarning)}</strong></p>` : ''}
       <p>La cita de <strong>${escapeHtml(payload.customerName)}</strong> para el ${formatApptDate(payload.startAt)} quedó aceptada en Square.</p>
       <p>${customerEmailSent ? 'Le mandamos la confirmación por correo al cliente.' : 'No se le pudo mandar la confirmación por correo al cliente (verifica tu dominio en Resend) — avísale tú.'}</p>
       <p>Si el cliente necesita cancelar, usa este link (reembolsa el depósito solo si cancela con más de 24 horas de anticipación):</p>
       <p><a href="${cancelUrl}">${cancelUrl}</a></p>`,
      emailKey('accepted', req.query.token),
    );

    res.send(approvalHtmlPage(
      '✅ Cita aceptada',
      `La cita de ${escapeHtml(payload.customerName)} para el ${formatApptDate(payload.startAt)} quedó confirmada en Square.${depositWarning ? ' ' + escapeHtml(depositWarning) : ''}`,
      `<a class="btn btn-secondary" href="${cancelUrl}">Cancelar esta cita</a>`,
    ));
  } catch (err) {
    console.error('Error aprobando la cita:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).send(approvalHtmlPage('❌ No se pudo crear la cita', escapeHtml(detail)));
  }
});

// Rechazar una solicitud: como la cita nunca se creó en Square, no hay nada
// que cancelar ahí. En vez de reembolsar de inmediato, el depósito queda en
// espera: se le ofrecen al cliente hasta 3 horarios alternativos (si elige
// uno, se reutiliza el mismo pago — no se le cobra otra vez) y un link para
// pedir el reembolso si prefiere no reagendar.
app.get('/decline-booking', async (req, res) => {
  const payload = verifyBookingToken(req.query.token, 'request');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Enlace inválido o vencido', 'Este enlace ya no es válido.'));
  }
  const cents = depositCentsOf(payload);
  const amount = `$${(cents / 100).toFixed(2)}`;
  const baseUrl = `${req.protocol}://${req.get('host')}`;

  if (payload.bookingId) {
    try {
      await squareClient.bookingsApi.cancelBooking(payload.bookingId, { idempotencyKey: idempotencyFrom(String(req.query.token) + ':cancel') });
    } catch (err) {
      console.error('Error liberando el horario rechazado:', err);
      const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
      return res.status(500).send(approvalHtmlPage('❌ No se pudo liberar el horario', escapeHtml(detail)));
    }
  }

  // Sin depósito que ofrecer o reembolsar: solo avisar que se rechazó.
  if (!payload.paymentId || cents <= 0) {
    return res.send(approvalHtmlPage(
      '🚫 Solicitud rechazada',
      `La solicitud de ${escapeHtml(payload.customerName)} para el ${formatApptDate(payload.startAt)} fue rechazada.`,
    ));
  }

  const serviceVariationIds = (payload.segments || []).map(s => s.serviceVariationId);
  const totalDurationMin = (payload.segments || []).reduce((sum, s) => sum + (s.durationMinutes || 0), 0);
  let alternatives = [];
  try {
    alternatives = await findAlternativeSlots(serviceVariationIds, totalDurationMin, payload.startAt, 3);
  } catch (err) {
    console.error('Error buscando horarios alternativos:', err);
  }

  const rebookLinks = alternatives.map(alt => {
    const segs = (payload.segments || []).map(s => ({ ...s, teamMemberId: alt.staffId }));
    const rebookToken = signBookingToken({
      kind: 'rebook',
      segments: segs,
      startAt: alt.startAt,
      customerId: payload.customerId,
      customerName: payload.customerName,
      customerEmail: payload.customerEmail,
      customerPhone: payload.customerPhone,
      address: payload.address,
      serviceSummary: payload.serviceSummary,
      staffName: STAFF_SCHEDULE[alt.staffId]?.name || alt.staffId,
      depositPaid: payload.depositPaid,
      balanceDue: payload.balanceDue,
      paymentId: payload.paymentId,
      exp: Date.now() + BOOKING_REQUEST_TTL_MS,
    });
    return { url: `${baseUrl}/rebook?token=${encodeURIComponent(rebookToken)}`, startAt: alt.startAt };
  });

  // Link a la página donde el cliente elige él mismo fecha, técnico y
  // horario (la misma sección "Schedule your appointment" del checkout) —
  // así no queda limitado a los 3 horarios sugeridos.
  const scheduleToken = signBookingToken({
    kind: 'rebook-pick',
    segments: payload.segments || [],
    customerId: payload.customerId,
    customerName: payload.customerName,
    customerEmail: payload.customerEmail,
    customerPhone: payload.customerPhone,
    address: payload.address,
    serviceSummary: payload.serviceSummary,
    depositPaid: payload.depositPaid,
    balanceDue: payload.balanceDue,
    paymentId: payload.paymentId,
    exp: Date.now() + BOOKING_REQUEST_TTL_MS,
  });
  const scheduleUrl = `${baseUrl}/rebook-schedule?token=${encodeURIComponent(scheduleToken)}`;

  const refundToken = signBookingToken({
    kind: 'rebook-refund',
    paymentId: payload.paymentId,
    depositCents: cents,
    customerName: payload.customerName,
    customerId: payload.customerId,
    // Horarios que se le ofrecieron al cliente para reagendar — si ya tiene
    // una cita ACEPTADA en Square para alguno de estos, este depósito ya se
    // está usando ahí y no se debe reembolsar por separado.
    candidateStartAts: alternatives.map(a => a.startAt),
    // Como ahora el cliente también puede elegir cualquier otro horario,
    // cualquier cita aceptada creada después del rechazo cuenta igual.
    declinedAt: Date.now(),
    exp: Date.now() + BOOKING_REQUEST_TTL_MS,
  });
  const refundUrl = `${baseUrl}/rebook-refund?token=${encodeURIComponent(refundToken)}`;

  const btnStyle = 'display:inline-block;background:#2ec4b6;color:#fff;padding:12px 22px;border-radius:100px;text-decoration:none;font-weight:bold;margin:4px 0;';
  const outlineBtnStyle = 'display:inline-block;background:#fff;color:#0f6a62;border:2px solid #2ec4b6;padding:12px 22px;border-radius:100px;text-decoration:none;font-weight:bold;margin:4px 0;';
  const optionsHtml = (fmt) => rebookLinks.map(l => `<p><a href="${l.url}" style="${btnStyle}">${escapeHtml(fmt(l.startAt))}</a></p>`).join('');

  const customerHtml = `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
      <h2 style="color:#0f6a62;">We couldn't confirm your appointment</h2>
      <p>Hi ${escapeHtml(payload.customerName)}, unfortunately we weren't able to confirm your request for ${formatApptDateEn(payload.startAt)}.</p>
      <p>You already paid a ${amount} deposit, so <strong>you won't be charged again</strong> when you reschedule.</p>
      ${rebookLinks.length ? `<p><strong>Suggested times</strong> — tap one to request it:</p>${optionsHtml(formatApptDateEn)}` : ''}
      <p style="margin-top:18px;"><strong>Prefer a different day?</strong> Pick any date, technician and time that works for you:</p>
      <p><a href="${scheduleUrl}" style="${outlineBtnStyle}">📅 Choose another date &amp; time</a></p>
      <p style="margin-top:20px;">Would you rather get your deposit back? <a href="${refundUrl}">Request a refund here</a>.</p>
      <p style="margin-top:20px;color:#8b9a9c;font-size:.8rem;">These links expire in 7 days.</p>
    </div>`;

  const customerEmailSent = payload.customerEmail
    ? await sendCustomerEmail(payload.customerEmail, "We couldn't confirm your appointment — choose a new time", customerHtml, emailKey('declined', req.query.token)).catch(() => false)
    : false;

  // El dueño siempre recibe los mismos links, por si el correo al cliente no
  // se pudo mandar (ej. todavía no se verifica un dominio propio en Resend)
  // — así los puede compartir a mano por WhatsApp o llamada.
  await sendOwnerEmail(
    `Solicitud rechazada — ${escapeHtml(payload.customerName)}`,
    `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
      <p>Rechazaste la solicitud de <strong>${escapeHtml(payload.customerName)}</strong> (${escapeHtml(payload.customerPhone) || 'sin teléfono'}) para el ${formatApptDate(payload.startAt)}.</p>
      <p>${customerEmailSent ? 'Ya le mandamos por correo estas opciones de reagendar:' : 'No le pudimos mandar el correo (verifica tu dominio en Resend) — compártele tú estos links:'}</p>
      ${rebookLinks.length ? optionsHtml(formatApptDate) : '<p>No se encontraron horarios sugeridos en los próximos 30 días.</p>'}
      <p>Link para que elija otra fecha y horario: <a href="${scheduleUrl}">${scheduleUrl}</a></p>
      <p>Link de reembolso: <a href="${refundUrl}">${refundUrl}</a></p>
    </div>`,
    emailKey('declined-owner', req.query.token),
  );

  res.send(approvalHtmlPage(
    '🚫 Solicitud rechazada',
    `La solicitud de ${escapeHtml(payload.customerName)} fue rechazada. ${customerEmailSent ? 'Le mandamos por correo los horarios alternativos y la opción de reembolso.' : 'No se pudo mandar el correo al cliente — revisa tu propio correo para compartirle las opciones manualmente.'}`,
  ));
});

// Monto ya reembolsado (en centavos) de un depósito en Square. Si el
// cliente pidió el reembolso por el otro link del correo, ya no se puede
// reagendar "gratis" con ese depósito. Si Square falla al responder, se
// asume 0 para no bloquear al cliente (el dueño igual lo ve al aceptar).
async function depositRefundedCents(paymentId) {
  if (!paymentId) return 0;
  try {
    const paymentResp = await squareClient.paymentsApi.getPayment(paymentId);
    const payment = paymentResp.result?.payment ?? paymentResp.payment;
    return payment?.refundedMoney?.amount != null ? Number(payment.refundedMoney.amount) : 0;
  } catch (err) {
    console.error('Error revisando el estado del pago antes de reagendar:', err);
    return 0;
  }
}

const DEPOSIT_ALREADY_REFUNDED_PAGE = () => approvalHtmlPage(
  '❌ This deposit was already refunded',
  "We've already refunded your deposit, so it can't be used to book this time. Please make a new booking from our website.",
  '', 'en',
);

// Arma la solicitud normal (kind "request") que pasa otra vez por el mismo
// correo de Aceptar/Rechazar al dueño — sirve tanto para los 3 horarios
// sugeridos como para el horario que el cliente elige él mismo.
function buildRebookRequest(payload, startAt, segments, staffName) {
  return {
    segments,
    startAt,
    customerId: payload.customerId,
    customerName: payload.customerName,
    customerEmail: payload.customerEmail || null,
    customerPhone: payload.customerPhone || null,
    address: payload.address || null,
    serviceSummary: payload.serviceSummary || null,
    staffName: staffName || null,
    depositPaid: payload.depositPaid ?? null,
    balanceDue: payload.balanceDue ?? null,
    paymentId: payload.paymentId || null,
    kind: 'request',
    exp: Date.now() + BOOKING_REQUEST_TTL_MS,
  };
}

// El cliente elige uno de los horarios alternativos — no se le cobra de
// nuevo, se reutiliza el mismo depósito. Esto crea una solicitud normal,
// que pasa otra vez por el mismo correo de Aceptar/Rechazar al dueño.
app.get('/rebook', (req, res) => {
  const payload = verifyBookingToken(req.query.token, 'rebook');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Invalid or expired link', 'This rescheduling link is no longer valid.', '', 'en'));
  }
  res.send(approvalHtmlPage(
    'Confirm your new time',
    `Would you like to request your appointment for ${formatApptDateEn(payload.startAt)} with ${escapeHtml(payload.staffName)}? You won't be charged again.`,
    `<form method="post" action="/rebook"><input type="hidden" name="token" value="${escapeHtml(req.query.token)}"><button class="btn btn-secondary" type="submit">Request this time</button></form>`,
    'en',
  ));
});

app.post('/rebook', async (req, res) => {
  const payload = verifyBookingToken(req.body?.token, 'rebook');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Invalid or expired link', 'This rescheduling link is no longer valid.', '', 'en'));
  }

  if (await depositRefundedCents(payload.paymentId) > 0) {
    return res.status(409).send(DEPOSIT_ALREADY_REFUNDED_PAGE());
  }

  const pendingPayload = buildRebookRequest(payload, payload.startAt, payload.segments, payload.staffName);

  try {
    const newToken = signBookingToken(pendingPayload);
    await sendApprovalEmail(req, pendingPayload, newToken, emailKey('approval-rebook', req.body.token));
    res.send(approvalHtmlPage(
      '✅ Request sent',
      `Your request for ${formatApptDateEn(payload.startAt)} was sent to our team. We'll confirm it shortly — you were not charged again.`,
      '', 'en',
    ));
  } catch (err) {
    console.error('Error reenviando la solicitud reagendada:', err);
    res.status(500).send(approvalHtmlPage('❌ We couldn\'t send your request', 'Please contact us directly to book this time.', '', 'en'));
  }
});

// --- Reagendar eligiendo cualquier fecha ---
// Página con la misma sección "Schedule your appointment" del checkout
// (servicio, calendario, técnico y horarios), para que el cliente no quede
// limitado a los 3 horarios sugeridos del correo. Se puede elegir hasta
// REBOOK_PICK_MAX_DAYS días hacia adelante.
const REBOOK_PICK_MAX_DAYS = 30;

function rebookSchedulePage(token, payload) {
  const segments = payload.segments || [];
  const totalDurationMin = segments.reduce((sum, s) => sum + (s.durationMinutes || 0), 0);
  const totalPrice = (Number(payload.depositPaid) || 0) + (Number(payload.balanceDue) || 0);
  const data = {
    token,
    serviceVariationIds: segments.map(s => s.serviceVariationId),
    totalDurationMin,
    staff: Object.fromEntries(Object.entries(STAFF_SCHEDULE).map(([id, s]) => [id, { name: s.name, days: s.days, endMin: s.endMin }])),
    maxDays: REBOOK_PICK_MAX_DAYS,
  };
  // "<" escapado para que nada dentro del JSON pueda cerrar el <script>.
  const dataJson = JSON.stringify(data).replace(/</g, '\\u003c');
  const meta = [totalPrice > 0 ? `$${totalPrice.toFixed(2)}` : '', totalDurationMin ? `${totalDurationMin} min` : ''].filter(Boolean).join(' · ');

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reschedule — Oh My Wash</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root{--teal:#2ec4b6;--teal-deep:#0f6a62;--teal-light:#7de0d4;--teal-pale:#e6faf7;--ink:#12191a;--off:#f4fafb;--shadow:0 20px 50px rgba(20,50,55,.12);--ease:cubic-bezier(.22,1,.36,1);}
  *{margin:0;padding:0;box-sizing:border-box;}
  body{font-family:'Inter',-apple-system,Segoe UI,Arial,sans-serif;color:var(--ink);background:var(--off);-webkit-font-smoothing:antialiased;min-height:100vh;padding:40px 16px 80px;}
  .wrap{max-width:640px;margin:0 auto;}
  .brand{text-align:center;font-weight:800;font-size:1.3rem;color:var(--teal-deep);margin-bottom:24px;letter-spacing:.3px;}
  .panel{background:#fff;border-radius:22px;padding:32px;box-shadow:var(--shadow);}
  .panel h1{font-weight:700;font-size:1.2rem;margin-bottom:22px;}
  .section-hint{color:#5c6b6e;font-size:.88rem;margin-bottom:18px;line-height:1.5;}
  .notice{background:var(--teal-pale);border-radius:14px;padding:14px 16px;color:var(--teal-deep);font-size:.88rem;font-weight:600;line-height:1.5;margin-bottom:22px;}
  .pay-field{margin-bottom:18px;}
  .pay-field label{display:block;font-weight:600;font-size:.88rem;margin-bottom:8px;}
  .appt-service-summary{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:14px 16px;border-radius:12px;background:var(--teal-pale);border:1.5px solid var(--teal-light);}
  .appt-service-name{font-weight:700;font-size:.95rem;}
  .appt-service-meta{font-size:.8rem;color:var(--teal-deep);font-weight:700;white-space:nowrap;}
  .date-picker-wrap{position:relative;}
  .date-picker-btn{width:100%;display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-radius:12px;border:1.5px solid #d8e8ea;background:#fff;font-size:.95rem;font-family:inherit;color:var(--ink);cursor:pointer;text-align:left;}
  .date-picker-btn:hover{border-color:var(--teal);}
  .appt-calendar{position:absolute;top:calc(100% + 10px);left:0;z-index:20;background:#fff;border-radius:20px;box-shadow:var(--shadow);border:1px solid #eaf1f2;padding:22px;width:320px;max-width:calc(100vw - 32px);}
  .cal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;}
  .cal-header span{font-weight:700;font-size:1.05rem;}
  .cal-nav{width:34px;height:34px;border-radius:50%;border:none;background:var(--teal-pale);color:var(--teal-deep);font-size:1.15rem;cursor:pointer;font-weight:700;}
  .cal-nav:hover:not(:disabled){background:var(--teal);color:#fff;}
  .cal-nav:disabled{opacity:.35;cursor:not-allowed;}
  .cal-weekdays{display:grid;grid-template-columns:repeat(7,1fr);gap:4px;margin-bottom:10px;}
  .cal-weekdays span{text-align:center;font-size:.7rem;font-weight:700;color:#8b9a9c;text-transform:uppercase;}
  .cal-days{display:grid;grid-template-columns:repeat(7,1fr);gap:6px;}
  .cal-day{aspect-ratio:1;display:flex;align-items:center;justify-content:center;border-radius:12px;border:none;background:transparent;font-size:.92rem;font-weight:600;color:var(--ink);cursor:pointer;font-family:inherit;}
  .cal-day:hover:not(:disabled):not(.empty){background:var(--teal-pale);}
  .cal-day.selected{background:var(--teal);color:#fff;}
  .cal-day.today:not(.selected){border:1.5px solid var(--teal);}
  .cal-day:disabled{color:#d0dbdc;cursor:not-allowed;}
  .cal-day.empty{visibility:hidden;}
  .cal-day.unavail{color:#b4bfc1;background:#f1f4f5;position:relative;}
  .cal-day.unavail::after{content:'/';position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:1.25rem;font-weight:400;color:#9aa6a8;}
  .chips{display:flex;flex-wrap:wrap;gap:10px;}
  .chip{padding:10px 16px;border-radius:100px;border:1.5px solid #d8e8ea;background:#fff;color:var(--ink);font-weight:600;font-size:.88rem;cursor:pointer;font-family:inherit;transition:all .2s var(--ease);}
  .chip:hover{border-color:var(--teal);}
  .chip.selected{background:var(--teal);border-color:var(--teal);color:#fff;}
  .empty-note{font-size:.85rem;color:#8b9a9c;}
  .btn-secondary{width:100%;padding:13px;border-radius:100px;border:1.5px solid var(--teal);background:#fff;color:var(--teal-deep);font-weight:600;font-size:.94rem;cursor:pointer;font-family:inherit;margin-top:4px;}
  .btn-secondary:hover{background:var(--teal-pale);}
  .btn-secondary:disabled,.btn-primary:disabled{opacity:.5;cursor:not-allowed;}
  .btn-primary{width:100%;padding:14px;border-radius:100px;border:none;background:var(--teal);color:#fff;font-weight:700;font-size:1rem;cursor:pointer;font-family:inherit;margin-top:20px;}
  .btn-primary:hover:not(:disabled){background:#22a89c;}
  #slots{margin-top:18px;}
  .link-btn{margin-left:8px;padding:6px 14px;border-radius:100px;border:1.5px solid var(--teal);background:#fff;color:var(--teal-deep);font-weight:700;font-size:.82rem;cursor:pointer;font-family:inherit;}
  #status{margin-top:16px;font-weight:600;font-size:.9rem;min-height:20px;line-height:1.5;}
  .done{text-align:center;padding:12px 0;}
  .done h1{margin-bottom:12px;}
  .done p{color:#5c6b6e;line-height:1.6;}
  @media (max-width:480px){.panel{padding:24px 18px;}}
</style></head><body><div class="wrap">
  <div class="brand">Oh My Wash</div>
  <div class="panel" id="panel">
    <h1>Schedule your appointment</h1>
    <p class="section-hint">Choose the date and confirm an available time with our team.</p>
    <div class="notice">Your deposit is already paid — you won't be charged again.</div>
    <div class="pay-field">
      <label>Service</label>
      <div class="appt-service-summary">
        <span class="appt-service-name">${escapeHtml(payload.serviceSummary || 'Your service')}</span>
        ${meta ? `<span class="appt-service-meta">${meta}</span>` : ''}
      </div>
    </div>
    <div class="pay-field">
      <label>Date</label>
      <div class="date-picker-wrap">
        <button type="button" id="dateBtn" class="date-picker-btn"><span id="dateLabel">Choose a date</span><span>📅</span></button>
        <div id="calendar" class="appt-calendar" hidden>
          <div class="cal-header">
            <button type="button" id="calPrev" class="cal-nav" aria-label="Previous month">‹</button>
            <span id="calMonth"></span>
            <button type="button" id="calNext" class="cal-nav" aria-label="Next month">›</button>
          </div>
          <div class="cal-weekdays">${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(d => `<span>${d}</span>`).join('')}</div>
          <div id="calDays" class="cal-days"></div>
        </div>
      </div>
    </div>
    <div class="pay-field">
      <label>Technician</label>
      <div id="staffPicker" class="chips"></div>
    </div>
    <button id="searchBtn" type="button" class="btn-secondary">Search available times</button>
    <div id="slots" class="chips"></div>
    <button id="submitBtn" type="button" class="btn-primary" hidden>Request this time</button>
    <p id="status"></p>
  </div>
</div>
<script>
(() => {
  const DATA = ${dataJson};
  const STAFF = DATA.staff;
  const TZ = 'America/New_York';

  const $ = (id) => document.getElementById(id);
  const dateBtn = $('dateBtn'), dateLabel = $('dateLabel'), calendar = $('calendar');
  const calMonth = $('calMonth'), calDays = $('calDays'), calPrev = $('calPrev'), calNext = $('calNext');
  const staffPicker = $('staffPicker'), searchBtn = $('searchBtn'), slotsEl = $('slots');
  const submitBtn = $('submitBtn'), statusEl = $('status');

  function setStatus(html, kind) {
    statusEl.innerHTML = html;
    statusEl.style.color = kind === 'error' ? '#c0392b' : kind === 'ok' ? '#1d8a4a' : '#5c6b6e';
  }

  const toDateStr = (d) => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  const dayKeyNY = (iso) => new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(iso));
  const weekdayOfKey = (key) => new Date(key + 'T12:00:00').getDay();
  function nyMinutesOfDay(date) {
    const parts = new Intl.DateTimeFormat('en-US', { timeZone: TZ, hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(date);
    return (parseInt(parts.find(p => p.type === 'hour').value, 10) % 24) * 60 + parseInt(parts.find(p => p.type === 'minute').value, 10);
  }

  const today = new Date();
  const minDate = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);
  const maxDate = new Date(today.getFullYear(), today.getMonth(), today.getDate() + DATA.maxDays);
  let selectedDate = new Date(minDate);
  let calView = new Date(minDate.getFullYear(), minDate.getMonth(), 1);
  let selectedStaffId = null;
  let slots = [];
  let selectedSlot = null;
  let userPickedDate = false;

  function updateDateLabel() {
    dateLabel.textContent = selectedDate.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
  }

  function renderStaffPicker() {
    const dow = selectedDate.getDay();
    const eligible = Object.entries(STAFF).filter(([, s]) => s.days.includes(dow));
    if (!eligible.length) {
      staffPicker.innerHTML = '<span class="empty-note">No technicians work this day. Please choose another date.</span>';
      selectedStaffId = null;
      return;
    }
    if (!eligible.some(([id]) => id === selectedStaffId)) selectedStaffId = eligible[0][0];
    staffPicker.innerHTML = eligible.map(([id, s]) => '<button type="button" class="chip' + (id === selectedStaffId ? ' selected' : '') + '" data-id="' + id + '">' + s.name + '</button>').join('');
    staffPicker.querySelectorAll('.chip').forEach(btn => btn.addEventListener('click', () => {
      selectedStaffId = btn.dataset.id;
      staffPicker.querySelectorAll('.chip').forEach(b => b.classList.toggle('selected', b === btn));
      clearSlots();
    }));
  }

  function clearSlots() {
    slots = []; selectedSlot = null;
    slotsEl.innerHTML = ''; submitBtn.hidden = true;
  }

  // Igual que en el checkout: Square conoce el horario del local y las citas
  // ya tomadas; aquí se recortan los horarios que terminarían después de la
  // hora de salida de cada técnico.
  const validFor = (staffId, av) => av.filter(a =>
    nyMinutesOfDay(new Date(new Date(a.startAt).getTime() + DATA.totalDurationMin * 60000)) <= STAFF[staffId].endMin
    && STAFF[staffId].days.includes(weekdayOfKey(dayKeyNY(a.startAt))));

  async function searchAvailability(staffId, startAt, endAt) {
    const res = await fetch('/availability', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serviceVariationIds: DATA.serviceVariationIds, teamMemberId: staffId, startAt, endAt }),
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.error);
    return data.availabilities || [];
  }

  const monthCache = {}, monthPending = {};
  function loadMonth(year, month) {
    const key = year + '-' + month;
    if (monthCache[key]) return Promise.resolve(monthCache[key]);
    if (monthPending[key]) return monthPending[key];
    const startAt = new Date(Math.max(Date.UTC(year, month, 1), Date.now() + 60000)).toISOString();
    const endAt = new Date(Math.min(Date.UTC(year, month + 1, 1), maxDate.getTime() + 2 * 86400000)).toISOString();
    monthPending[key] = Promise.all(Object.keys(STAFF).map(id =>
      searchAvailability(id, startAt, endAt).then(av => validFor(id, av)).catch(() => [])
    )).then(results => {
      const open = new Set(results.flat().map(a => dayKeyNY(a.startAt)));
      monthCache[key] = open;
      delete monthPending[key];
      return open;
    });
    return monthPending[key];
  }

  function renderCalendar() {
    calMonth.textContent = calView.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    const year = calView.getFullYear(), month = calView.getMonth();
    const openDays = monthCache[year + '-' + month];
    if (!openDays) loadMonth(year, month).then(renderCalendar).catch(() => {});
    let html = '';
    for (let i = 0; i < new Date(year, month, 1).getDay(); i++) html += '<button type="button" class="cal-day empty" disabled></button>';
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    for (let d = 1; d <= daysInMonth; d++) {
      const dateObj = new Date(year, month, d);
      const dStr = toDateStr(dateObj);
      const disabled = dateObj < minDate || dateObj > maxDate;
      const unavail = !disabled && openDays && !openDays.has(dStr);
      const cls = 'cal-day' + (dStr === toDateStr(selectedDate) ? ' selected' : '') + (dStr === toDateStr(today) ? ' today' : '') + (unavail ? ' unavail' : '');
      html += '<button type="button" class="' + cls + '" data-date="' + dStr + '"' + (disabled || unavail ? ' disabled' : '') + '>' + d + '</button>';
    }
    calDays.innerHTML = html;
    calPrev.disabled = year === minDate.getFullYear() && month === minDate.getMonth();
    calNext.disabled = year === maxDate.getFullYear() && month === maxDate.getMonth();
    calDays.querySelectorAll('.cal-day[data-date]:not(:disabled)').forEach(btn => btn.addEventListener('click', () => {
      const [y, m, day] = btn.dataset.date.split('-').map(Number);
      selectDay(new Date(y, m - 1, day));
      userPickedDate = true;
      calendar.hidden = true;
      searchBtn.click();
    }));
  }

  function selectDay(date, staffId) {
    selectedDate = date;
    if (staffId) selectedStaffId = staffId;
    updateDateLabel();
    renderStaffPicker();
    renderCalendar();
    clearSlots();
  }

  dateBtn.addEventListener('click', () => { calendar.hidden = !calendar.hidden; if (!calendar.hidden) renderCalendar(); });
  calPrev.addEventListener('click', () => { calView.setMonth(calView.getMonth() - 1); renderCalendar(); });
  calNext.addEventListener('click', () => { calView.setMonth(calView.getMonth() + 1); renderCalendar(); });
  document.addEventListener('click', (e) => {
    if (!calendar.hidden && !calendar.contains(e.target) && !dateBtn.contains(e.target)) calendar.hidden = true;
  });

  async function findNextAvailable(fromDate) {
    const start = new Date(Math.max(fromDate.getTime(), Date.now() + 60000));
    const end = new Date(maxDate.getTime() + 2 * 86400000);
    if (end <= start) return null;
    const results = await Promise.all(Object.keys(STAFF).map(id =>
      searchAvailability(id, start.toISOString(), end.toISOString())
        .then(av => validFor(id, av).map(a => ({ ...a, staffId: id })))
        .catch(() => [])
    ));
    const minKey = toDateStr(minDate), maxKey = toDateStr(maxDate);
    const all = results.flat().filter(a => dayKeyNY(a.startAt) >= minKey && dayKeyNY(a.startAt) <= maxKey);
    all.sort((x, y) => new Date(x.startAt) - new Date(y.startAt));
    return all[0] || null;
  }

  const fmtTime = (iso) => new Date(iso).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', timeZone: TZ });
  const fmtDay = (iso) => new Date(iso).toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', timeZone: TZ });
  const keyToDate = (key) => { const [y, m, d] = key.split('-').map(Number); return new Date(y, m - 1, d); };

  searchBtn.addEventListener('click', async () => {
    if (!selectedStaffId) { setStatus('No technicians work this day. Please choose another date.', 'error'); return; }
    const dateVal = toDateStr(selectedDate);
    clearSlots();
    setStatus('Searching for available times...', 'info');
    searchBtn.disabled = true;
    try {
      // Rango amplio en UTC que cubre todo el día en Nueva York; luego se
      // filtra por la fecha local de cada horario.
      const startAt = new Date(Math.max(Date.parse(dateVal + 'T00:00:00Z'), Date.now() + 60000)).toISOString();
      const endAt = new Date(Date.parse(dateVal + 'T00:00:00Z') + 36 * 3600000).toISOString();
      const av = await searchAvailability(selectedStaffId, startAt, endAt);
      slots = validFor(selectedStaffId, av).filter(a => dayKeyNY(a.startAt) === dateVal);
      if (!slots.length) {
        const next = await findNextAvailable(new Date(dateVal + 'T00:00:00Z'));
        if (next) {
          setStatus('No available times that day. Next available: <strong>' + fmtDay(next.startAt) + '</strong>, ' + fmtTime(next.startAt) + ' <button type="button" id="useNext" class="link-btn">Use this</button>', 'info');
          $('useNext').addEventListener('click', () => { selectDay(keyToDate(dayKeyNY(next.startAt)), next.staffId); searchBtn.click(); });
        } else {
          setStatus('No availability in the next ' + DATA.maxDays + ' days. Please call us at +1 678-895-5812.', 'error');
        }
        return;
      }
      slotsEl.innerHTML = slots.map((a, i) => '<button type="button" class="chip" data-i="' + i + '">' + fmtTime(a.startAt) + '</button>').join('');
      slotsEl.querySelectorAll('.chip').forEach(btn => btn.addEventListener('click', () => {
        selectedSlot = slots[Number(btn.dataset.i)];
        slotsEl.querySelectorAll('.chip').forEach(b => b.classList.toggle('selected', b === btn));
        submitBtn.hidden = false;
        setStatus('Selected: <strong>' + fmtDay(selectedSlot.startAt) + ', ' + fmtTime(selectedSlot.startAt) + '</strong> with ' + STAFF[selectedStaffId].name + '.', 'info');
      }));
      setStatus('', 'info');
    } catch (err) {
      console.error(err);
      setStatus('We couldn\\'t load available times. Please try again.', 'error');
    } finally {
      searchBtn.disabled = false;
    }
  });

  submitBtn.addEventListener('click', async () => {
    if (!selectedSlot) return;
    submitBtn.disabled = true;
    setStatus('Sending your request...', 'info');
    try {
      const res = await fetch('/rebook-schedule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: DATA.token, staffId: selectedStaffId, startAt: selectedSlot.startAt }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error || 'Unknown error');
      $('panel').innerHTML = '<div class="done"><h1>✅ Request sent</h1><p>Your request for <strong>' + fmtDay(selectedSlot.startAt) + ', ' + fmtTime(selectedSlot.startAt) + '</strong> was sent to our team. We\\'ll confirm it by email shortly — you were not charged again.</p></div>';
    } catch (err) {
      setStatus(err.message, 'error');
      submitBtn.disabled = false;
    }
  });

  updateDateLabel();
  renderStaffPicker();
  // Igual que el checkout: arranca en el próximo horario disponible.
  findNextAvailable(minDate).then(next => {
    if (userPickedDate) return;
    if (!next) { setStatus('No availability in the next ' + DATA.maxDays + ' days. Please call us at +1 678-895-5812.', 'error'); return; }
    selectDay(keyToDate(dayKeyNY(next.startAt)), next.staffId);
    searchBtn.click();
  }).catch(() => {});
})();
</script></body></html>`;
}

app.get('/rebook-schedule', (req, res) => {
  const payload = verifyBookingToken(req.query.token, 'rebook-pick');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Invalid or expired link', 'This rescheduling link is no longer valid. Please contact us to book a new time.', '', 'en'));
  }
  res.send(rebookSchedulePage(String(req.query.token), payload));
});

// El cliente manda el horario que eligió en la página de arriba. Se vuelve
// a validar todo en el servidor (día y hora de salida del técnico, y que
// Square siga teniendo ese horario libre) antes de mandar la solicitud al
// dueño — el navegador del cliente no es de fiar.
app.post('/rebook-schedule', async (req, res) => {
  const { token, staffId, startAt } = req.body || {};
  const payload = verifyBookingToken(token, 'rebook-pick');
  if (!payload) {
    return res.status(400).json({ success: false, error: 'This rescheduling link is no longer valid. Please contact us.' });
  }
  const cfg = STAFF_SCHEDULE[staffId];
  const startMs = Date.parse(startAt);
  if (!cfg || !Number.isFinite(startMs)) {
    return res.status(400).json({ success: false, error: 'Please choose a technician and a time.' });
  }
  if (startMs < Date.now() || startMs > Date.now() + (REBOOK_PICK_MAX_DAYS + 2) * 24 * 60 * 60 * 1000) {
    return res.status(400).json({ success: false, error: 'That time is outside the dates we can book. Please choose another.' });
  }
  const segments = (payload.segments || []).map(s => ({ ...s, teamMemberId: staffId }));
  const totalDurationMin = segments.reduce((sum, s) => sum + (s.durationMinutes || 0), 0);
  const fitsSchedule = cfg.days.includes(new Date(nyDateKey(startAt) + 'T12:00:00').getDay())
    && nyMinutesOfDay(new Date(startMs + totalDurationMin * 60000)) <= cfg.endMin;
  if (!fitsSchedule) {
    return res.status(400).json({ success: false, error: `${cfg.name} isn't available at that time. Please choose another.` });
  }

  try {
    const rangeStart = new Date(Math.max(Date.now() + 60000, startMs - 60 * 60 * 1000));
    const rangeEnd = new Date(rangeStart.getTime() + 25 * 60 * 60 * 1000);
    const response = await squareClient.bookingsApi.searchAvailability({
      query: { filter: {
        startAtRange: { startAt: rangeStart.toISOString(), endAt: rangeEnd.toISOString() },
        locationId: process.env.SQUARE_LOCATION_ID,
        segmentFilters: segments.map(s => ({ serviceVariationId: s.serviceVariationId, teamMemberIdFilter: { any: [staffId] } })),
      } },
    });
    const availabilities = response.result?.availabilities ?? response.availabilities ?? [];
    if (!availabilities.some(a => Date.parse(a.startAt) === startMs)) {
      return res.status(409).json({ success: false, error: 'Sorry, that time was just taken. Please choose another.' });
    }
  } catch (err) {
    console.error('Error verificando el horario elegido para reagendar:', err);
    return res.status(500).json({ success: false, error: "We couldn't check that time. Please try again." });
  }

  if (await depositRefundedCents(payload.paymentId) > 0) {
    return res.status(409).json({ success: false, error: "Your deposit was already refunded, so it can't be used for this booking. Please make a new booking from our website." });
  }

  try {
    const pendingPayload = buildRebookRequest(payload, new Date(startMs).toISOString(), segments, cfg.name);
    await sendApprovalEmail(req, pendingPayload, signBookingToken(pendingPayload), emailKey('approval-pick', `${token}|${startMs}|${staffId}`));
    res.json({ success: true });
  } catch (err) {
    console.error('Error enviando la solicitud reagendada (horario elegido):', err);
    res.status(500).json({ success: false, error: "We couldn't send your request. Please contact us directly." });
  }
});

// El cliente prefiere no reagendar y pide el reembolso del depósito que
// había quedado en espera.
// Revisa si el cliente ya tiene una cita ACEPTADA en Square que esté usando
// este depósito — ya sea uno de los horarios sugeridos al rechazar, o
// cualquier cita creada después del rechazo (el cliente pudo elegir otro
// horario en /rebook-schedule). Si la tiene, este depósito ya está
// asegurando esa cita y no se debe reembolsar aparte (se le dirige al link
// de cancelación de esa cita, que ya tiene la regla correcta de 24 horas).
async function findConfirmedAlternative(payload) {
  if (!payload.customerId || (!payload.candidateStartAts?.length && !payload.declinedAt)) return null;
  try {
    const response = await squareClient.bookingsApi.listBookings(
      undefined, undefined, payload.customerId, undefined,
      process.env.SQUARE_LOCATION_ID,
      new Date().toISOString(),
      new Date(Date.now() + 31 * 24 * 60 * 60 * 1000).toISOString(),
    );
    const bookings = response.result?.bookings ?? response.bookings ?? [];
    return bookings.find(b => b.status === 'ACCEPTED' && (
      (payload.candidateStartAts || []).includes(b.startAt)
      || (payload.declinedAt && Date.parse(b.createdAt) > payload.declinedAt)
    )) || null;
  } catch (err) {
    console.error('Error revisando si ya hay una cita confirmada:', err);
    return null;
  }
}

const ALREADY_CONFIRMED_PAGE = (confirmed) => approvalHtmlPage(
  '❌ You already have a confirmed appointment',
  `You already have an appointment confirmed for ${formatApptDateEn(confirmed.startAt)}, and your deposit is being used for it. If you need to cancel it, please contact us.`,
  '', 'en',
);

app.get('/rebook-refund', async (req, res) => {
  const payload = verifyBookingToken(req.query.token, 'rebook-refund');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Invalid or expired link', 'This refund link is no longer valid.', '', 'en'));
  }
  const confirmed = await findConfirmedAlternative(payload);
  if (confirmed) return res.status(409).send(ALREADY_CONFIRMED_PAGE(confirmed));
  const amount = `$${((payload.depositCents || 0) / 100).toFixed(2)}`;
  res.send(approvalHtmlPage(
    'Request a refund',
    `Do you want a refund of your ${amount} deposit instead of rescheduling?`,
    `<form method="post" action="/rebook-refund"><input type="hidden" name="token" value="${escapeHtml(req.query.token)}"><button class="btn" type="submit">Confirm refund</button></form>`,
    'en',
  ));
});

app.post('/rebook-refund', async (req, res) => {
  const payload = verifyBookingToken(req.body?.token, 'rebook-refund');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Invalid or expired link', 'This refund link is no longer valid.', '', 'en'));
  }
  const confirmed = await findConfirmedAlternative(payload);
  if (confirmed) return res.status(409).send(ALREADY_CONFIRMED_PAGE(confirmed));
  const cents = payload.depositCents || 0;
  const amount = `$${(cents / 100).toFixed(2)}`;
  try {
    await refundDeposit(payload.paymentId, cents, 'Cliente no quiso reagendar tras rechazo', req.body.token + ':rebook-refund');
    res.send(approvalHtmlPage(
      '✅ Refund processed',
      `We've refunded your ${amount} deposit. It may take a few business days to appear on your card.`,
      '', 'en',
    ));
  } catch (err) {
    console.error('Error procesando el reembolso de reagendar:', err);
    // Esta página la ve el cliente, así que al dueño se le avisa aparte.
    await sendOwnerEmail(
      `Reembolso fallido — ${escapeHtml(payload.customerName)}`,
      `<p>El cliente <strong>${escapeHtml(payload.customerName)}</strong> pidió el reembolso de su depósito, pero no se pudo procesar automáticamente. Hazlo manualmente desde Square por ${amount}.</p>`,
      emailKey('refund-failed', req.body.token),
    ).catch(() => {});
    res.status(500).send(approvalHtmlPage(
      "❌ We couldn't process your refund",
      "Something went wrong while processing your refund. We've notified our team and will take care of it manually.",
      '', 'en',
    ));
  }
});

// Cancelación de una cita ya aceptada. Con más de 24 horas de anticipación
// se reembolsa el depósito; con menos, no hay reembolso. La cita siempre se
// libera del calendario.
function refundStatus(payload) {
  const hours = (Date.parse(payload.startAt) - Date.now()) / 3600000;
  const cents = payload.depositCents || 0;
  const amount = `$${(cents / 100).toFixed(2)}`;
  if (cents <= 0) return { refundable: false, text: 'No hay depósito que reembolsar.' };
  if (!payload.paymentId) return { refundable: false, text: `No se puede reembolsar automáticamente (falta el ID del pago). Reembolsa ${amount} manualmente desde Square.` };
  if (hours < DEPOSIT_REFUND_MIN_HOURS) return { refundable: false, text: `No hay reembolso: la cancelación es con menos de 24 horas de anticipación (${amount} no reembolsables).` };
  return { refundable: true, text: `Se reembolsarán ${amount} (cancelación con más de 24 horas de anticipación).` };
}

// Lógica compartida por el link del dueño (/cancel-booking) y el del
// cliente (/cancel-appointment): libera la cita en Square, le avisa al
// cliente por correo y reembolsa el depósito si aplica la regla de 24 horas.
// Las idempotencyKey se derivan del token, así que hacer clic dos veces no
// cancela ni reembolsa dos veces. Si la cita ya estaba cancelada (por el
// otro link), no se hace nada más — así nunca se reembolsa dos veces.
async function cancelAcceptedBooking(token, payload) {
  const { refundable, text: policyText } = refundStatus(payload);
  const cents = payload.depositCents || 0;

  try {
    const bookingResp = await squareClient.bookingsApi.retrieveBooking(payload.bookingId);
    const booking = bookingResp.result?.booking ?? bookingResp.booking;
    if (booking?.status && booking.status.startsWith('CANCELLED')) {
      return { outcome: 'already', cents, policyText };
    }
  } catch (err) {
    console.error('Error revisando el estado de la cita antes de cancelar:', err);
  }

  try {
    await squareClient.bookingsApi.cancelBooking(payload.bookingId, { idempotencyKey: idempotencyFrom(token + ':cancel') });
  } catch (err) {
    console.error('Error cancelando la cita:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    return { outcome: 'error', detail, cents, policyText };
  }

  // Igual que al aceptar, Square no le avisa al cliente de la cancelación.
  // Los links de cancelación creados antes de este cambio no traen el correo.
  if (payload.customerEmail) {
    await sendCustomerEmail(
      payload.customerEmail,
      'Your Oh My Wash appointment was canceled',
      `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
        <h2 style="color:#0f6a62;">Your appointment was canceled</h2>
        <p>Hi ${escapeHtml(payload.customerName)}, your appointment for <strong>${formatApptDateEn(payload.startAt)}</strong> has been canceled.</p>
        <p>${refundable
          ? `We'll refund your $${(cents / 100).toFixed(2)} deposit. It may take a few business days to appear on your card.`
          : cents > 0 ? 'Since the cancellation was made less than 24 hours in advance, the deposit is non-refundable.' : ''}</p>
        <p style="margin-top:20px;">If you'd like to book another date, we'll be happy to help.</p>
      </div>`,
      emailKey('canceled', payload.bookingId),
    ).catch(() => false);
  }

  if (!refundable) return { outcome: 'canceled', refunded: false, cents, policyText };

  try {
    await refundDeposit(payload.paymentId, cents, 'Cancelación con más de 24 horas de anticipación', token + ':refund');
    return { outcome: 'canceled', refunded: true, cents, policyText };
  } catch (err) {
    console.error('Error reembolsando la cancelación:', err);
    return { outcome: 'canceled', refunded: false, refundFailed: true, cents, policyText };
  }
}

app.get('/cancel-booking', (req, res) => {
  const payload = verifyBookingToken(req.query.token, 'cancel');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Enlace inválido o vencido', 'Este enlace de cancelación no es válido.'));
  }
  const { text: policyText } = refundStatus(payload);

  res.send(approvalHtmlPage(
    'Cancelar cita',
    `Cita de ${escapeHtml(payload.customerName)} para el ${formatApptDate(payload.startAt)}. ${policyText}`,
    `<form method="post" action="/cancel-booking"><input type="hidden" name="token" value="${escapeHtml(req.query.token)}"><button class="btn" type="submit">Confirmar cancelación</button></form>`,
  ));
});

app.post('/cancel-booking', async (req, res) => {
  const token = req.body?.token;
  const payload = verifyBookingToken(token, 'cancel');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Enlace inválido o vencido', 'Este enlace de cancelación no es válido.'));
  }
  const result = await cancelAcceptedBooking(token, payload);
  const amount = `$${(result.cents / 100).toFixed(2)}`;

  if (result.outcome === 'already') {
    return res.send(approvalHtmlPage('ℹ️ La cita ya estaba cancelada', `La cita de ${escapeHtml(payload.customerName)} para el ${formatApptDate(payload.startAt)} ya se había cancelado (quizás el cliente la canceló desde su correo). No se hizo ningún cambio.`));
  }
  if (result.outcome === 'error') {
    return res.status(500).send(approvalHtmlPage('❌ No se pudo cancelar', escapeHtml(result.detail)));
  }
  if (result.refundFailed) {
    return res.status(500).send(approvalHtmlPage(
      '⚠️ Cancelada, pero el reembolso falló',
      `La cita fue cancelada, pero el reembolso de ${amount} no se pudo procesar. Hazlo manualmente desde Square.`,
    ));
  }
  if (result.refunded) {
    return res.send(approvalHtmlPage('✅ Cita cancelada y reembolsada', `La cita de ${escapeHtml(payload.customerName)} fue cancelada y se reembolsaron ${amount}.`));
  }
  res.send(approvalHtmlPage('✅ Cita cancelada', `La cita de ${escapeHtml(payload.customerName)} fue cancelada. ${escapeHtml(result.policyText)}`));
});

// Link de cancelación que va en el correo de confirmación del cliente — en
// inglés y con la política de reembolso explicada antes de confirmar. Usa
// su propio tipo de token ("customer-cancel") para que el cliente no reciba
// el link del dueño (páginas en español).
function customerRefundPolicy(payload) {
  const hours = (Date.parse(payload.startAt) - Date.now()) / 3600000;
  const cents = payload.depositCents || 0;
  const amount = `$${(cents / 100).toFixed(2)}`;
  if (cents <= 0) return '';
  if (hours >= DEPOSIT_REFUND_MIN_HOURS && !payload.paymentId) return `Since you're canceling more than 24 hours in advance, our team will refund your ${amount} deposit.`;
  if (hours >= DEPOSIT_REFUND_MIN_HOURS) return `Since you're canceling more than 24 hours in advance, your ${amount} deposit will be refunded to your card.`;
  return `Because your appointment is less than 24 hours away, your ${amount} deposit is <strong>non-refundable</strong>.`;
}

app.get('/cancel-appointment', async (req, res) => {
  const payload = verifyBookingToken(req.query.token, 'customer-cancel');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Invalid or expired link', 'This cancellation link is no longer valid. Please contact us.', '', 'en'));
  }
  if (Date.parse(payload.startAt) < Date.now()) {
    return res.status(400).send(approvalHtmlPage('❌ This appointment has already passed', 'This appointment can no longer be canceled online. Please contact us if you need help.', '', 'en'));
  }
  res.send(approvalHtmlPage(
    'Cancel your appointment',
    `Your appointment is scheduled for <strong>${formatApptDateEn(payload.startAt)}</strong>. ${customerRefundPolicy(payload)}<br><br>Are you sure you want to cancel?`,
    `<form method="post" action="/cancel-appointment"><input type="hidden" name="token" value="${escapeHtml(req.query.token)}"><button class="btn" type="submit">Yes, cancel my appointment</button></form>`,
    'en',
  ));
});

app.post('/cancel-appointment', async (req, res) => {
  const token = req.body?.token;
  const payload = verifyBookingToken(token, 'customer-cancel');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Invalid or expired link', 'This cancellation link is no longer valid. Please contact us.', '', 'en'));
  }
  if (Date.parse(payload.startAt) < Date.now()) {
    return res.status(400).send(approvalHtmlPage('❌ This appointment has already passed', 'This appointment can no longer be canceled online. Please contact us if you need help.', '', 'en'));
  }
  const result = await cancelAcceptedBooking(token, payload);
  const amount = `$${(result.cents / 100).toFixed(2)}`;

  if (result.outcome === 'already') {
    return res.send(approvalHtmlPage('ℹ️ Already canceled', 'This appointment was already canceled. No further changes were made.', '', 'en'));
  }
  if (result.outcome === 'error') {
    return res.status(500).send(approvalHtmlPage("❌ We couldn't cancel your appointment", 'Something went wrong. Please try again or contact us directly.', '', 'en'));
  }

  // El dueño se entera de inmediato de las cancelaciones que hace el cliente.
  await sendOwnerEmail(
    `Cita cancelada por el cliente — ${escapeHtml(payload.customerName)}`,
    `<p><strong>${escapeHtml(payload.customerName)}</strong> canceló su cita del ${formatApptDate(payload.startAt)} desde el link de su correo de confirmación. Ya se liberó en Square.</p>
     <p>${result.refundFailed
       ? `⚠️ Le correspondía el reembolso de ${amount}, pero falló — hazlo manualmente desde Square.`
       : result.refunded ? `Se le reembolsaron ${amount} automáticamente.` : escapeHtml(result.policyText)}</p>`,
    emailKey('customer-canceled', payload.bookingId),
  ).catch(() => {});

  if (result.refundFailed) {
    return res.send(approvalHtmlPage('✅ Appointment canceled', `Your appointment was canceled. We had a problem processing your ${amount} refund automatically — our team has been notified and will take care of it.`, '', 'en'));
  }
  res.send(approvalHtmlPage(
    '✅ Appointment canceled',
    `Your appointment for ${formatApptDateEn(payload.startAt)} was canceled.${result.refunded ? ` Your ${amount} deposit has been refunded — it may take a few business days to appear on your card.` : ''} We've also sent you a confirmation email.`,
    '', 'en',
  ));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Oh My Wash server escuchando en http://localhost:${PORT}`);
});
