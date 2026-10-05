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

function approvalHtmlPage(title, message, extraHtml = '') {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title}</title>
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

async function sendApprovalEmail(req, payload, token) {
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

  if (!emailResp.ok) {
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
          preferences: { emailUnsubscribed: marketingOptIn !== true },
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

    // La cita se crea en Square desde el momento de la solicitud para bloquear
    // el horario. Si el dueño rechaza, se cancela (y se reembolsa el depósito).
    let bookingId;
    try {
      const bookingResp = await squareClient.bookingsApi.createBooking({
        idempotencyKey: randomUUID(),
        booking: {
          locationId: process.env.SQUARE_LOCATION_ID,
          startAt,
          customerId,
          locationType: address ? 'CUSTOMER_LOCATION' : undefined,
          address,
          appointmentSegments: segmentList.map(s => ({
            teamMemberId: s.teamMemberId,
            serviceVariationId: s.serviceVariationId,
            serviceVariationVersion: s.serviceVariationVersion != null ? BigInt(s.serviceVariationVersion) : undefined,
            durationMinutes: s.durationMinutes,
          })),
        },
      });
      bookingId = (bookingResp.result?.booking ?? bookingResp.booking).id;
    } catch (bookingErr) {
      console.error('Error bloqueando el horario en Square:', bookingErr);
      const refunded = await refundDepositSafely(paymentId, depositPaid, 'Horario no disponible al solicitar la cita', randomUUID());
      const detail = bookingErr?.errors?.[0]?.detail || bookingErr?.body?.errors?.[0]?.detail || bookingErr.message || 'Error desconocido';
      return res.status(409).json({ success: false, error: detail, refunded });
    }

    const pendingPayload = {
      bookingId,
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
    try {
      await sendApprovalEmail(req, pendingPayload, token);
    } catch (emailErr) {
      await squareClient.bookingsApi.cancelBooking(bookingId, { idempotencyKey: randomUUID() }).catch(() => {});
      throw emailErr;
    }

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

async function refundDepositSafely(paymentId, depositPaid, reason, seed) {
  const cents = Math.round(Number(depositPaid || 0) * 100);
  if (!paymentId || cents <= 0) return false;
  try {
    await refundDeposit(paymentId, cents, reason, seed);
    return true;
  } catch (err) {
    console.error('Reembolso automático fallido:', err);
    return false;
  }
}

async function sendOwnerEmail(subject, html) {
  if (!process.env.RESEND_API_KEY || !process.env.NOTIFY_EMAIL) return;
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: process.env.NOTIFY_FROM || 'Oh My Wash <onboarding@resend.dev>',
      to: [process.env.NOTIFY_EMAIL],
      subject,
      html,
    }),
  });
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
    // Solicitudes creadas antes del bloqueo inmediato no tienen bookingId:
    // para esas todavía se crea la cita al aprobar.
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

    const cancelToken = signBookingToken({
      kind: 'cancel',
      bookingId,
      paymentId: payload.paymentId || null,
      depositCents: depositCentsOf(payload),
      startAt: payload.startAt,
      customerName: payload.customerName,
      exp: Date.now() + TOKEN_LONG_TTL_MS,
    });
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const cancelUrl = `${baseUrl}/cancel-booking?token=${encodeURIComponent(cancelToken)}`;

    await sendOwnerEmail(
      `Cita aceptada — ${escapeHtml(payload.customerName)}`,
      `<p>La cita de <strong>${escapeHtml(payload.customerName)}</strong> para el ${formatApptDate(payload.startAt)} quedó aceptada en Square.</p>
       <p>Si el cliente necesita cancelar, usa este link (reembolsa el depósito solo si cancela con más de 24 horas de anticipación):</p>
       <p><a href="${cancelUrl}">${cancelUrl}</a></p>`,
    );

    res.send(approvalHtmlPage(
      '✅ Cita aceptada',
      `La cita de ${escapeHtml(payload.customerName)} para el ${formatApptDate(payload.startAt)} quedó confirmada en Square.`,
      `<a class="btn btn-secondary" href="${cancelUrl}">Cancelar esta cita</a>`,
    ));
  } catch (err) {
    console.error('Error aprobando la cita:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).send(approvalHtmlPage('❌ No se pudo crear la cita', escapeHtml(detail)));
  }
});

// Rechazar una solicitud: como la cita nunca se creó en Square, no hay nada
// que cancelar ahí, pero el cliente ya pagó el depósito, así que se reembolsa.
app.get('/decline-booking', async (req, res) => {
  const payload = verifyBookingToken(req.query.token, 'request');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Enlace inválido o vencido', 'Este enlace ya no es válido.'));
  }
  const cents = depositCentsOf(payload);
  const amount = `$${(cents / 100).toFixed(2)}`;

  if (payload.bookingId) {
    try {
      await squareClient.bookingsApi.cancelBooking(payload.bookingId, { idempotencyKey: idempotencyFrom(String(req.query.token) + ':cancel') });
    } catch (err) {
      console.error('Error liberando el horario rechazado:', err);
      const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
      return res.status(500).send(approvalHtmlPage('❌ No se pudo liberar el horario', escapeHtml(detail)));
    }
  }

  if (!payload.paymentId || cents <= 0) {
    return res.send(approvalHtmlPage(
      '🚫 Solicitud rechazada',
      `La solicitud de ${escapeHtml(payload.customerName)} para el ${formatApptDate(payload.startAt)} fue rechazada y el horario quedó libre.`,
    ));
  }

  try {
    await refundDeposit(payload.paymentId, cents, 'Solicitud de cita rechazada por el negocio', String(req.query.token) + ':refund');
    res.send(approvalHtmlPage(
      '🚫 Solicitud rechazada',
      `La solicitud de ${escapeHtml(payload.customerName)} para el ${formatApptDate(payload.startAt)} fue rechazada, el horario quedó libre y se reembolsaron ${amount}.`,
    ));
  } catch (err) {
    console.error('Error reembolsando la solicitud rechazada:', err);
    res.status(500).send(approvalHtmlPage(
      '⚠️ Rechazada, pero el reembolso falló',
      `El horario quedó libre, pero el reembolso de ${amount} no se pudo procesar. Hazlo manualmente desde Square.`,
    ));
  }
});

// Cancelación de una cita ya aceptada. Con más de 24 horas de anticipación
// se reembolsa el depósito; con menos, no hay reembolso. La cita siempre se
// libera del calendario.
app.get('/cancel-booking', (req, res) => {
  const payload = verifyBookingToken(req.query.token, 'cancel');
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Enlace inválido o vencido', 'Este enlace de cancelación no es válido.'));
  }
  const hours = (Date.parse(payload.startAt) - Date.now()) / 3600000;
  const cents = payload.depositCents || 0;
  const refundable = hours >= DEPOSIT_REFUND_MIN_HOURS && cents > 0 && !!payload.paymentId;
  const policyText = cents <= 0
    ? 'No hay depósito que reembolsar.'
    : refundable
      ? `Se reembolsarán $${(cents / 100).toFixed(2)} (cancelación con más de 24 horas de anticipación).`
      : `No hay reembolso: la cancelación es con menos de 24 horas de anticipación ($${(cents / 100).toFixed(2)} no reembolsables).`;

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
  const hours = (Date.parse(payload.startAt) - Date.now()) / 3600000;
  const cents = payload.depositCents || 0;
  const refundable = hours >= DEPOSIT_REFUND_MIN_HOURS && cents > 0 && !!payload.paymentId;

  try {
    await squareClient.bookingsApi.cancelBooking(payload.bookingId, { idempotencyKey: idempotencyFrom(token + ':cancel') });
  } catch (err) {
    console.error('Error cancelando la cita:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    return res.status(500).send(approvalHtmlPage('❌ No se pudo cancelar', escapeHtml(detail)));
  }

  if (!refundable) {
    return res.send(approvalHtmlPage(
      '✅ Cita cancelada',
      `La cita de ${escapeHtml(payload.customerName)} fue cancelada. ${cents > 0 ? 'No hubo reembolso (menos de 24 horas).' : ''}`,
    ));
  }

  try {
    await refundDeposit(payload.paymentId, cents, 'Cancelación con más de 24 horas de anticipación', token + ':refund');
    res.send(approvalHtmlPage(
      '✅ Cita cancelada y reembolsada',
      `La cita de ${escapeHtml(payload.customerName)} fue cancelada y se reembolsaron $${(cents / 100).toFixed(2)}.`,
    ));
  } catch (err) {
    console.error('Error reembolsando la cancelación:', err);
    res.status(500).send(approvalHtmlPage(
      '⚠️ Cancelada, pero el reembolso falló',
      `La cita fue cancelada, pero el reembolso de $${(cents / 100).toFixed(2)} no se pudo procesar. Hazlo manualmente desde Square.`,
    ));
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Oh My Wash server escuchando en http://localhost:${PORT}`);
});
