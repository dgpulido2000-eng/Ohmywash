import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID, createHmac, createHash, timingSafeEqual } from 'node:crypto';
import pkg from 'square';
import nodemailer from 'nodemailer';
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
const mailTransport = process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
    })
  : null;

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

function verifyBookingToken(token) {
  if (!APPROVAL_SECRET || !token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expectedSig = createHmac('sha256', APPROVAL_SECRET).update(body).digest('base64url');
  const sigBuf = Buffer.from(sig || '', 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
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

function approvalHtmlPage(title, message) {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title}</title>
<style>
  body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#f4fafb;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:24px;box-sizing:border-box;}
  .card{max-width:420px;background:#fff;border-radius:20px;padding:36px 30px;box-shadow:0 20px 50px rgba(20,50,55,.12);text-align:center;}
  h1{font-size:1.3rem;margin:0 0 12px;color:#12191a;}
  p{color:#5c6b6e;line-height:1.6;margin:0;}
</style></head><body><div class="card"><h1>${title}</h1><p>${message}</p></div></body></html>`;
}

function formatApptDate(startAt) {
  return new Date(startAt).toLocaleString('es-US', {
    timeZone: 'America/New_York', weekday: 'long', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit',
  });
}

async function sendApprovalEmail(req, payload, token) {
  if (!mailTransport) {
    throw new Error('El correo de aprobación no está configurado (faltan GMAIL_USER / GMAIL_APP_PASSWORD en el servidor).');
  }
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const approveUrl = `${baseUrl}/approve-booking?token=${encodeURIComponent(token)}`;
  const declineUrl = `${baseUrl}/decline-booking?token=${encodeURIComponent(token)}`;
  const addressStr = payload.address
    ? [payload.address.addressLine1, payload.address.locality, payload.address.administrativeDistrictLevel1, payload.address.postalCode].filter(Boolean).join(', ')
    : 'No especificada';

  await mailTransport.sendMail({
    from: `"Oh My Wash — Reservas" <${process.env.GMAIL_USER}>`,
    to: process.env.GMAIL_USER,
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
        <p><strong>Fecha y hora:</strong> ${formatApptDate(payload.startAt)}</p>
        <div style="margin-top:24px;">
          <a href="${approveUrl}" style="display:inline-block;background:#2ec4b6;color:#fff;padding:14px 26px;border-radius:100px;text-decoration:none;font-weight:bold;margin-right:12px;">✅ Aceptar cita</a>
          <a href="${declineUrl}" style="display:inline-block;background:#e2574c;color:#fff;padding:14px 26px;border-radius:100px;text-decoration:none;font-weight:bold;">❌ Rechazar</a>
        </div>
        <p style="margin-top:20px;color:#8b9a9c;font-size:.8rem;">Este enlace vence en 7 días.</p>
      </div>
    `,
  });
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
        });
      }
    }

    if (!customerId) {
      const createResp = await squareClient.customersApi.createCustomer({
        givenName: customerName,
        emailAddress: customerEmail || undefined,
        phoneNumber: customerPhone || undefined,
        address,
      });
      customerId = (createResp.result?.customer ?? createResp.customer)?.id;
    }

    // No se llama a bookingsApi.createBooking aquí. En su lugar, se firma
    // un token con todos los datos necesarios para crear la cita después,
    // y se manda por correo con botones de Aceptar/Rechazar — la cita real
    // en Square solo se crea cuando el dueño hace clic en "Aceptar"
    // (endpoint /approve-booking).
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
      exp: Date.now() + BOOKING_REQUEST_TTL_MS,
    };

    const token = signBookingToken(pendingPayload);
    await sendApprovalEmail(req, pendingPayload, token);

    res.json({ success: true, pending: true });
  } catch (err) {
    console.error('Error creando la solicitud de cita:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).json({ success: false, error: detail });
  }
});

// El dueño hace clic en este link desde el correo para aceptar la cita —
// aquí sí se crea la cita real en Square. idempotencyKey se deriva del
// token para que hacer clic dos veces (o recargar la página) no cree dos
// citas duplicadas.
app.get('/approve-booking', async (req, res) => {
  const payload = verifyBookingToken(req.query.token);
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Enlace inválido o vencido', 'Este enlace de aprobación ya no es válido (venció a los 7 días, o el token está mal formado).'));
  }

  try {
    const idempotencyKey = createHash('sha256').update(String(req.query.token)).digest('hex').slice(0, 45);
    const bookingResp = await squareClient.bookingsApi.createBooking({
      idempotencyKey,
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

    const booking = bookingResp.result?.booking ?? bookingResp.booking;
    res.send(approvalHtmlPage(
      '✅ Cita aceptada',
      `La cita de ${escapeHtml(payload.customerName)} para el ${formatApptDate(payload.startAt)} fue creada en Square (ID: ${escapeHtml(booking.id)}).`,
    ));
  } catch (err) {
    console.error('Error aprobando la cita:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).send(approvalHtmlPage('❌ No se pudo crear la cita', escapeHtml(detail)));
  }
});

// El dueño hace clic en este link para rechazar la solicitud — como la
// cita nunca se creó en Square, no hay nada que cancelar ahí.
app.get('/decline-booking', async (req, res) => {
  const payload = verifyBookingToken(req.query.token);
  if (!payload) {
    return res.status(400).send(approvalHtmlPage('❌ Enlace inválido o vencido', 'Este enlace ya no es válido.'));
  }
  res.send(approvalHtmlPage(
    '🚫 Solicitud rechazada',
    `La solicitud de ${escapeHtml(payload.customerName)} para el ${formatApptDate(payload.startAt)} fue rechazada. No se creó ninguna cita en Square.`,
  ));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Oh My Wash server escuchando en http://localhost:${PORT}`);
});
