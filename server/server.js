import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID } from 'node:crypto';
import pkg from 'square';
const { Client, Environment } = pkg;

const app = express();

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

// Crea la cita real en Square (y el cliente si no existe todavía).
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
  } = req.body || {};

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
    }

    if (!customerId) {
      const createResp = await squareClient.customersApi.createCustomer({
        givenName: customerName,
        emailAddress: customerEmail || undefined,
        phoneNumber: customerPhone || undefined,
      });
      customerId = (createResp.result?.customer ?? createResp.customer)?.id;
    }

    const bookingResp = await squareClient.bookingsApi.createBooking({
      idempotencyKey: randomUUID(),
      booking: {
        locationId: process.env.SQUARE_LOCATION_ID,
        startAt,
        customerId,
        appointmentSegments: segmentList.map(s => ({
          teamMemberId: s.teamMemberId,
          serviceVariationId: s.serviceVariationId,
          serviceVariationVersion: s.serviceVariationVersion != null ? BigInt(s.serviceVariationVersion) : undefined,
          durationMinutes: s.durationMinutes,
        })),
      },
    });

    const booking = bookingResp.result?.booking ?? bookingResp.booking;

    res.json({
      success: true,
      bookingId: booking.id,
      startAt: booking.startAt,
      status: booking.status,
    });
  } catch (err) {
    console.error('Error creando la cita:', err);
    const detail = err?.errors?.[0]?.detail || err?.body?.errors?.[0]?.detail || err.message || 'Error desconocido';
    res.status(500).json({ success: false, error: detail });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Oh My Wash server escuchando en http://localhost:${PORT}`);
});
