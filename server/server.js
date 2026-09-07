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

const squareClient = new Client({
  accessToken: process.env.SQUARE_ACCESS_TOKEN,
  environment: Environment.Sandbox,
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
