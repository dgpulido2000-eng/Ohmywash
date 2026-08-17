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

// --- Preparado para reservas (futuro) ---
// Cuando quieras añadir reservas con la Bookings API, sigue el mismo patrón:
// usa squareClient.bookingsApi (mismas credenciales, mismo .env) y crea un
// endpoint POST /create-booking que reciba serviceVariationId, startAt, etc.
// app.post('/create-booking', async (req, res) => { ... });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Oh My Wash server escuchando en http://localhost:${PORT}`);
});
