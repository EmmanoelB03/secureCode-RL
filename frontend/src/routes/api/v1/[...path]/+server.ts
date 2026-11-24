import { env } from '$env/dynamic/private';
import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

const proxy: RequestHandler = async ({ params, request, fetch }) => {
  const path = params.path ?? '';
  const reads = /^(health|dataset\/(info|distribution)|model\/(info|metrics|supervised)|experiments(?:\/[a-z0-9-]+)?)$/;
  const writes = /^(analyze|repair)$/;
  if (!(request.method === 'GET' ? reads : writes).test(path)) return json({ detail: 'Rota desconhecida.' }, { status: 404 });
  try {
    const body = request.method === 'POST' ? await request.text() : undefined;
    if (body && body.length > 300000) return json({ detail: 'Código muito grande.' }, { status: 413 });
    const response = await fetch(`${env.BACKEND_URL || 'http://127.0.0.1:8000'}/api/v1/${path}`, {
      method: request.method, headers: { 'Content-Type': 'application/json' }, body, signal: AbortSignal.timeout(25000)
    });
    return new Response(await response.text(), { status: response.status, headers: { 'Content-Type': 'application/json' } });
  } catch { return json({ detail: 'Backend indisponível. Inicie a API na porta 8000.' }, { status: 503 }); }
};
export const GET = proxy;
export const POST = proxy;
