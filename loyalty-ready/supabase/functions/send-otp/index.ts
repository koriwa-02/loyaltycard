import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'

const RESEND_API_KEY = Deno.env.get('RESEND_API_KEY')!

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'authorization, content-type'
    }})
  }

  const { code, email, merchant_name } = await req.json()

  if (!email || !code) {
    return new Response(JSON.stringify({ error: 'Missing fields' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    })
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'KORIWA Loyalty <onboarding@resend.dev>',
      to: [email],
      subject: `${code} — your verification code`,
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;">
          <h2 style="font-size:22px;font-weight:800;margin-bottom:8px;">Your verification code</h2>
          <p style="color:#6B6B6B;font-size:14px;margin-bottom:24px;">
            Enter this code to access your loyalty card at <strong>${merchant_name || 'the shop'}</strong>.
          </p>
          <div style="background:#F4F3F0;border-radius:16px;padding:24px;text-align:center;margin-bottom:24px;">
            <span style="font-size:40px;font-weight:800;letter-spacing:8px;color:#0E0E0E;">${code}</span>
          </div>
          <p style="color:#6B6B6B;font-size:13px;">Expires in 10 minutes. If you didn't request this, ignore this email.</p>
        </div>
      `
    })
  })

  const resBody = await res.json()

  if (!res.ok) {
    return new Response(JSON.stringify({ error: resBody }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    })
  }

  return new Response(JSON.stringify({ success: true, id: resBody.id }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  })
})
