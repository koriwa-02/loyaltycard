import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL  = "https://lvzzcwsttvbaqsnuwdze.supabase.co";
const SUPABASE_ANON = Deno.env.get("SUPABASE_ANON_KEY") || "";

// Allowed origins — add your domain when you get one
const ALLOWED_ORIGINS = [
  "https://koriwa-02.github.io",
  "http://localhost",
  "http://127.0.0.1",
];

// In-memory rate limiter (resets on cold start)
const requestCounts = new Map<string, { count: number; window: number }>();

function checkRateLimit(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const record = requestCounts.get(key);

  if (!record || now - record.window > windowMs) {
    requestCounts.set(key, { count: 1, window: now });
    return true;
  }

  if (record.count >= max) return false;

  record.count++;
  return true;
}

function getClientIP(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("cf-connecting-ip")
    || "unknown";
}

function hashIP(ip: string): string {
  // Simple hash — don't store raw IPs
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = ((hash << 5) - hash) + ip.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}

serve(async (req) => {
  const origin = req.headers.get("origin") || "";
  const ip     = getClientIP(req);
  const ipHash = hashIP(ip);

  const corsHeaders = {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };

  // Handle preflight
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  // Origin check
  const originAllowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o));
  if (!originAllowed && origin !== "") {
    console.warn(`Blocked origin: ${origin}`);
    return new Response(JSON.stringify({ error: "Forbidden" }), {
      status: 403,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }

  // Global rate limit — 200 requests per minute per IP
  if (!checkRateLimit(`${ipHash}:global`, 200, 60_000)) {
    return new Response(JSON.stringify({ error: "Too many requests" }), {
      status: 429,
      headers: { ...corsHeaders, "Content-Type": "application/json", "Retry-After": "60" }
    });
  }

  try {
    const body = await req.json();
    const { action, token, cashier_id, merchant_id } = body;

    if (!action || !token || !merchant_id) {
      return new Response(JSON.stringify({ error: "Missing required fields" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Action-specific rate limits
    const actionKey = `${ipHash}:${action}`;
    const limits: Record<string, [number, number]> = {
      add_stamp:     [60, 60_000],   // 60 stamps per minute per device
      redeem_reward: [10, 60_000],   // 10 redeems per minute per device
      refresh_token: [30, 60_000],   // 30 refreshes per minute per device
    };

    const [maxCalls, windowMs] = limits[action] || [30, 60_000];
    if (!checkRateLimit(actionKey, maxCalls, windowMs)) {
      return new Response(JSON.stringify({ error: "Rate limit exceeded — slow down" }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Token format validation
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(token)) {
      return new Response(JSON.stringify({ error: "Invalid token format" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Call Supabase RPC
    const sb = createClient(SUPABASE_URL, SUPABASE_ANON);
    let result;

    if (action === "add_stamp") {
      const { data, error } = await sb.rpc("add_stamp_by_token", {
        p_token:       token,
        p_cashier_id:  cashier_id || null,
        p_merchant_id: merchant_id,
      });
      result = error ? { success: false, error: error.message } : data;

    } else if (action === "redeem_reward") {
      const { data, error } = await sb.rpc("redeem_reward_by_token", {
        p_token:       token,
        p_cashier_id:  cashier_id || null,
        p_merchant_id: merchant_id,
      });
      result = error ? { success: false, error: error.message } : data;

    } else {
      result = { success: false, error: "Unknown action" };
    }

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

  } catch (e) {
    return new Response(JSON.stringify({ error: "Internal error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
