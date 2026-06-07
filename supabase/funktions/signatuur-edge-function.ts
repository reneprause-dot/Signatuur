// supabase/functions/sign-document/index.ts
// Edge Function: Serverseitiges Signieren mit RFC-3161 Zeitstempel (Sectigo TSA)
// Läuft mit service_role — nie im Browser!

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const SECTIGO_TSA_URL = "https://timestamp.sectigo.com";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-document-token",
};

// ── Supabase Admin Client (service_role, bypasses RLS) ──────────
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ── SHA-256 via WebCrypto ────────────────────────────────────────
async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", encoder.encode(data));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(buf);
}

// ── RFC-3161 Timestamp Request (Sectigo TSA) ────────────────────
// Erstellt einen minimalen ASN.1 DER-kodierten Timestamp Request
async function requestTimestamp(hashHex: string): Promise<{
  token: string;
  timestamp: Date;
  serial: string;
} | null> {
  try {
    // Hash als Bytes
    const hashBytes = new Uint8Array(hashHex.match(/.{2}/g)!.map((h) => parseInt(h, 16)));

    // Minimaler RFC-3161 TimeStampReq in DER
    // SEQUENCE { INTEGER 1, MessageImprint { AlgorithmIdentifier SHA-256, OCTET STRING hash }, BOOLEAN TRUE }
    const sha256OID = new Uint8Array([0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00]);
    const msgImprint = new Uint8Array([0x30, sha256OID.length + hashBytes.length + 4, ...sha256OID, 0x04, hashBytes.length, ...hashBytes]);
    const version = new Uint8Array([0x02, 0x01, 0x01]);
    const certReq = new Uint8Array([0x01, 0x01, 0xff]);
    const tsReqContent = new Uint8Array([...version, ...msgImprint, ...certReq]);
    const tsReq = new Uint8Array([0x30, tsReqContent.length, ...tsReqContent]);

    const response = await fetch(SECTIGO_TSA_URL, {
      method: "POST",
      headers: { "Content-Type": "application/timestamp-query" },
      body: tsReq,
    });

    if (!response.ok) {
      console.error("TSA response error:", response.status, await response.text());
      return null;
    }

    const tsrBytes = new Uint8Array(await response.arrayBuffer());
    const tokenBase64 = btoa(String.fromCharCode(...tsrBytes));

    // Zeitstempel aus der Response lesen (vereinfacht — Produktiv: ASN.1 Parser)
    const timestamp = new Date();

    // Seriennummer als Hex der ersten 8 Bytes des Tokens (Approximation)
    const serial = Array.from(tsrBytes.slice(10, 18))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(":");

    return { token: tokenBase64, timestamp, serial };
  } catch (err) {
    console.error("TSA request failed:", err);
    return null;
  }
}

// ── OTP generieren & hashen ─────────────────────────────────────
function generateOTP(): string {
  const digits = "0123456789";
  let otp = "";
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  for (const b of bytes) otp += digits[b % 10];
  return otp;
}

async function hashOTP(otp: string): Promise<string> {
  // Verwende SHA-256 + Salt für OTP-Hashing (in Produktion: bcrypt via pg_crypt)
  const salt = crypto.randomUUID();
  const hash = await sha256(otp + salt);
  return `${salt}:${hash}`;
}

async function verifyOTP(otp: string, storedHash: string): Promise<boolean> {
  const [salt, hash] = storedHash.split(":");
  const computed = await sha256(otp + salt);
  return computed === hash;
}

// ── IP-Adresse aus Request extrahieren ──────────────────────────
function getClientIP(req: Request): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    req.headers.get("x-real-ip") ||
    "unknown"
  );
}

// ================================================================
// MAIN HANDLER
// ================================================================
serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  const url = new URL(req.url);
  const action = url.searchParams.get("action") || "sign";
  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  try {
    switch (action) {

      // ── 1. DOKUMENT ANLEGEN + OTP SENDEN ──────────────────────
      case "create": {
        const authHeader = req.headers.get("authorization");
        if (!authHeader) return json({ error: "Nicht authentifiziert" }, 401);

        const { data: { user }, error: authErr } = await supabase.auth.getUser(
          authHeader.replace("Bearer ", "")
        );
        if (authErr || !user) return json({ error: "Ungültiger Token" }, 401);

        const body = await req.json();
        const { title, doc_type, description, signer_name, signer_email, file_path, file_hash } = body;

        if (!title || !signer_name || !signer_email) {
          return json({ error: "Pflichtfelder fehlen" }, 400);
        }

        // Dokument anlegen
        const { data: doc, error: docErr } = await supabase
          .from("documents")
          .insert({
            owner_id: user.id,
            title,
            doc_type: doc_type || "other",
            description,
            signer_name,
            signer_email,
            file_path: file_path || null,
            file_hash_sha256: file_hash || null,
            status: "pending_otp",
            expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          })
          .select()
          .single();

        if (docErr) return json({ error: docErr.message }, 500);

        // OTP generieren
        const otp = generateOTP();
        const otpHash = await hashOTP(otp);

        await supabase.from("otp_tokens").insert({
          document_id: doc.id,
          email: signer_email,
          token_hash: otpHash,
          expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
        });

        // Audit-Trail
        await supabase.from("audit_trail").insert({
          document_id: doc.id,
          event: "created",
          actor_user_id: user.id,
          ip_address: ip,
          user_agent: userAgent,
          payload_hash: await sha256(JSON.stringify({ title, signer_email, ts: new Date().toISOString() })),
        });

        // OTP via Supabase Auth E-Mail senden
        // In Produktion: supabase.auth.admin.sendRawEmail() oder Resend API
        // Hier: OTP im Response zurückgeben (nur für lokale Tests!)
        // WICHTIG: In Produktion diesen Block durch echten E-Mail-Versand ersetzen!
        await supabase.from("audit_trail").insert({
          document_id: doc.id,
          event: "otp_sent",
          actor_email: signer_email,
          ip_address: ip,
          notes: `OTP gesendet an ${signer_email}`,
        });

        // Supabase Built-in Email via Auth Magic Link als OTP-Alternative
        // oder eigene E-Mail-Funktion aufrufen:
        await sendOTPEmail(signer_email, signer_name, otp, doc.id, title);

        return json({
          success: true,
          document_id: doc.id,
          message: `OTP wurde an ${signer_email} gesendet`,
          // OTP nur in Development zurückgeben!
          ...(Deno.env.get("ENVIRONMENT") === "development" && { dev_otp: otp }),
        });
      }

      // ── 2. OTP VERIFIZIEREN ────────────────────────────────────
      case "verify-otp": {
        const { document_id, otp, signer_email } = await req.json();
        if (!document_id || !otp || !signer_email) {
          return json({ error: "Pflichtfelder fehlen" }, 400);
        }

        // Gültigen OTP-Token suchen
        const { data: tokens } = await supabase
          .from("otp_tokens")
          .select("*")
          .eq("document_id", document_id)
          .eq("email", signer_email)
          .is("used_at", null)
          .gt("expires_at", new Date().toISOString())
          .order("created_at", { ascending: false })
          .limit(1);

        if (!tokens || tokens.length === 0) {
          return json({ error: "Kein gültiger OTP gefunden oder abgelaufen" }, 400);
        }

        const tokenRecord = tokens[0];

        // Zu viele Versuche?
        if (tokenRecord.attempts >= tokenRecord.max_attempts) {
          return json({ error: "Maximale Versuche überschritten" }, 429);
        }

        // Versuche erhöhen
        await supabase.from("otp_tokens")
          .update({ attempts: tokenRecord.attempts + 1 })
          .eq("id", tokenRecord.id);

        // OTP prüfen
        const valid = await verifyOTP(otp, tokenRecord.token_hash);
        if (!valid) {
          return json({ error: "Ungültiger OTP-Code", remaining: tokenRecord.max_attempts - tokenRecord.attempts - 1 }, 400);
        }

        // OTP als verwendet markieren
        await supabase.from("otp_tokens").update({ used_at: new Date().toISOString() }).eq("id", tokenRecord.id);

        // Einwilligungstext speichern (DSGVO)
        await supabase.from("consent_log").insert({
          document_id,
          signer_email,
          consent_text: "Ich bestätige mit Eingabe des OTP-Codes, dass ich das vorliegende Dokument elektronisch unterzeichnen möchte. Diese Signatur entspricht einer Fortgeschrittenen Elektronischen Signatur (FES) gemäß Art. 26 der eIDAS-Verordnung (EU) Nr. 910/2014.",
          ip_address: ip,
        });

        // Dokument-Status aktualisieren
        await supabase.from("documents")
          .update({ status: "pending_sign" })
          .eq("id", document_id);

        // Audit
        await supabase.from("audit_trail").insert({
          document_id,
          event: "otp_verified",
          actor_email: signer_email,
          ip_address: ip,
          user_agent: userAgent,
        });

        // Einmaliges Sign-Token generieren (für den nächsten Schritt)
        const signToken = await sha256(`${document_id}:${signer_email}:${Date.now()}:${crypto.randomUUID()}`);

        return json({ success: true, sign_token: signToken });
      }

      // ── 3. DOKUMENT SIGNIEREN ──────────────────────────────────
      case "sign": {
        const body = await req.json();
        const { document_id, signer_email, signature_data, sign_token } = body;

        if (!document_id || !signer_email || !signature_data) {
          return json({ error: "Pflichtfelder fehlen" }, 400);
        }

        // Dokument laden und Status prüfen
        const { data: doc, error: docErr } = await supabase
          .from("documents")
          .select("*")
          .eq("id", document_id)
          .single();

        if (docErr || !doc) return json({ error: "Dokument nicht gefunden" }, 404);
        if (doc.status !== "pending_sign") return json({ error: `Ungültiger Status: ${doc.status}` }, 400);
        if (doc.signer_email !== signer_email) return json({ error: "E-Mail stimmt nicht überein" }, 403);
        if (new Date(doc.expires_at) < new Date()) return json({ error: "Signaturfrist abgelaufen" }, 410);

        // Payload-Hash erstellen (Manipulationsnachweis)
        const signedAt = new Date().toISOString();
        const payloadStr = JSON.stringify({
          document_id,
          title: doc.title,
          signer_email,
          signer_name: doc.signer_name,
          file_hash: doc.file_hash_sha256,
          signature_data: signature_data.substring(0, 64), // Prefix genügt für Hash
          signed_at: signedAt,
        });
        const payloadHash = await sha256(payloadStr);

        // RFC-3161 Zeitstempel von Sectigo anfordern
        console.log("Requesting TSA timestamp from Sectigo...");
        const tsa = await requestTimestamp(payloadHash);

        if (!tsa) {
          console.warn("TSA fehlgeschlagen — Signatur wird trotzdem gespeichert (ohne qualifizierten Zeitstempel)");
        }

        // Dokument aktualisieren
        const { error: updateErr } = await supabase
          .from("documents")
          .update({
            status: "signed",
            signature_data,
            payload_hash: payloadHash,
            tsa_token: tsa?.token || null,
            tsa_ts: tsa?.timestamp?.toISOString() || null,
            tsa_serial: tsa?.serial || null,
            signed_at: signedAt,
          })
          .eq("id", document_id);

        if (updateErr) return json({ error: updateErr.message }, 500);

        // Audit-Trail
        await supabase.from("audit_trail").insert({
          document_id,
          event: "signed",
          actor_email: signer_email,
          ip_address: ip,
          user_agent: userAgent,
          payload_hash: payloadHash,
          notes: tsa ? `TSA: ${tsa.serial}` : "TSA nicht verfügbar",
        });

        return json({
          success: true,
          document_id,
          payload_hash: payloadHash,
          tsa_available: !!tsa,
          tsa_serial: tsa?.serial,
          signed_at: signedAt,
        });
      }

      // ── 4. DOKUMENT WIDERRUFEN ─────────────────────────────────
      case "revoke": {
        const authHeader = req.headers.get("authorization");
        if (!authHeader) return json({ error: "Nicht authentifiziert" }, 401);

        const { data: { user } } = await supabase.auth.getUser(authHeader.replace("Bearer ", ""));
        if (!user) return json({ error: "Ungültiger Token" }, 401);

        const { document_id, reason } = await req.json();
        if (!document_id || !reason) return json({ error: "Dokument-ID und Grund erforderlich" }, 400);

        // Dokument gehört dem User?
        const { data: doc } = await supabase.from("documents").select("owner_id, status").eq("id", document_id).single();
        if (!doc || doc.owner_id !== user.id) return json({ error: "Kein Zugriff" }, 403);
        if (doc.status === "revoked") return json({ error: "Bereits widerrufen" }, 400);

        await supabase.from("documents").update({
          status: "revoked",
          revoked_at: new Date().toISOString(),
          revoke_reason: reason,
        }).eq("id", document_id);

        await supabase.from("revocation_log").insert({
          document_id,
          revoked_by: user.id,
          reason,
          ip_address: ip,
        });

        await supabase.from("audit_trail").insert({
          document_id,
          event: "revoked",
          actor_user_id: user.id,
          ip_address: ip,
          notes: reason,
        });

        return json({ success: true, message: "Signatur erfolgreich widerrufen" });
      }

      // ── 5. SIGNATUR VERIFIZIEREN ───────────────────────────────
      case "verify": {
        const { document_id, hash } = await req.json();

        const query = document_id
          ? supabase.from("documents").select("id, title, signer_name, signer_email, status, payload_hash, tsa_ts, tsa_serial, signed_at, file_hash_sha256").eq("id", document_id).single()
          : supabase.from("documents").select("id, title, signer_name, signer_email, status, payload_hash, tsa_ts, tsa_serial, signed_at, file_hash_sha256").eq("payload_hash", hash).single();

        const { data: doc } = await query;

        if (!doc) return json({ valid: false, error: "Dokument nicht gefunden" }, 404);

        return json({
          valid: doc.status === "signed",
          status: doc.status,
          document_id: doc.id,
          title: doc.title,
          signer_name: doc.signer_name,
          signer_email: doc.signer_email,
          payload_hash: doc.payload_hash,
          signed_at: doc.signed_at,
          tsa_available: !!doc.tsa_ts,
          tsa_ts: doc.tsa_ts,
          tsa_serial: doc.tsa_serial,
          file_hash: doc.file_hash_sha256,
        });
      }

      default:
        return json({ error: "Unbekannte Aktion" }, 400);
    }
  } catch (err) {
    console.error("Edge Function Error:", err);
    return json({ error: "Interner Serverfehler" }, 500);
  }
});

// ── Hilfsfunktionen ─────────────────────────────────────────────
function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

// E-Mail via Supabase Auth OTP (Magic Link als OTP-Träger)
// In Produktion: Eigene E-Mail-Vorlage in Supabase Dashboard konfigurieren
async function sendOTPEmail(email: string, name: string, otp: string, docId: string, docTitle: string) {
  try {
    // Option A: Supabase Auth sendet OTP (erfordert Auth-User für den Unterzeichner)
    // Hier vereinfacht: Direkte E-Mail via Supabase SMTP oder Resend
    // Für Produktion: Resend / SendGrid einbinden

    console.log(`[DEV] OTP für ${email}: ${otp} (Dokument: ${docTitle})`);

    // Beispiel Resend-Integration (API-Key via Env-Variable):
    const RESEND_KEY = Deno.env.get("RESEND_API_KEY");
    if (RESEND_KEY) {
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${RESEND_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: "Signatuur <noreply@deine-domain.de>",
          to: [email],
          subject: `Ihr Signatur-Code für: ${docTitle}`,
          html: `
            <div style="font-family:Georgia,serif; max-width:480px; margin:0 auto; padding:32px;">
              <h2 style="color:#0d1117;">Signatuur</h2>
              <p>Hallo ${name},</p>
              <p>Sie wurden gebeten, das folgende Dokument elektronisch zu unterschreiben:</p>
              <p style="background:#f7f4ef; padding:12px; border-left:3px solid #c8a96e;">
                <strong>${docTitle}</strong>
              </p>
              <p>Ihr Bestätigungscode:</p>
              <div style="font-size:2rem; letter-spacing:0.2em; font-family:monospace; background:#0d1117; color:#c8a96e; padding:16px; text-align:center; border-radius:4px;">
                ${otp}
              </div>
              <p style="color:#888; font-size:0.85rem; margin-top:16px;">
                Dieser Code ist 15 Minuten gültig.<br/>
                Diese Signatur entspricht einer Fortgeschrittenen Elektronischen Signatur (FES) nach Art. 26 eIDAS.
              </p>
            </div>
          `,
        }),
      });
    }
  } catch (err) {
    console.error("E-Mail-Versand fehlgeschlagen:", err);
  }
}
