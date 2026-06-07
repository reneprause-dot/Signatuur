# Signatuur — Produktiv-Setup Guide

## Übersicht

```
signatuur-pro/
├── index.html                          ← PWA Frontend
├── manifest.json                       ← PWA Manifest
├── sw.js                               ← Service Worker
├── icons/                              ← App Icons (selbst erstellen)
├── supabase/
│   ├── migrations/
│   │   └── 001_initial_schema.sql      ← Datenbankschema ausführen
│   └── functions/
│       └── sign-document/
│           └── index.ts                ← Edge Function deployen
└── SETUP.md                            ← Diese Datei
```

---

## 1. Supabase Projekt einrichten

### 1.1 Neues Projekt anlegen
1. https://app.supabase.com → "New Project"
2. Name: `signatuur`, Region: `eu-central-1` (Frankfurt) → DSGVO-konform
3. Starkes Datenbank-Passwort notieren

### 1.2 Schema ausführen
SQL Editor → New Query → Inhalt von `001_initial_schema.sql` einfügen → Run

### 1.3 Storage Buckets anlegen
Storage → New Bucket:
```
Name: documents-original   → Private ✓   Max Upload Size: 10MB
Name: documents-signed     → Private ✓   Max Upload Size: 15MB
```

Storage Policies für `documents-original`:
```sql
-- Nur Eigentümer darf hochladen
CREATE POLICY "Upload eigene Dokumente" ON storage.objects
  FOR INSERT WITH CHECK (
    bucket_id = 'documents-original'
    AND auth.uid()::text = (storage.foldername(name))[1]
  );

-- Nur Eigentümer darf lesen
CREATE POLICY "Lesen eigene Dokumente" ON storage.objects
  FOR SELECT USING (
    bucket_id = 'documents-original'
    AND auth.uid()::text = (storage.foldername(name))[1]
  );
```

### 1.4 Auth konfigurieren
Authentication → Settings:
- Site URL: `https://deine-domain.de`
- Redirect URLs: `https://deine-domain.de/*`
- Email Confirmations: ✓ aktiviert
- Custom SMTP (Resend/SendGrid empfohlen für Produktiv)

---

## 2. Edge Function deployen

### 2.1 Supabase CLI installieren
```bash
npm install -g supabase
supabase login
supabase link --project-ref DEIN-PROJECT-REF
```

### 2.2 Edge Function deployen
```bash
supabase functions deploy sign-document --no-verify-jwt
```

### 2.3 Secrets setzen
```bash
supabase secrets set ENVIRONMENT=production
supabase secrets set RESEND_API_KEY=re_xxxxxxxxxxxx
# Optional: eigene SMTP-Config
```

### 2.4 CORS für deine Domain konfigurieren
In `sign-document/index.ts` den CORS-Header anpassen:
```typescript
const corsHeaders = {
  "Access-Control-Allow-Origin": "https://deine-domain.de",
  ...
};
```

---

## 3. Frontend konfigurieren

In `index.html` die Zeilen 3-5 im `<script>` Block anpassen:
```javascript
const SUPABASE_URL  = 'https://DEIN-PROJEKT-REF.supabase.co';
const SUPABASE_ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // anon key
const EDGE_FN_URL   = `${SUPABASE_URL}/functions/v1/sign-document`;
```

**Supabase-Keys findest du:** Settings → API → Project URL & anon public key

---

## 4. E-Mail-Versand (Resend)

### 4.1 Resend einrichten
1. https://resend.com → Konto erstellen
2. Domain verifizieren (DNS TXT + MX Records)
3. API Key erstellen → in Supabase Secrets speichern

### 4.2 E-Mail-Template anpassen
In `sign-document/index.ts`, Funktion `sendOTPEmail()`:
```typescript
from: "Signatuur <noreply@deine-domain.de>",
```

### 4.3 Alternativ: Supabase eigener E-Mail-Versand
Authentication → Email Templates → anpassen
(Kostenlos, aber begrenzt auf 3 E-Mails/Stunde im Free-Tier)

---

## 5. Deployment (Frontend)

### Option A: Netlify (empfohlen)
```bash
# Einfach den Ordner auf netlify.com ziehen
# oder via CLI:
npm install -g netlify-cli
netlify deploy --prod --dir .
```

`netlify.toml` erstellen:
```toml
[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200
```

### Option B: Vercel
```bash
npm install -g vercel
vercel --prod
```

### Option C: Supabase selbst (Storage + CDN)
```bash
supabase storage cp index.html  ss:///public-site/index.html
supabase storage cp manifest.json ss:///public-site/manifest.json
supabase storage cp sw.js ss:///public-site/sw.js
```

---

## 6. Icons erstellen

Benötigte Größen (alle quadratisch, PNG):
```
icons/icon-72.png
icons/icon-96.png
icons/icon-128.png
icons/icon-144.png
icons/icon-192.png   ← wichtigste Größe
icons/icon-512.png   ← App Stores
```

Tool: https://realfavicongenerator.net → Upload Logo → Download-Paket

---

## 7. Sectigo TSA testen

Die Edge Function ruft automatisch `https://timestamp.sectigo.com` auf.

Test in der Browser-Konsole:
```javascript
// Zeitstempel-Response prüfen
const res = await fetch('https://timestamp.sectigo.com', {
  method: 'POST',
  headers: { 'Content-Type': 'application/timestamp-query' },
  body: new Uint8Array([/* TSQ bytes */])
});
console.log(res.status); // 200 = OK
```

**Sectigo TSA Limits:** Kostenlos, keine harte Rate-Limit-Grenze (fair use)
**Fallback:** Falls TSA nicht erreichbar, wird die Signatur ohne TSA-Token gespeichert
→ In production: Retry-Logik + Alert implementieren

---

## 8. pg_cron für automatisches Ablaufen aktivieren

Supabase Dashboard → Database → Extensions → `pg_cron` aktivieren

Dann im SQL Editor:
```sql
SELECT cron.schedule(
  'expire-documents',
  '0 * * * *',  -- Jede Stunde
  $$
    UPDATE public.documents
    SET status = 'expired'
    WHERE status IN ('pending_otp', 'pending_sign')
    AND expires_at < NOW();
  $$
);
```

---

## 9. Sicherheits-Checkliste vor Go-Live

- [ ] Supabase RLS aktiviert und getestet
- [ ] CORS auf eigene Domain beschränkt
- [ ] SUPABASE_SERVICE_ROLE_KEY niemals im Frontend
- [ ] RESEND_API_KEY als Supabase Secret (nicht in Code)
- [ ] HTTPS erzwungen (Netlify/Vercel machen das automatisch)
- [ ] Datenschutzerklärung verlinkt
- [ ] AGB verlinkt
- [ ] Impressum vorhanden
- [ ] Cookie-Banner (falls Analytics)
- [ ] E-Mail-Bestätigung bei Registrierung aktiviert
- [ ] Passwort-Reset-Flow getestet
- [ ] PDF-Upload-Größe serverseitig limitiert
- [ ] Rate-Limiting für Edge Functions (Supabase Dashboard)
- [ ] Error-Monitoring eingerichtet (z.B. Sentry)

---

## 10. Rechtliche Dokumente (Templates)

**Datenschutzerklärung** muss enthalten:
- Verantwortlicher (Name, Anschrift)
- Zweck: Signaturverarbeitung, Audit-Trail
- Rechtsgrundlage: Art. 6 Abs. 1 lit. b DSGVO (Vertragserfüllung)
- Speicherdauer: 10 Jahre (§ 147 AO)
- Auftragsverarbeiter: Supabase Inc. (USA → SCCs erforderlich!)
- Betroffenenrechte (Art. 15–22 DSGVO)

**Supabase DPA (Data Processing Agreement):**
https://supabase.com/privacy → "Data Processing Addendum" herunterladen und unterzeichnen

**Sectigo TSA:**
Kein DPA notwendig (öffentlicher Zeitstempeldienst, keine personenbezogenen Daten)

---

## Support & Weiterentwicklung

### Mögliche Erweiterungen:
- **QES-Integration:** D-Trust, Bundesdruckerei API
- **Mehrfach-Unterzeichner:** Workflow-Engine
- **Webhook:** POST an dein System nach Signierung
- **API:** REST-API für externe Systeme
- **White-Label:** Custom Domain + Logo pro Kunde
- **Push-Notifications:** Erinnerungen für ausstehende Signaturen
