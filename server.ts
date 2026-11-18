import 'dotenv/config';
import express from 'express';
import type { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

function createGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY is not configured in the server environment.');
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '15mb' }));

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ ok: true, service: 'kavach-security-console' });
  });

  app.post('/api/analyze-image', async (req: Request, res: Response) => {
    try {
      const { imageBase64, mimeType, fileName, language } = req.body as {
        imageBase64?: string;
        mimeType?: string;
        fileName?: string;
        language?: 'en' | 'hi';
      };

      if (!imageBase64 || typeof imageBase64 !== 'string') {
        res.status(400).json({ error: 'Image data is required.' });
        return;
      }

      const allowedMimeTypes = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'];
      const safeMimeType =
        mimeType && allowedMimeTypes.includes(mimeType) ? mimeType : 'image/png';

      const cleanBase64 = imageBase64.includes(',')
        ? imageBase64.split(',')[1]
        : imageBase64;

      const langLabel = language === 'hi' ? 'Hindi (Devanagari script)' : 'English';
      const ai = createGeminiClient();

      const promptText = `You are a mobile cybersecurity analyst assisting a smartphone user with Android APK malware removal and anti-hacking defense.
Inspect the uploaded mobile screenshot (file name: ${fileName || 'screenshot.png'}).
Identify whether this screenshot shows:
- Downloaded or sideloaded .apk / .xapk files
- Phishing SMS/WhatsApp/Telegram links pushing malicious APKs (e.g., fake bank KYC, e-challan, loan, Aadhaar, reward, or mod APKs)
- Dangerous Android permissions (Accessibility Services, Device Admin, Install Unknown Apps, Overlay permission)
- Google Play Protect warnings or active device compromise indicators

Respond strictly in ${langLabel} for headline, summary, indicators, and remediationSteps.
Keep remediationSteps concrete, safe, and directly actionable on an Android phone (including permanently deleting APK files and emptying Trash).`;

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: {
          parts: [
            {
              inlineData: {
                mimeType: safeMimeType,
                data: cleanBase64,
              },
            },
            {
              text: promptText,
            },
          ],
        },
        config: {
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              verdict: {
                type: Type.STRING,
                description: 'Must be one of: safe, suspicious, critical',
              },
              headline: {
                type: Type.STRING,
                description: 'Short 1-line assessment title in requested language.',
              },
              summary: {
                type: Type.STRING,
                description: 'Concise 2-3 sentence explanation of what is visible and the security risk.',
              },
              indicators: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: 'Specific risk indicators or observations spotted in the screenshot.',
              },
              remediationSteps: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
                description: 'Ordered Android steps to remove threats and prevent hacking.',
              },
            },
            required: ['verdict', 'headline', 'summary', 'indicators', 'remediationSteps'],
          },
        },
      });

      const rawText = (response.text ?? '{}').trim();
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(rawText) as Record<string, unknown>;
      } catch {
        res.status(502).json({
          error: 'Failed to parse model response.',
          details: rawText.slice(0, 300),
        });
        return;
      }

      const rawVerdict = String(parsed.verdict ?? 'suspicious').toLowerCase();
      const verdict =
        rawVerdict === 'safe' || rawVerdict === 'critical' ? rawVerdict : 'suspicious';

      res.json({
        verdict,
        headline: String(parsed.headline ?? 'Screenshot Analyzed'),
        summary: String(parsed.summary ?? ''),
        indicators: Array.isArray(parsed.indicators)
          ? parsed.indicators.map(String).slice(0, 8)
          : [],
        remediationSteps: Array.isArray(parsed.remediationSteps)
          ? parsed.remediationSteps.map(String).slice(0, 8)
          : [],
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unexpected server error';
      const status = message.includes('GEMINI_API_KEY')
        ? 500
        : message.includes('PERMISSION_DENIED') || message.includes('403')
          ? 403
          : message.includes('RESOURCE_EXHAUSTED') || message.includes('429')
            ? 429
            : 500;
      res.status(status).json({ error: message });
    }
  });

  if (!isProduction) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Kavach Security Console running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
