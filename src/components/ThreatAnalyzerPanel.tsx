import React, { useRef, useState } from 'react';
import {
  ImagePlus,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
} from 'lucide-react';
import type { Language } from '../lib/hardeningData';

export interface AnalysisHistoryItem {
  id: string;
  fileName: string;
  verdict: 'safe' | 'suspicious' | 'critical';
  headline: string;
  summary: string;
  indicators: string[];
  remediationSteps: string[];
  analyzedAtIso: string;
}

interface ThreatAnalyzerPanelProps {
  language: Language;
  analyses: AnalysisHistoryItem[];
  onAnalysisComplete: (item: AnalysisHistoryItem) => Promise<void>;
  suppressedApkCount: number;
  hardeningCompletedCount: number;
  hardeningTotalCount: number;
}

export const ThreatAnalyzerPanel: React.FC<ThreatAnalyzerPanelProps> = ({
  language,
  analyses,
  onAnalysisComplete,
  suppressedApkCount,
  hardeningCompletedCount,
  hardeningTotalCount,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<{
    name: string;
    mimeType: string;
    base64: string;
  } | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [latestResult, setLatestResult] = useState<AnalysisHistoryItem | null>(
    analyses[0] ?? null
  );

  const isHi = language === 'hi';

  const handleImagePick = (file: File | undefined) => {
    if (!file) return;
    setErrorMsg(null);
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result || '');
      setPreviewUrl(dataUrl);
      setSelectedFile({
        name: file.name,
        mimeType: file.type || 'image/png',
        base64: dataUrl,
      });
    };
    reader.readAsDataURL(file);
  };

  const handleAnalyze = async () => {
    if (!selectedFile) return;
    setLoading(true);
    setErrorMsg(null);

    try {
      const response = await fetch('/api/analyze-image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          imageBase64: selectedFile.base64,
          mimeType: selectedFile.mimeType,
          fileName: selectedFile.name,
          language,
        }),
      });

      const data = (await response.json()) as {
        error?: string;
        verdict?: 'safe' | 'suspicious' | 'critical';
        headline?: string;
        summary?: string;
        indicators?: string[];
        remediationSteps?: string[];
      };

      if (!response.ok) {
        throw new Error(data.error || `Server error (${response.status})`);
      }

      const record: AnalysisHistoryItem = {
        id: `scan_${Date.now()}`,
        fileName: selectedFile.name,
        verdict: data.verdict ?? 'suspicious',
        headline: data.headline ?? 'Analysis Complete',
        summary: data.summary ?? '',
        indicators: data.indicators ?? [],
        remediationSteps: data.remediationSteps ?? [],
        analyzedAtIso: new Date().toISOString(),
      };

      setLatestResult(record);
      await onAnalysisComplete(record);
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'Unable to analyze screenshot right now.'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadClearanceCard = () => {
    const canvas = document.createElement('canvas');
    canvas.width = 1200;
    canvas.height = 675;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.fillStyle = '#080C14';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.strokeStyle = '#1E293B';
    ctx.lineWidth = 2;
    ctx.strokeRect(36, 36, canvas.width - 72, canvas.height - 72);

    ctx.fillStyle = '#10B981';
    ctx.font = '600 22px "Plus Jakarta Sans", sans-serif';
    ctx.fillText('KAVACH MOBILE SECURITY CONSOLE', 76, 102);

    ctx.fillStyle = '#F8FAFC';
    ctx.font = '700 44px "Plus Jakarta Sans", sans-serif';
    ctx.fillText('Device Hygiene & APK Audit Summary', 76, 165);

    ctx.fillStyle = '#94A3B8';
    ctx.font = '400 20px "JetBrains Mono", monospace';
    ctx.fillText(`Generated: ${new Date().toLocaleString()}`, 76, 212);

    // Metric panels
    ctx.fillStyle = '#0F1623';
    ctx.fillRect(76, 260, 500, 170);
    ctx.strokeStyle = '#334155';
    ctx.strokeRect(76, 260, 500, 170);

    ctx.fillStyle = '#94A3B8';
    ctx.font = '500 18px "DM Sans", sans-serif';
    ctx.fillText('PERMANENTLY SUPPRESSED APKs', 104, 305);
    ctx.fillStyle = '#F8FAFC';
    ctx.font = '700 56px "JetBrains Mono", monospace';
    ctx.fillText(String(suppressedApkCount), 104, 385);

    ctx.fillStyle = '#0F1623';
    ctx.fillRect(624, 260, 500, 170);
    ctx.strokeStyle = '#334155';
    ctx.strokeRect(624, 260, 500, 170);

    ctx.fillStyle = '#94A3B8';
    ctx.font = '500 18px "DM Sans", sans-serif';
    ctx.fillText('ANTI-HACK HARDENING CHECKS', 652, 305);
    ctx.fillStyle = '#10B981';
    ctx.font = '700 56px "JetBrains Mono", monospace';
    ctx.fillText(`${hardeningCompletedCount} / ${hardeningTotalCount}`, 652, 385);

    ctx.fillStyle = '#CBD5E1';
    ctx.font = '400 20px "DM Sans", sans-serif';
    ctx.fillText(
      'Citizen Cyber Safety Reminders: Empty Android Trash · Block Unknown Apps · Helpline 1930',
      76,
      515
    );

    ctx.fillStyle = '#64748B';
    ctx.font = '400 17px "JetBrains Mono", monospace';
    ctx.fillText('cybercrime.gov.in  ·  sancharsaathi.gov.in  ·  Play Protect Verified', 76, 565);

    const link = document.createElement('a');
    link.download = `kavach-security-summary-${Date.now()}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
  };

  return (
    <div className="space-y-6">
      <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-5 sm:p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1">
            <h1 className="text-xl sm:text-2xl font-semibold text-slate-50">
              {isHi
                ? 'संदिग्ध स्क्रीनशॉट और फ़िशिंग एनालाइज़र'
                : 'Suspicious Screenshot & APK Threat Analyzer'}
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed max-w-2xl">
              {isHi
                ? 'किसी भी संदिग्ध WhatsApp/SMS APK लिंक, अनजान ऐप सेटिंग, या Play Protect चेतावनी का स्क्रीनशॉट अपलोड करें। यह सिस्टम तुरंत हैकिंग के संकेतों की पहचान कर हटाने के स्टेप्स बताएगा।'
                : 'Upload a mobile screenshot of any suspicious APK download, WhatsApp/SMS link, Accessibility prompt, or warning screen to inspect hacking indicators and get Android cleanup steps.'}
            </p>
          </div>

          <button
            type="button"
            onClick={handleDownloadClearanceCard}
            className="inline-flex items-center justify-center gap-2 min-h-[44px] px-4 py-2 rounded-lg bg-slate-800 text-slate-100 border border-slate-700 text-sm font-medium hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="w-4 h-4" />
            {isHi ? 'सिक्योरिटी रिपोर्ट डाउनलोड करें' : 'Export Audit Card (PNG)'}
          </button>
        </div>

        <input
          ref={fileInputRef}
          type="file"
          accept="image/png,image/jpeg,image/webp"
          className="hidden"
          onChange={(e) => handleImagePick(e.target.files?.[0])}
        />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Upload / Preview Column */}
          <div className="lg:col-span-5 space-y-4">
            <div
              onClick={() => fileInputRef.current?.click()}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
              }}
              className="border border-dashed border-slate-700 rounded-xl bg-[#080C14] p-4 min-h-[240px] flex flex-col items-center justify-center text-center cursor-pointer hover:border-emerald-500/70 transition-colors"
            >
              {previewUrl ? (
                <img
                  src={previewUrl}
                  alt="Uploaded security screenshot preview"
                  referrerPolicy="no-referrer"
                  className="max-h-72 w-auto rounded-lg object-contain"
                />
              ) : (
                <div className="space-y-2.5 py-6">
                  <div className="mx-auto w-11 h-11 rounded-lg bg-slate-800 flex items-center justify-center text-slate-300">
                    <ImagePlus className="w-5 h-5" />
                  </div>
                  <p className="text-sm font-medium text-slate-200">
                    {isHi ? 'स्क्रीनशॉट चुनने के लिए टैप करें' : 'Tap to upload mobile screenshot'}
                  </p>
                  <p className="text-xs text-slate-400">
                    PNG, JPG or WEBP
                  </p>
                </div>
              )}
            </div>

            <div className="flex flex-wrap gap-3">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="min-h-[44px] px-4 py-2 rounded-lg bg-slate-800 text-slate-100 border border-slate-700 text-sm font-medium hover:bg-slate-700 transition-colors flex-1"
              >
                {isHi ? 'दूसरी फ़ोटो चुनें' : 'Choose Image'}
              </button>
              <button
                type="button"
                disabled={!selectedFile || loading}
                onClick={() => void handleAnalyze()}
                className="inline-flex items-center justify-center gap-2 min-h-[44px] px-5 py-2 rounded-lg bg-emerald-500 text-slate-950 text-sm font-semibold hover:bg-emerald-400 transition-colors flex-1 disabled:opacity-50"
              >
                <ScanSearch className="w-4 h-4" />
                {loading
                  ? isHi
                    ? 'जांच जारी है...'
                    : 'Analyzing...'
                  : isHi
                    ? 'स्क्रीनशॉट जांचें'
                    : 'Analyze Threat'}
              </button>
            </div>

            {errorMsg && (
              <div className="p-3.5 rounded-lg bg-rose-950/40 border border-rose-800 text-xs text-rose-200 leading-relaxed">
                {errorMsg}
              </div>
            )}
          </div>

          {/* Analysis Result Column */}
          <div className="lg:col-span-7 bg-[#080C14] border border-slate-800 rounded-xl p-5 space-y-4">
            {!latestResult ? (
              <div className="py-12 text-center space-y-2">
                <p className="text-sm font-medium text-slate-300">
                  {isHi
                    ? 'अभी तक कोई स्क्रीनशॉट जांच नहीं हुई है'
                    : 'No screenshot analyzed yet'}
                </p>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  {isHi
                    ? 'बाईं ओर से अपने मोबाइल का स्क्रीनशॉट अपलोड करें और "स्क्रीनशॉट जांचें" दबाएं।'
                    : 'Upload a screenshot on the left and run "Analyze Threat" to inspect APK prompts or phishing risks.'}
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    {latestResult.verdict === 'critical' ? (
                      <ShieldAlert className="w-5 h-5 text-rose-400" />
                    ) : latestResult.verdict === 'safe' ? (
                      <ShieldCheck className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-amber-400" />
                    )}
                    <h2 className="text-base font-semibold text-slate-50">
                      {latestResult.headline}
                    </h2>
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    {latestResult.fileName}
                  </span>
                </div>

                <p className="text-sm text-slate-200 leading-relaxed">
                  {latestResult.summary}
                </p>

                {latestResult.indicators.length > 0 && (
                  <div className="space-y-1.5">
                    <h3 className="text-xs font-semibold text-slate-400">
                      {isHi ? 'मुख्य जोखिम संकेत' : 'Detected Risk Indicators'}
                    </h3>
                    <ul className="space-y-1 text-sm text-slate-300">
                      {latestResult.indicators.map((ind, idx) => (
                        <li key={idx}>• {ind}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {latestResult.remediationSteps.length > 0 && (
                  <div className="space-y-2 pt-2 border-t border-slate-800">
                    <h3 className="text-xs font-semibold text-emerald-400">
                      {isHi ? 'सुरक्षित करने के कदम' : 'Recommended Cleanup Steps'}
                    </h3>
                    <ol className="space-y-1.5 text-sm text-slate-200 list-decimal list-inside">
                      {latestResult.remediationSteps.map((step, idx) => (
                        <li key={idx} className="leading-relaxed">
                          {step}
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Previous Analyses History */}
      {analyses.length > 1 && (
        <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-slate-100">
            {isHi ? 'पिछली जांच का इतिहास' : 'Recent Screenshot Checks'}
          </h2>
          <div className="divide-y divide-slate-800/80">
            {analyses.slice(0, 6).map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setLatestResult(item)}
                className="w-full text-left py-3 flex items-center justify-between gap-4 hover:bg-slate-900/40 px-2 rounded-lg transition-colors"
              >
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-100 truncate">
                    {item.headline}
                  </p>
                  <p className="text-xs text-slate-400 font-mono truncate">
                    {item.fileName} · {new Date(item.analyzedAtIso).toLocaleString()}
                  </p>
                </div>
                <span
                  className={`text-xs font-semibold shrink-0 ${
                    item.verdict === 'critical'
                      ? 'text-rose-400'
                      : item.verdict === 'safe'
                        ? 'text-emerald-400'
                        : 'text-amber-400'
                  }`}
                >
                  {item.verdict.toUpperCase()}
                </span>
              </button>
            ))}
          </div>
        </section>
      )}
    </div>
  );
};
