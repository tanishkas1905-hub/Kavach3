import React, { useState } from 'react';
import { Download, Smartphone, WifiOff, X } from 'lucide-react';
import { useOnlineStatus, usePWAInstall } from '../hooks/usePWAInstall';
import type { Language } from '../lib/hardeningData';

export const PWAInstallButton: React.FC<{ language: Language }> = ({
  language,
}) => {
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showGuide, setShowGuide] = useState(false);
  const isHi = language === 'hi';

  // Hide when already running in standalone installed mode
  if (isInstalled) {
    return null;
  }

  const handleClick = async () => {
    if (isInstallable) {
      const accepted = await install();
      if (!accepted) {
        setShowGuide(true);
      }
      return;
    }
    setShowGuide(true);
  };

  return (
    <>
      <button
        type="button"
        onClick={() => void handleClick()}
        className="inline-flex items-center gap-2 min-h-[38px] px-3 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-semibold hover:bg-emerald-500/25 transition-colors whitespace-nowrap shrink-0"
      >
        <Download className="w-3.5 h-3.5 shrink-0" />
        <span>
          {isHi ? 'फ़ोन में इंस्टॉल करें (PWA)' : 'Install App on Device'}
        </span>
      </button>

      {showGuide && (
        <div
          className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-end sm:items-center justify-center p-0 sm:p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full sm:max-w-md bg-[#0F1623] border border-slate-700 rounded-t-2xl sm:rounded-xl p-6 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5 text-emerald-400">
                <Smartphone className="w-5 h-5 shrink-0" />
                <h3 className="text-base font-semibold text-slate-100">
                  {isHi
                    ? 'Kavach को होम स्क्रीन पर इंस्टॉल करें'
                    : 'Install Kavach on Your Device'}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowGuide(false)}
                className="text-slate-400 hover:text-white p-1"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {isIOS ? (
              <ol className="text-sm text-slate-300 space-y-2 list-decimal list-inside leading-relaxed">
                <li>
                  {isHi
                    ? 'Safari के नीचे Share बटन पर टैप करें।'
                    : 'Tap the Share button in Safari.'}
                </li>
                <li>
                  {isHi
                    ? '"Add to Home Screen" चुनें और Add दबाएं।'
                    : 'Scroll down and tap "Add to Home Screen".'}
                </li>
              </ol>
            ) : (
              <ol className="text-sm text-slate-300 space-y-2 list-decimal list-inside leading-relaxed">
                <li>
                  {isHi
                    ? 'अगर नीचे पॉप-अप नहीं आया तो Chrome में ऊपर दाईं ओर ⋮ मेन्यू खोलें।'
                    : 'Open the browser menu (⋮ in Android Chrome or install icon in desktop address bar).'}
                </li>
                <li>
                  {isHi
                    ? '"Install app" या "Add to Home screen" चुनें।'
                    : 'Tap "Install app" or "Add to Home screen".'}
                </li>
                <li>
                  {isHi
                    ? 'नोट: अगर आप ऐप को प्रीव्यू फ्रेम के अंदर देख रहे हैं, तो पहले ऐप को सीधे टैब (Shared/App URL) में खोलें ताकि Chrome इंस्टॉल प्रॉम्प्ट दिखा सके।'
                    : 'Note: When viewing inside an embedded preview frame, open the standalone app URL in Chrome first to trigger native PWA install.'}
                </li>
              </ol>
            )}

            <button
              type="button"
              onClick={() => setShowGuide(false)}
              className="w-full min-h-[44px] rounded-lg bg-slate-800 text-slate-100 text-sm font-medium hover:bg-slate-700 transition-colors"
            >
              {isHi ? 'बंद करें' : 'Close'}
            </button>
          </div>
        </div>
      )}
    </>
  );
};

export const OfflineIndicator: React.FC<{ language: Language }> = ({
  language,
}) => {
  const isOnline = useOnlineStatus();
  if (isOnline) return null;

  return (
    <div className="fixed bottom-20 md:bottom-4 left-4 z-50 flex items-center gap-2 rounded-lg bg-amber-950/95 border border-amber-700 px-3.5 py-2 text-xs font-medium text-amber-100 shadow-lg">
      <WifiOff className="w-4 h-4 text-amber-400 shrink-0" />
      <span>
        {language === 'hi'
          ? 'ऑफ़लाइन मोड — कैश्ड सुरक्षा डेटा उपयोग हो रहा है'
          : 'Offline Mode — Cached scanner & vault active'}
      </span>
    </div>
  );
};
