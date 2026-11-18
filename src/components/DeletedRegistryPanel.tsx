import React, { useState } from 'react';
import { ShieldOff, Trash2 } from 'lucide-react';
import type { Language } from '../lib/hardeningData';
import { formatBytes, type DeletedApkRecord } from '../lib/apkScanner';

interface DeletedRegistryPanelProps {
  language: Language;
  deletedRecords: DeletedApkRecord[];
  onPurgeAllRecords: () => Promise<void>;
}

export const DeletedRegistryPanel: React.FC<DeletedRegistryPanelProps> = ({
  language,
  deletedRecords,
  onPurgeAllRecords,
}) => {
  const [confirmClear, setConfirmClear] = useState(false);
  const isHi = language === 'hi';

  return (
    <div className="space-y-6">
      <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-5 sm:p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1 max-w-2xl">
          <h1 className="text-xl sm:text-2xl font-semibold text-slate-50">
            {isHi
              ? 'परमानेंट डिलीट ब्लॉकलिस्ट (Suppression Vault)'
              : 'Permanent Deletion Suppression Registry'}
          </h1>
          <p className="text-sm text-slate-300 leading-relaxed">
            {isHi
              ? 'यहाँ केवल उन APK फ़ाइलों का क्रिप्टोग्राफिक रिकॉर्ड रहता है जिन्हें आपने परमानेंट डिलीट किया है। यह रिकॉर्ड सुनिश्चित करता है कि मुख्य स्कैनर में ये फ़ाइलें कभी वापस न दिखें।'
              : 'Audit log of permanently deleted APK SHA-256 fingerprints. Any file matching a fingerprint below is automatically hidden from the active scanner so it never reappears.'}
          </p>
        </div>

        {deletedRecords.length > 0 && (
          <button
            type="button"
            onClick={() => setConfirmClear(true)}
            className="inline-flex items-center justify-center gap-2 min-h-[44px] px-4 py-2 rounded-lg bg-slate-800 text-slate-200 border border-slate-700 text-sm font-medium hover:bg-rose-950/50 hover:border-rose-800 hover:text-rose-200 transition-colors whitespace-nowrap shrink-0"
          >
            <Trash2 className="w-4 h-4" />
            {isHi ? 'ऑडिट लॉग रीसेट करें' : 'Reset Audit Vault'}
          </button>
        )}
      </section>

      <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl overflow-hidden">
        {deletedRecords.length === 0 ? (
          <div className="p-10 text-center space-y-2.5">
            <div className="mx-auto w-11 h-11 rounded-xl bg-slate-800 flex items-center justify-center text-slate-400">
              <ShieldOff className="w-5 h-5" />
            </div>
            <p className="text-sm font-medium text-slate-200">
              {isHi ? 'अभी कोई डिलीट की गई APK दर्ज नहीं है' : 'Suppression registry is empty'}
            </p>
            <p className="text-xs text-slate-400">
              {isHi
                ? 'जब आप APK Scanner से कोई APK डिलीट करेंगे, तो उसका स्थायी ब्लॉकलिस्ट रिकॉर्ड यहाँ सुरक्षित रहेगा।'
                : 'Permanently deleted APKs from the scanner are recorded here by SHA-256 fingerprint.'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {deletedRecords.map((rec) => (
              <div
                key={rec.id}
                className="p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
              >
                <div className="space-y-1 min-w-0">
                  <div className="text-sm font-semibold text-slate-100 break-all">
                    {rec.fileName}
                  </div>
                  <div className="text-xs text-slate-400 font-mono flex flex-wrap gap-x-2 gap-y-1">
                    <span>SHA-256: {rec.sha256.slice(0, 18)}…</span>
                    <span aria-hidden="true">·</span>
                    <span>{rec.fileSize > 0 ? formatBytes(rec.fileSize) : 'Manual Entry'}</span>
                    <span aria-hidden="true">·</span>
                    <span>
                      {rec.deletionMethod === 'disk_removed'
                        ? isHi
                          ? 'डिस्क से हटाया गया'
                          : 'Erased from disk'
                        : isHi
                          ? 'स्थायी रूप से ब्लॉक'
                          : 'Permanently suppressed'}
                    </span>
                  </div>
                </div>

                <div className="text-xs font-mono tabular-nums text-slate-400 shrink-0">
                  {new Date(rec.deletedAtIso).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {confirmClear && (
        <div
          className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-end sm:items-center justify-center p-0 sm:p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full sm:max-w-md bg-[#0F1623] border border-slate-700 rounded-t-2xl sm:rounded-xl p-6 space-y-4">
            <h3 className="text-base font-semibold text-slate-100">
              {isHi ? 'सप्रेशन वॉल्ट खाली करें?' : 'Reset Suppression Registry?'}
            </h3>
            <p className="text-sm text-slate-300 leading-relaxed">
              {isHi
                ? 'सावधान: इसे रीसेट करने पर पहले से डिलीट की गई APKs यदि आपके फ़ोल्डर में मौजूद हैं तो दोबारा स्कैन में दिख सकती हैं।'
                : 'Clearing this audit vault stops suppressing previously deleted APKs if those files still exist on storage.'}
            </p>
            <div className="flex flex-col-reverse sm:flex-row sm:justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setConfirmClear(false)}
                className="min-h-[44px] px-4 py-2 rounded-lg bg-slate-800 text-slate-200 text-sm font-medium hover:bg-slate-700 transition-colors"
              >
                {isHi ? 'रद्द करें' : 'Cancel'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setConfirmClear(false);
                  void onPurgeAllRecords();
                }}
                className="min-h-[44px] px-4 py-2 rounded-lg bg-rose-600 text-white text-sm font-semibold hover:bg-rose-500 transition-colors"
              >
                {isHi ? 'हां, रीसेट करें' : 'Confirm Reset'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
