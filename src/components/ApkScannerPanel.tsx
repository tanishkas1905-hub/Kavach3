import React, { useRef, useState } from 'react';
import {
  FolderSearch,
  FileUp,
  Trash2,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Plus,
  Smartphone,
  CheckCircle2,
  X,
  AppWindow,
  Link2,
  MessageSquareWarning,
  PhoneIncoming,
} from 'lucide-react';
import type { Language } from '../lib/hardeningData';
import {
  analyzeLocalApkFile,
  analyzeSmsOrCallInput,
  analyzeSuspiciousLink,
  auditInstalledPackageList,
  createManualApkEntry,
  formatBytes,
  inspectApkArchiveBuffer,
  isApkFileName,
  isApkSuppressed,
  isSuspiciousPayloadFileName,
  scanDirectoryHandleForApks,
  type DeletedApkRecord,
  type PackageAuditResult,
  type ScannedApkItem,
} from '../lib/apkScanner';

interface ApkScannerPanelProps {
  language: Language;
  activeApks: ScannedApkItem[];
  deletedRecords: DeletedApkRecord[];
  onAddScannedApks: (items: ScannedApkItem[], suppressedSkipped: number, visitedFiles: number) => void;
  onPermanentlyDeleteApk: (item: ScannedApkItem) => Promise<{ diskRemoved: boolean; error?: string }>;
  onDeleteAllApks: () => Promise<void>;
  lastScanStats: { visitedFiles: number; suppressedSkipped: number; scannedAt: string | null };
  onOpenHardening: () => void;
  onOpenAnalyzer: () => void;
}

export const ApkScannerPanel: React.FC<ApkScannerPanelProps> = ({
  language,
  activeApks,
  deletedRecords,
  onAddScannedApks,
  onPermanentlyDeleteApk,
  onDeleteAllApks,
  lastScanStats,
  onOpenHardening,
  onOpenAnalyzer,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderFallbackRef = useRef<HTMLInputElement>(null);

  const [scanMode, setScanMode] = useState<'files' | 'apps' | 'links' | 'sms' | 'calls'>('files');
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);
  const [manualName, setManualName] = useState('');
  const [manualPath, setManualPath] = useState('/Download/');
  const [appAuditText, setAppAuditText] = useState('');
  const [appAuditResults, setAppAuditResults] = useState<PackageAuditResult[] | null>(null);
  const [linkInput, setLinkInput] = useState('');
  const [smsInput, setSmsInput] = useState('');
  const [callInput, setCallInput] = useState('');
  const [pendingDelete, setPendingDelete] = useState<ScannedApkItem | null>(null);
  const [confirmDeleteAll, setConfirmDeleteAll] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const isHi = language === 'hi';
  const supportsDirectoryPicker =
    typeof window !== 'undefined' && 'showDirectoryPicker' in window;

  const handleDirectoryScan = async () => {
    setScanError(null);
    setStatusNotice(null);

    if (!supportsDirectoryPicker) {
      folderFallbackRef.current?.click();
      return;
    }

    try {
      setScanning(true);
      const picker = (
        window as unknown as {
          showDirectoryPicker: (opts?: { mode?: 'read' | 'readwrite' }) => Promise<FileSystemDirectoryHandle>;
        }
      ).showDirectoryPicker;

      let dirHandle: FileSystemDirectoryHandle;
      try {
        dirHandle = await picker({ mode: 'readwrite' });
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') {
          setScanning(false);
          return;
        }
        dirHandle = await picker({ mode: 'read' });
      }

      const result = await scanDirectoryHandleForApks(dirHandle, deletedRecords);
      onAddScannedApks(result.items, result.suppressedCount, result.totalFilesVisited);

      if (result.items.length === 0) {
        setStatusNotice(
          isHi
            ? `कुल ${result.totalFilesVisited} फ़ाइलों (सभी प्रकार) की जांच पूरी हुई। कोई सक्रिय APK या संदिग्ध बाइनरी नहीं मिली${result.suppressedCount > 0 ? ` (${result.suppressedCount} पहले से डिलीट की गई APK को छिपाया गया)` : ''}।`
            : `Deep-scanned ${result.totalFilesVisited} total file(s). No active APKs or disguised binaries found${result.suppressedCount > 0 ? ` (${result.suppressedCount} permanently deleted APK suppressed)` : ''}.`
        );
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        return;
      }
      folderFallbackRef.current?.click();
    } finally {
      setScanning(false);
    }
  };

  const handleFilesSelected = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setScanError(null);
    setStatusNotice(null);
    setScanning(true);

    try {
      const scanned: ScannedApkItem[] = [];
      let suppressedCount = 0;
      let visited = 0;

      for (const file of Array.from(files)) {
        visited++;
        const hasApkExt = isApkFileName(file.name);
        const hasPayloadExt = isSuspiciousPayloadFileName(file.name);

        let isDisguisedApk = false;
        if (!hasApkExt && !hasPayloadExt && file.size > 64 && file.size <= 80 * 1024 * 1024) {
          const headerSlice = new Uint8Array(await file.slice(0, 4).arrayBuffer());
          if (
            headerSlice[0] === 0x50 &&
            headerSlice[1] === 0x4b &&
            headerSlice[2] === 0x03 &&
            headerSlice[3] === 0x04
          ) {
            const fullBuf = await file.arrayBuffer();
            const archiveCheck = inspectApkArchiveBuffer(fullBuf);
            if (archiveCheck.hasManifest || archiveCheck.hasDex) {
              isDisguisedApk = true;
            }
          }
        }

        if (!hasApkExt && !hasPayloadExt && !isDisguisedApk) {
          continue;
        }

        const relPath =
          (file as File & { webkitRelativePath?: string }).webkitRelativePath ||
          `/Download/${file.name}`;
        const analyzed = await analyzeLocalApkFile(file, relPath, 'file_picker');
        if (isDisguisedApk) {
          analyzed.riskLevel = 'critical';
          analyzed.packageHint = 'Disguised APK Binary';
          analyzed.findings = [
            'Renamed file hides an AndroidManifest.xml / DEX executable archive inside a non-APK extension',
            ...analyzed.findings,
          ];
        } else if (hasPayloadExt && !hasApkExt) {
          analyzed.packageHint = 'Executable / Script Payload';
        }

        if (isApkSuppressed(analyzed, deletedRecords)) {
          suppressedCount++;
        } else {
          scanned.push(analyzed);
        }
      }

      onAddScannedApks(scanned, suppressedCount, visited);

      if (scanned.length === 0) {
        setStatusNotice(
          isHi
            ? `कुल ${visited} फ़ाइलों की जांच के बाद कोई नई संदिग्ध या APK फ़ाइल नहीं दिखी${suppressedCount > 0 ? ` (${suppressedCount} परमानेंट डिलीट की गई APK वापस नहीं दिखाई गई)` : ''}।`
            : `Deep-scanned ${visited} file(s). No active APKs or disguised binaries shown${suppressedCount > 0 ? ` (${suppressedCount} permanently deleted APK suppressed)` : ''}.`
        );
      }
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Failed to inspect selected files.');
    } finally {
      setScanning(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
      if (folderFallbackRef.current) folderFallbackRef.current.value = '';
    }
  };

  const handleManualAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanError(null);
    setStatusNotice(null);

    if (!manualName.trim()) return;
    const item = await createManualApkEntry(manualName, manualPath);

    if (isApkSuppressed(item, deletedRecords)) {
      setStatusNotice(
        isHi
          ? `"${item.fileName}" पहले ही परमानेंटली डिलीट की जा चुकी है, इसलिए इसे वापस नहीं दिखाया जाएगा।`
          : `"${item.fileName}" is already permanently deleted and suppressed — it will not be shown again.`
      );
      setManualName('');
      return;
    }

    onAddScannedApks([item], 0, 1);
    setManualName('');
  };

  const handleRunAppAudit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!appAuditText.trim()) return;
    const flagged = auditInstalledPackageList(appAuditText);
    setAppAuditResults(flagged);
  };

  const handleFlagPackageToQuarantine = async (pkgName: string) => {
    const item = await createManualApkEntry(pkgName, '/data/app/');
    item.category = 'app';
    item.packageHint = 'Category: App';
    if (!isApkSuppressed(item, deletedRecords)) {
      onAddScannedApks([item], 0, 1);
    }
  };

  const handleScanLinks = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanError(null);
    setStatusNotice(null);
    if (!linkInput.trim()) return;
    const candidates = await analyzeSuspiciousLink(linkInput);
    const unsuppressed = candidates.filter((c) => !isApkSuppressed(c, deletedRecords));
    const skipped = candidates.length - unsuppressed.length;
    onAddScannedApks(unsuppressed, skipped, candidates.length);
    setLinkInput('');
    if (unsuppressed.length === 0 && skipped > 0) {
      setStatusNotice(
        isHi
          ? `${skipped} लिंक पहले से परमानेंट डिलीट और ब्लॉकलिस्ट हैं, इसलिए वापस नहीं दिखाए गए।`
          : `${skipped} link(s) already permanently suppressed and will not be shown again.`
      );
    }
  };

  const handleScanSmsOrCall = async (e: React.FormEvent, mode: 'sms' | 'call') => {
    e.preventDefault();
    setScanError(null);
    setStatusNotice(null);
    const raw = mode === 'sms' ? smsInput : callInput;
    if (!raw.trim()) return;
    const candidates = await analyzeSmsOrCallInput(raw, mode);
    const unsuppressed = candidates.filter((c) => !isApkSuppressed(c, deletedRecords));
    const skipped = candidates.length - unsuppressed.length;
    onAddScannedApks(unsuppressed, skipped, candidates.length);
    if (mode === 'sms') setSmsInput('');
    else setCallInput('');
    if (unsuppressed.length === 0 && skipped > 0) {
      setStatusNotice(
        isHi
          ? `${skipped} प्रविष्टियाँ पहले ही डिलीट और ब्लॉक की जा चुकी हैं।`
          : `${skipped} entry/entries already permanently deleted and suppressed.`
      );
    }
  };

  const confirmAndDeleteSingle = async () => {
    if (!pendingDelete) return;
    setDeletingId(pendingDelete.id);
    setScanError(null);

    const res = await onPermanentlyDeleteApk(pendingDelete);
    setDeletingId(null);

    if (res.error) {
      setScanError(res.error);
    }

    setStatusNotice(
      res.diskRemoved
        ? isHi
          ? `"${pendingDelete.fileName}" को स्टोरेज से हमेशा के लिए डिलीट कर दिया गया है और ब्लॉकलिस्ट में जोड़ दिया गया है। अब यह दोबारा कभी नहीं दिखेगी।`
          : `"${pendingDelete.fileName}" was erased from disk and permanently suppressed. It will never appear again.`
        : isHi
          ? `"${pendingDelete.fileName}" को कंसोल से हमेशा के लिए हटाकर ब्लॉकलिस्ट में सेव कर दिया गया है। अपने फोन के Files -> Trash से भी Empty Trash ज़रूर करें।`
          : `"${pendingDelete.fileName}" was permanently removed and suppressed from all future scans. Also empty Files -> Trash on Android if present.`
    );
    setPendingDelete(null);
  };

  const handleBatchDelete = async () => {
    setConfirmDeleteAll(false);
    await onDeleteAllApks();
    setStatusNotice(
      isHi
        ? 'सभी सक्रिय APK फ़ाइलें परमानेंटली डिलीट और ब्लॉकलिस्ट कर दी गई हैं। अब ये वापस नहीं दिखेंगी।'
        : 'All active APK files were permanently deleted and suppressed. They will not reappear.'
    );
  };

  return (
    <div className="space-y-6">
      {/* Hidden inputs for mobile/browser compatibility */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={(e) => void handleFilesSelected(e.target.files)}
      />
      <input
        ref={folderFallbackRef}
        type="file"
        multiple
        {...({ webkitdirectory: '', directory: '' } as React.InputHTMLAttributes<HTMLInputElement>)}
        className="hidden"
        onChange={(e) => void handleFilesSelected(e.target.files)}
      />

      {/* Primary Action Strip */}
      <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-5 sm:p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5">
          <div className="space-y-1.5 max-w-2xl">
            <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-slate-50 [text-wrap:balance]">
              {isHi
                ? 'मोबाइल सभी फ़ाइलें, APK स्कैनर और परमानेंट डिलीट वॉल्ट'
                : 'Device All-Files Scanner, APK Inspector & Permanent Vault'}
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed">
              {isHi
                ? 'डिवाइस के किसी भी फ़ोल्डर की सभी फ़ाइलें (छुपे या रीनेम किए गए APK सहित) स्कैन करें। डिलीट करने पर वह APK हमेशा के लिए ब्लॉकलिस्ट हो जाती है और दोबारा कभी नहीं दिखती।'
                : 'Deep-scan all files in a storage folder (including .apk/.xapk/.apks, scripts, and disguised APK binaries). Any permanently deleted APK is suppressed forever and never shown again.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => void handleDirectoryScan()}
              disabled={scanning}
              className="inline-flex items-center justify-center gap-2 min-h-[44px] px-4 py-2.5 rounded-lg bg-emerald-500 text-slate-950 font-semibold text-sm hover:bg-emerald-400 active:scale-[0.99] transition-all whitespace-nowrap shrink-0 disabled:opacity-60"
            >
              <FolderSearch className="w-4 h-4" />
              {scanning
                ? isHi
                  ? 'स्कैन हो रहा है...'
                  : 'Scanning...'
                : isHi
                  ? 'सभी फ़ाइलें स्कैन करें'
                  : 'Scan All Device Files'}
            </button>

            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              disabled={scanning}
              className="inline-flex items-center justify-center gap-2 min-h-[44px] px-4 py-2.5 rounded-lg bg-slate-800 text-slate-100 border border-slate-700 font-medium text-sm hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0 disabled:opacity-60"
            >
              <FileUp className="w-4 h-4" />
              {isHi ? 'फ़ाइलें चुनकर जांचें' : 'Select Files / APKs'}
            </button>
          </div>
        </div>

        {/* Android browser capability note */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-400">
          <div className="flex items-start sm:items-center gap-2">
            <Smartphone className="w-4 h-4 text-slate-400 shrink-0 mt-0.5 sm:mt-0" />
            <span>
              {isHi
                ? 'Android ब्राउज़र सुरक्षा सैंडबॉक्स के कारण सभी इंस्टॉल किए गए ऐप्स को सीधे पढ़ने की अनुमति नहीं देता — नीचे दिए गए App Audit या Screenshot Analyzer से सभी ऐप्स भी जांचें।'
                : 'Browsers sandbox installed OS apps for privacy. Use "Scan All Device Files" for storage files, plus the Installed Apps Audit or Screenshot Analyzer below for installed apps.'}
            </span>
          </div>
          <button
            type="button"
            onClick={onOpenHardening}
            className="text-emerald-400 hover:text-emerald-300 font-medium underline underline-offset-4 whitespace-nowrap shrink-0 self-start sm:self-auto"
          >
            {isHi ? 'Android हटाने के स्टेप्स देखें' : 'View Android Cleanup Steps'}
          </button>
        </div>
      </section>

      {/* Unified Mobile Threat Scanner Mode Selector (Files, Apps, Links, SMS, Calls) */}
      <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-5 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-1">
            <h2 className="text-sm font-semibold text-slate-100">
              {isHi
                ? 'मोबाइल स्कैन श्रेणी चुनें (Files · Apps · Link · Call · SMS)'
                : 'Scan Mobile Surfaces (Files · Apps · Links · Calls · SMS)'}
            </h2>
            <p className="text-xs text-slate-400">
              {isHi
                ? 'जांचने के लिए नीचे टैब चुनें—हर स्कैन की गई फ़ाइल, ऐप, लिंक, SMS या कॉल को परमानेंट डिलीट और ब्लॉक करने का विकल्प मिलेगा।'
                : 'Select a category below to scan and queue unwanted items with a permanent delete & suppression option.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1 p-1 bg-[#080C14] border border-slate-800 rounded-lg">
            <button
              type="button"
              onClick={() => setScanMode('files')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                scanMode === 'files'
                  ? 'bg-emerald-500 text-slate-950 font-semibold'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              {isHi ? 'फ़ाइलें / APK' : 'Files / APK'}
            </button>
            <button
              type="button"
              onClick={() => setScanMode('apps')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                scanMode === 'apps'
                  ? 'bg-emerald-500 text-slate-950 font-semibold'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              {isHi ? 'ऐप्स' : 'Apps'}
            </button>
            <button
              type="button"
              onClick={() => setScanMode('links')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                scanMode === 'links'
                  ? 'bg-emerald-500 text-slate-950 font-semibold'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              {isHi ? 'लिंक (URL)' : 'Links'}
            </button>
            <button
              type="button"
              onClick={() => setScanMode('sms')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                scanMode === 'sms'
                  ? 'bg-emerald-500 text-slate-950 font-semibold'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              SMS
            </button>
            <button
              type="button"
              onClick={() => setScanMode('calls')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                scanMode === 'calls'
                  ? 'bg-emerald-500 text-slate-950 font-semibold'
                  : 'text-slate-300 hover:text-white'
              }`}
            >
              {isHi ? 'कॉल' : 'Calls'}
            </button>
          </div>
        </div>

        {scanMode === 'files' && (
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pt-2 border-t border-slate-800/80">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-slate-100">
                {isHi
                  ? 'यदि कोई APK पहले से शो कर रहा है तो उसे यहाँ डालकर परमानेंट डिलीट करें'
                  : 'Quarantine & Permanently Suppress a Visible APK'}
              </h3>
              <p className="text-xs text-slate-400">
                {isHi
                  ? 'अगर मोबाइल या कंसोल में कोई APK फ़ाइल दिख रही है (जैसे update.apk), तो उसका नाम लिखें ताकि डिलीट बटन मिले और वह हमेशा के लिए हट जाए।'
                  : 'If another console or your Android Downloads list shows an APK filename, add it below to quarantine, remove, and permanently block it.'}
              </p>
            </div>

            <form onSubmit={(e) => void handleManualAdd(e)} className="flex flex-col sm:flex-row gap-2.5 w-full md:w-auto">
              <input
                type="text"
                value={manualName}
                onChange={(e) => setManualName(e.target.value)}
                placeholder={isHi ? 'उदा. bank_kyc_update.apk' : 'e.g. bank_kyc_update.apk'}
                aria-label="APK filename"
                className="min-h-[44px] px-3.5 py-2 rounded-lg bg-[#080C14] border border-slate-700/90 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500 w-full sm:w-60"
              />
              <input
                type="text"
                value={manualPath}
                onChange={(e) => setManualPath(e.target.value)}
                placeholder="/Download/"
                aria-label="Folder path"
                className="min-h-[44px] px-3.5 py-2 rounded-lg bg-[#080C14] border border-slate-700/90 text-sm font-mono text-slate-300 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500 w-full sm:w-40"
              />
              <button
                type="submit"
                className="inline-flex items-center justify-center gap-1.5 min-h-[44px] px-4 py-2 rounded-lg bg-slate-100 text-slate-950 font-semibold text-sm hover:bg-white transition-colors whitespace-nowrap shrink-0"
              >
                <Plus className="w-4 h-4" />
                {isHi ? 'जोड़ें' : 'Add to Queue'}
              </button>
            </form>
          </div>
        )}

        {scanMode === 'apps' && (
          <div className="space-y-4 pt-2 border-t border-slate-800/80">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <AppWindow className="w-4 h-4 text-emerald-400 shrink-0" />
                  <h3 className="text-sm font-semibold text-slate-100">
                    {isHi
                      ? 'इंस्टॉल किए गए ऐप्स की जांच (App & Package Audit)'
                      : 'Installed Apps & Package Name Audit'}
                  </h3>
                </div>
                <p className="text-xs text-slate-400">
                  {isHi
                    ? 'फोन के Settings -> Apps से ऐप नाम या package IDs यहाँ पेस्ट करें (या Apps स्क्रीनशॉट की जांच करें)।'
                    : 'Paste app names or Android package IDs (e.g. from Settings -> Apps or ADB) to flag and permanently quarantine risky apps.'}
                </p>
              </div>
              <button
                type="button"
                onClick={onOpenAnalyzer}
                className="text-xs font-medium text-emerald-400 hover:text-emerald-300 underline underline-offset-4 whitespace-nowrap shrink-0 self-start sm:self-auto"
              >
                {isHi ? 'Apps स्क्रीनशॉट जांचें' : 'Analyze Apps Screenshot'}
              </button>
            </div>

            <form onSubmit={handleRunAppAudit} className="space-y-3">
              <textarea
                rows={2}
                value={appAuditText}
                onChange={(e) => setAppAuditText(e.target.value)}
                placeholder={
                  isHi
                    ? 'ऐप नाम या पैकेज आईडी लिखें (उदा. com.bank.kyc_update, AnyDesk, gbwhatsapp)...'
                    : 'Paste app names or package IDs (e.g. com.bank.kyc_update, AnyDesk, gbwhatsapp)...'
                }
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#080C14] border border-slate-700/90 text-sm font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <div className="flex flex-wrap items-center justify-between gap-3">
                <button
                  type="submit"
                  className="inline-flex items-center justify-center gap-2 min-h-[44px] px-4 py-2 rounded-lg bg-slate-800 text-slate-100 border border-slate-700 text-sm font-medium hover:bg-slate-700 transition-colors"
                >
                  {isHi ? 'ऐप लिस्ट जांचें' : 'Audit App List'}
                </button>
                {appAuditResults !== null && (
                  <span className="text-xs text-slate-400 tabular-nums">
                    {appAuditResults.length}{' '}
                    {isHi ? 'संदिग्ध ऐप संकेत मिले' : 'flagged app indicator(s)'}
                  </span>
                )}
              </div>
            </form>

            {appAuditResults !== null && appAuditResults.length > 0 && (
              <div className="divide-y divide-slate-800/80 border border-slate-800 rounded-lg bg-[#080C14]">
                {appAuditResults.map((res) => (
                  <div
                    key={res.packageName}
                    className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="space-y-0.5 min-w-0">
                      <div className="text-sm font-mono font-semibold text-rose-300 break-all">
                        {res.packageName}
                      </div>
                      <div className="text-xs text-slate-300">{res.reason}</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => void handleFlagPackageToQuarantine(res.packageName)}
                      className="min-h-[40px] px-3 py-1.5 rounded-lg bg-rose-600/20 border border-rose-500/40 text-rose-200 text-xs font-semibold hover:bg-rose-600/30 transition-colors whitespace-nowrap shrink-0"
                    >
                      {isHi ? 'डिलीट लिस्ट में डालें' : 'Queue for Permanent Delete'}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {scanMode === 'links' && (
          <form onSubmit={(e) => void handleScanLinks(e)} className="space-y-3 pt-2 border-t border-slate-800/80">
            <div className="flex items-center gap-2">
              <Link2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <h3 className="text-sm font-semibold text-slate-100">
                {isHi ? 'संदिग्ध वेब लिंक / APK URL स्कैन करें' : 'Scan Suspicious Links & APK URLs'}
              </h3>
            </div>
            <p className="text-xs text-slate-400">
              {isHi
                ? 'WhatsApp, Chrome या SMS में आए किसी भी संदिग्ध लिंक को यहाँ पेस्ट करें (या Android Share -> Kavach से सीधे भेजें)।'
                : 'Paste suspicious URLs from Chrome, WhatsApp, or SMS (or share directly from Android to Kavach) to inspect and delete/suppress them.'}
            </p>
            <textarea
              rows={2}
              value={linkInput}
              onChange={(e) => setLinkInput(e.target.value)}
              placeholder="https://example.com/kyc-update.apk"
              className="w-full px-3.5 py-2.5 rounded-lg bg-[#080C14] border border-slate-700/90 text-sm font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              className="inline-flex items-center justify-center gap-2 min-h-[44px] px-4 py-2 rounded-lg bg-emerald-500 text-slate-950 text-sm font-semibold hover:bg-emerald-400 transition-colors"
            >
              {isHi ? 'लिंक स्कैन करें' : 'Scan Link(s)'}
            </button>
          </form>
        )}

        {scanMode === 'sms' && (
          <form onSubmit={(e) => void handleScanSmsOrCall(e, 'sms')} className="space-y-3 pt-2 border-t border-slate-800/80">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <MessageSquareWarning className="w-4 h-4 text-emerald-400 shrink-0" />
                <h3 className="text-sm font-semibold text-slate-100">
                  {isHi ? 'संदिग्ध SMS संदेश स्कैन करें' : 'Scan Suspicious SMS Messages'}
                </h3>
              </div>
              <button
                type="button"
                onClick={onOpenAnalyzer}
                className="text-xs font-medium text-emerald-400 hover:text-emerald-300 underline underline-offset-4 self-start sm:self-auto"
              >
                {isHi ? 'SMS स्क्रीनशॉट जांचें' : 'Analyze SMS Screenshot'}
              </button>
            </div>
            <p className="text-xs text-slate-400">
              {isHi
                ? 'ब्राउज़र सुरक्षा के कारण वेबसाइटें सीधे आपका SMS इनबॉक्स नहीं पढ़ सकतीं। संदिग्ध SMS यहाँ पेस्ट करें—सिस्टम लिंक, OTP/KYC फ़िशिंग और कॉल-फ़ॉरवर्डिंग कोड जांचकर डिलीट और ब्लॉकलिस्ट का विकल्प देगा।'
                : 'Web browsers sandbox your SMS inbox. Paste suspicious SMS text below to detect phishing links, OTP scams, or USSD codes and queue them for permanent deletion & suppression.'}
            </p>
            <textarea
              rows={2}
              value={smsInput}
              onChange={(e) => setSmsInput(e.target.value)}
              placeholder={
                isHi
                  ? 'संदिग्ध SMS टेक्स्ट यहाँ पेस्ट करें...'
                  : 'Paste suspicious SMS message(s) here...'
              }
              className="w-full px-3.5 py-2.5 rounded-lg bg-[#080C14] border border-slate-700/90 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              className="inline-flex items-center justify-center gap-2 min-h-[44px] px-4 py-2 rounded-lg bg-emerald-500 text-slate-950 text-sm font-semibold hover:bg-emerald-400 transition-colors"
            >
              {isHi ? 'SMS स्कैन करें' : 'Scan SMS'}
            </button>
          </form>
        )}

        {scanMode === 'calls' && (
          <form onSubmit={(e) => void handleScanSmsOrCall(e, 'call')} className="space-y-3 pt-2 border-t border-slate-800/80">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <PhoneIncoming className="w-4 h-4 text-emerald-400 shrink-0" />
                <h3 className="text-sm font-semibold text-slate-100">
                  {isHi ? 'संदिग्ध कॉल नंबर और कॉल फ़ॉरवर्डिंग जांच' : 'Scan Call Numbers & Call-Forwarding Codes'}
                </h3>
              </div>
              <button
                type="button"
                onClick={onOpenAnalyzer}
                className="text-xs font-medium text-emerald-400 hover:text-emerald-300 underline underline-offset-4 self-start sm:self-auto"
              >
                {isHi ? 'कॉल लॉग स्क्रीनशॉट जांचें' : 'Analyze Call Log Screenshot'}
              </button>
            </div>
            <p className="text-xs text-slate-400">
              {isHi
                ? 'अनजान कॉल नंबर या *21* / *401* जैसे कॉल-फ़ॉरवर्डिंग कोड यहाँ डालें। यदि कॉल हैक हुई हो तो फ़ोन से ##002# डायल कर फ़ॉरवर्डिंग बंद करें।'
                : 'Enter suspicious caller numbers or dialed USSD codes (*21*, *401*) to inspect, suppress, and get instant call-forwarding cancellation steps (dial ##002#).'}
            </p>
            <textarea
              rows={2}
              value={callInput}
              onChange={(e) => setCallInput(e.target.value)}
              placeholder={
                isHi
                  ? 'उदा. +9198XXXXXXXX या *401*...'
                  : 'e.g. +9198XXXXXXXX or *401*...'
              }
              className="w-full px-3.5 py-2.5 rounded-lg bg-[#080C14] border border-slate-700/90 text-sm font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              className="inline-flex items-center justify-center gap-2 min-h-[44px] px-4 py-2 rounded-lg bg-emerald-500 text-slate-950 text-sm font-semibold hover:bg-emerald-400 transition-colors"
            >
              {isHi ? 'कॉल नंबर जांचें' : 'Scan Call Entry'}
            </button>
          </form>
        )}
      </section>

      {/* Feedback Banner */}
      {scanError && (
        <div className="bg-rose-950/40 border border-rose-800/80 rounded-xl p-4 flex items-start justify-between gap-3 text-sm text-rose-200">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <span>{scanError}</span>
          </div>
          <button
            type="button"
            onClick={() => setScanError(null)}
            aria-label="Dismiss error"
            className="text-rose-300 hover:text-white p-1"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {statusNotice && (
        <div className="bg-emerald-950/35 border border-emerald-800/70 rounded-xl p-4 flex items-start justify-between gap-3 text-sm text-emerald-100">
          <div className="flex items-start gap-2.5">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <span>{statusNotice}</span>
          </div>
          <button
            type="button"
            onClick={() => setStatusNotice(null)}
            aria-label="Dismiss notice"
            className="text-emerald-300 hover:text-white p-1"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Active Detected APK List */}
      <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800/90 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              {isHi ? 'सक्रिय APK फ़ाइलें' : 'Active Detected APK Files'}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5 tabular-nums">
              {activeApks.length}{' '}
              {isHi ? 'दिख रही हैं' : 'visible'} · {deletedRecords.length}{' '}
              {isHi ? 'परमानेंट डिलीट होकर छिपाई गईं' : 'permanently deleted & hidden'}
              {lastScanStats.scannedAt
                ? ` · ${isHi ? 'अंतिम स्कैन' : 'Last scan'}: ${lastScanStats.scannedAt}`
                : ''}
            </p>
          </div>

          {activeApks.length > 1 && (
            <button
              type="button"
              onClick={() => setConfirmDeleteAll(true)}
              className="inline-flex items-center gap-2 min-h-[44px] px-4 py-2 rounded-lg bg-rose-600 text-white text-sm font-semibold hover:bg-rose-500 transition-colors whitespace-nowrap shrink-0"
            >
              <Trash2 className="w-4 h-4" />
              {isHi ? 'सभी APK हमेशा के लिए डिलीट करें' : 'Permanently Delete All'}
            </button>
          )}
        </div>

        {activeApks.length === 0 ? (
          <div className="p-8 sm:p-10 text-center space-y-3">
            <div className="mx-auto w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <h3 className="text-base font-semibold text-slate-100">
              {isHi
                ? 'कोई भी APK फ़ाइल सक्रिय नहीं है'
                : 'No Active APK Files Shown'}
            </h3>
            <p className="text-sm text-slate-400 max-w-md mx-auto leading-relaxed">
              {deletedRecords.length > 0
                ? isHi
                  ? `आपकी डिलीट की गई ${deletedRecords.length} APK फ़ाइल(ें) परमानेंट ब्लॉकलिस्ट में हैं और दोबारा कभी शो नहीं होंगी।`
                  : `${deletedRecords.length} permanently deleted APK record(s) are suppressed and will never reappear on rescan.`
                : isHi
                  ? 'जांच शुरू करने के लिए ऊपर "फ़ोल्डर स्कैन करें" या "APK फ़ाइल चुनें" दबाएं।'
                  : 'Use "Scan Downloads Folder" or "Select .APK File(s)" above to inspect mobile packages and permanently remove unwanted APKs.'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {activeApks.map((item) => {
              const isCritical = item.riskLevel === 'critical';
              const isHigh = item.riskLevel === 'high';
              const riskText = isCritical
                ? isHi
                  ? 'गंभीर खतरा (Critical)'
                  : 'Critical Risk'
                : isHigh
                  ? isHi
                    ? 'उच्च जोखिम (High)'
                    : 'High Risk'
                  : isHi
                    ? 'सावधान (Medium)'
                    : 'Medium Risk';

              return (
                <div
                  key={item.id}
                  className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4 hover:bg-slate-900/50 transition-colors"
                >
                  <div className="space-y-2 min-w-0">
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="text-base font-semibold text-slate-50 break-all">
                        {item.fileName}
                      </span>
                      <span
                        className={`inline-flex items-center gap-1.5 text-xs font-semibold ${
                          isCritical
                            ? 'text-rose-400'
                            : isHigh
                              ? 'text-amber-400'
                              : 'text-sky-400'
                        }`}
                      >
                        <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                        {riskText}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-400 font-mono">
                      <span>{item.relativePath}</span>
                      <span aria-hidden="true">·</span>
                      <span className="tabular-nums">
                        {item.fileSize > 0 ? formatBytes(item.fileSize) : 'Flagged entry'}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>SHA-256: {item.sha256.slice(0, 14)}…</span>
                      {item.source === 'directory_handle' && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="text-emerald-400 font-sans">
                            {isHi ? 'डायरेक्ट डिस्क डिलीट सक्षम' : 'Direct disk erase ready'}
                          </span>
                        </>
                      )}
                    </div>

                    <ul className="space-y-1 text-xs text-slate-300 pt-1">
                      {item.findings.map((finding, idx) => (
                        <li key={idx} className="leading-relaxed">
                          • {finding}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <button
                      type="button"
                      disabled={deletingId === item.id}
                      onClick={() => setPendingDelete(item)}
                      className="inline-flex items-center justify-center gap-2 min-h-[44px] px-4 py-2.5 rounded-lg bg-rose-600 text-white text-sm font-semibold hover:bg-rose-500 active:scale-[0.98] transition-all whitespace-nowrap shrink-0 disabled:opacity-50 w-full sm:w-auto"
                    >
                      <Trash2 className="w-4 h-4" />
                      {isHi ? 'परमानेंट डिलीट करें' : 'Delete Permanently'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Single Delete Confirmation Modal */}
      {pendingDelete && (
        <div
          className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-end sm:items-center justify-center p-0 sm:p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full sm:max-w-md bg-[#0F1623] border border-slate-700 rounded-t-2xl sm:rounded-xl p-6 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5 text-rose-400">
                <Trash2 className="w-5 h-5 shrink-0" />
                <h3 className="text-base font-semibold text-slate-100">
                  {isHi ? 'APK को हमेशा के लिए डिलीट करें?' : 'Permanently Delete APK?'}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setPendingDelete(null)}
                className="text-slate-400 hover:text-white p-1"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-sm text-slate-300 space-y-2 leading-relaxed">
              <p>
                <span className="font-semibold text-white break-all">
                  {pendingDelete.fileName}
                </span>
              </p>
              <p>
                {pendingDelete.source === 'directory_handle'
                  ? isHi
                    ? 'यह फ़ाइल आपके चुने हुए फ़ोल्डर से डिलीट हो जाएगी और ब्लॉकलिस्ट में सेव हो जाएगी ताकि दोबारा कभी शो न हो।'
                    : 'This will permanently erase the file from your selected folder and add its SHA-256 hash to the suppression vault so it is never displayed again.'
                  : isHi
                    ? 'यह APK कंसोल से हमेशा के लिए हटाकर ब्लॉकलिस्ट में सेव हो जाएगी ताकि दोबारा कभी न दिखे। फोन के Files ऐप के Trash को भी खाली करना याद रखें।'
                    : 'This removes and permanently suppresses the APK from all future scans. Remember to also empty Files -> Trash on your Android device.'}
              </p>
            </div>

            <div className="flex flex-col-reverse sm:flex-row sm:justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setPendingDelete(null)}
                className="min-h-[44px] px-4 py-2 rounded-lg bg-slate-800 text-slate-200 text-sm font-medium hover:bg-slate-700 transition-colors"
              >
                {isHi ? 'रद्द करें' : 'Cancel'}
              </button>
              <button
                type="button"
                onClick={() => void confirmAndDeleteSingle()}
                className="min-h-[44px] px-4 py-2 rounded-lg bg-rose-600 text-white text-sm font-semibold hover:bg-rose-500 transition-colors"
              >
                {isHi ? 'हां, हमेशा के लिए डिलीट करें' : 'Yes, Delete Forever'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Batch Delete Confirmation Modal */}
      {confirmDeleteAll && (
        <div
          className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-end sm:items-center justify-center p-0 sm:p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full sm:max-w-md bg-[#0F1623] border border-slate-700 rounded-t-2xl sm:rounded-xl p-6 space-y-4">
            <h3 className="text-base font-semibold text-slate-100">
              {isHi
                ? `सभी ${activeApks.length} APK फ़ाइलें हमेशा के लिए डिलीट करें?`
                : `Permanently delete all ${activeApks.length} APKs?`}
            </h3>
            <p className="text-sm text-slate-300 leading-relaxed">
              {isHi
                ? 'सभी दिख रही APK फ़ाइलें डिलीट और ब्लॉकलिस्ट कर दी जाएंगी और भविष्य के किसी भी स्कैन में वापस नहीं दिखेंगी।'
                : 'Every listed APK will be erased where writable and permanently suppressed from all future scans.'}
            </p>
            <div className="flex flex-col-reverse sm:flex-row sm:justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setConfirmDeleteAll(false)}
                className="min-h-[44px] px-4 py-2 rounded-lg bg-slate-800 text-slate-200 text-sm font-medium hover:bg-slate-700 transition-colors"
              >
                {isHi ? 'रद्द करें' : 'Cancel'}
              </button>
              <button
                type="button"
                onClick={() => void handleBatchDelete()}
                className="min-h-[44px] px-4 py-2 rounded-lg bg-rose-600 text-white text-sm font-semibold hover:bg-rose-500 transition-colors"
              >
                {isHi ? 'सभी डिलीट करें' : 'Delete All Forever'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
