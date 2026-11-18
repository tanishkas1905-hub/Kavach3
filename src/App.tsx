import React, { useEffect, useMemo, useState } from 'react';
import {
  Shield,
  ScanSearch,
  ListChecks,
  ArchiveX,
  LogIn,
  LogOut,
  PhoneCall,
} from 'lucide-react';
import { onAuthStateChanged, type User } from 'firebase/auth';
import {
  collection,
  deleteDoc,
  doc,
  onSnapshot,
  orderBy,
  query,
  serverTimestamp,
  setDoc,
  Timestamp,
} from 'firebase/firestore';
import {
  auth,
  db,
  handleFirestoreError,
  OperationType,
  signInWithGoogle,
  signOutAccount,
} from './firebase';
import {
  analyzeSmsOrCallInput,
  analyzeSuspiciousLink,
  isApkSuppressed,
  type DeletedApkRecord,
  type ScannedApkItem,
} from './lib/apkScanner';
import { HARDENING_STEPS, type Language } from './lib/hardeningData';
import { ApkScannerPanel } from './components/ApkScannerPanel';
import {
  ThreatAnalyzerPanel,
  type AnalysisHistoryItem,
} from './components/ThreatAnalyzerPanel';
import { HardeningPanel } from './components/HardeningPanel';
import { DeletedRegistryPanel } from './components/DeletedRegistryPanel';
import { OfflineIndicator, PWAInstallButton } from './components/PWAInstallButton';

type ActiveTab = 'scanner' | 'analyzer' | 'hardening' | 'vault';

const LOCAL_DELETED_KEY = 'kavach_deleted_apks_v1';
const LOCAL_HARDENING_KEY = 'kavach_hardening_v1';
const LOCAL_ANALYSES_KEY = 'kavach_analyses_v1';
const LOCAL_LANG_KEY = 'kavach_language_v1';

function readLocalJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function sanitizeDocId(raw: string): string {
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 120);
  return cleaned || `rec_${Date.now()}`;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('scanner');
  const [language, setLanguage] = useState<Language>(() =>
    readLocalJson<Language>(LOCAL_LANG_KEY, 'en')
  );

  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  const [activeApks, setActiveApks] = useState<ScannedApkItem[]>([]);
  const [localDeleted, setLocalDeleted] = useState<DeletedApkRecord[]>(() =>
    readLocalJson<DeletedApkRecord[]>(LOCAL_DELETED_KEY, [])
  );
  const [cloudDeleted, setCloudDeleted] = useState<DeletedApkRecord[]>([]);

  const [hardeningMap, setHardeningMap] = useState<Record<string, boolean>>(() =>
    readLocalJson<Record<string, boolean>>(LOCAL_HARDENING_KEY, {})
  );

  const [localAnalyses, setLocalAnalyses] = useState<AnalysisHistoryItem[]>(() =>
    readLocalJson<AnalysisHistoryItem[]>(LOCAL_ANALYSES_KEY, [])
  );
  const [cloudAnalyses, setCloudAnalyses] = useState<AnalysisHistoryItem[]>([]);

  const [lastScanStats, setLastScanStats] = useState<{
    visitedFiles: number;
    suppressedSkipped: number;
    scannedAt: string | null;
  }>({
    visitedFiles: 0,
    suppressedSkipped: 0,
    scannedAt: null,
  });

  const isHi = language === 'hi';

  const handleSetLanguage = (next: Language) => {
    setLanguage(next);
    try {
      localStorage.setItem(LOCAL_LANG_KEY, JSON.stringify(next));
    } catch {
      // ignore storage quota errors
    }
  };

  // Merge local and Firestore deletion records so suppressed APKs never reappear
  const deletedRecords = useMemo(() => {
    const map = new Map<string, DeletedApkRecord>();
    for (const rec of [...cloudDeleted, ...localDeleted]) {
      const key = `${rec.sha256}_${rec.normalizedName}`;
      if (!map.has(key)) {
        map.set(key, rec);
      }
    }
    return Array.from(map.values()).sort(
      (a, b) => new Date(b.deletedAtIso).getTime() - new Date(a.deletedAtIso).getTime()
    );
  }, [cloudDeleted, localDeleted]);

  const analyses = useMemo(() => {
    const map = new Map<string, AnalysisHistoryItem>();
    for (const item of [...cloudAnalyses, ...localAnalyses]) {
      if (!map.has(item.id)) map.set(item.id, item);
    }
    return Array.from(map.values()).sort(
      (a, b) => new Date(b.analyzedAtIso).getTime() - new Date(a.analyzedAtIso).getTime()
    );
  }, [cloudAnalyses, localAnalyses]);

  // Filter active APKs whenever deletedRecords updates so a deleted APK is never displayed again
  useEffect(() => {
    setActiveApks((prev) => prev.filter((item) => !isApkSuppressed(item, deletedRecords)));
  }, [deletedRecords]);

  // Process Android PWA Share Target (?url=, ?text=, ?title=)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sharedUrl = params.get('url') || '';
    const sharedText = params.get('text') || '';
    const sharedTitle = params.get('title') || '';
    if (!sharedUrl && !sharedText && !sharedTitle) return;

    void (async () => {
      const results: ScannedApkItem[] = [];
      if (sharedUrl) {
        results.push(...(await analyzeSuspiciousLink(sharedUrl)));
      }
      const combinedText = [sharedTitle, sharedText].filter(Boolean).join(' ').trim();
      if (combinedText) {
        results.push(...(await analyzeSmsOrCallInput(combinedText, 'sms')));
      }
      const unsuppressed = results.filter((item) => !isApkSuppressed(item, deletedRecords));
      if (unsuppressed.length > 0) {
        setActiveApks((prev) => [...unsuppressed, ...prev]);
      }
      window.history.replaceState({}, '', window.location.pathname);
    })();
    // Run once on initial launch with share params
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Firebase Auth listener
  useEffect(() => {
    const unsub = onAuthStateChanged(auth, (nextUser) => {
      setUser(nextUser);
      setAuthReady(true);
    });
    return () => unsub();
  }, []);

  // Firestore real-time subscriptions when authenticated with verified email
  useEffect(() => {
    if (!authReady || !user || !user.emailVerified) {
      setCloudDeleted([]);
      setCloudAnalyses([]);
      return;
    }

    const deletedPath = `users/${user.uid}/deleted_apks`;
    const deletedQuery = query(
      collection(db, deletedPath),
      orderBy('deletedAt', 'desc')
    );

    const unsubDeleted = onSnapshot(
      deletedQuery,
      (snap) => {
        const rows: DeletedApkRecord[] = snap.docs.map((d) => {
          const data = d.data();
          const ts = data.deletedAt instanceof Timestamp ? data.deletedAt.toDate() : new Date();
          return {
            id: d.id,
            sha256: String(data.sha256 || ''),
            fileName: String(data.fileName || ''),
            normalizedName: String(data.normalizedName || ''),
            fileSize: Number(data.fileSize || 0),
            packageHint: String(data.packageHint || ''),
            deletionMethod:
              (data.deletionMethod as DeletedApkRecord['deletionMethod']) ||
              'suppressed_permanently',
            riskLevel: (data.riskLevel as DeletedApkRecord['riskLevel']) || 'high',
            deletedAtIso: ts.toISOString(),
          };
        });
        setCloudDeleted(rows);
      },
      (error) => handleFirestoreError(error, OperationType.LIST, deletedPath)
    );

    const hardeningPath = `users/${user.uid}/hardening_state`;
    const unsubHardening = onSnapshot(
      collection(db, hardeningPath),
      (snap) => {
        if (snap.empty) return;
        setHardeningMap((prev) => {
          const merged = { ...prev };
          for (const d of snap.docs) {
            const data = d.data();
            merged[d.id] = Boolean(data.completed);
          }
          try {
            localStorage.setItem(LOCAL_HARDENING_KEY, JSON.stringify(merged));
          } catch {
            // ignore
          }
          return merged;
        });
      },
      (error) => handleFirestoreError(error, OperationType.LIST, hardeningPath)
    );

    const analysesPath = `users/${user.uid}/threat_analyses`;
    const analysesQuery = query(
      collection(db, analysesPath),
      orderBy('analyzedAt', 'desc')
    );
    const unsubAnalyses = onSnapshot(
      analysesQuery,
      (snap) => {
        const rows: AnalysisHistoryItem[] = snap.docs.map((d) => {
          const data = d.data();
          const ts =
            data.analyzedAt instanceof Timestamp ? data.analyzedAt.toDate() : new Date();
          return {
            id: d.id,
            fileName: String(data.fileName || ''),
            verdict:
              data.verdict === 'critical' || data.verdict === 'safe'
                ? data.verdict
                : 'suspicious',
            headline: String(data.fileName || 'Screenshot Audit'),
            summary: String(data.summary || ''),
            indicators: [],
            remediationSteps: [],
            analyzedAtIso: ts.toISOString(),
          };
        });
        setCloudAnalyses(rows);
      },
      (error) => handleFirestoreError(error, OperationType.LIST, analysesPath)
    );

    return () => {
      unsubDeleted();
      unsubHardening();
      unsubAnalyses();
    };
  }, [authReady, user]);

  const handleAuthAction = async () => {
    setAuthError(null);
    try {
      if (user) {
        await signOutAccount();
      } else {
        await signInWithGoogle();
      }
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Authentication request cancelled.');
    }
  };

  const handleAddScannedApks = (
    items: ScannedApkItem[],
    suppressedSkipped: number,
    visitedFiles: number
  ) => {
    setLastScanStats({
      visitedFiles,
      suppressedSkipped,
      scannedAt: new Date().toLocaleTimeString(),
    });

    setActiveApks((prev) => {
      const next = [...prev];
      for (const candidate of items) {
        if (isApkSuppressed(candidate, deletedRecords)) continue;
        const alreadyInList = next.some(
          (x) =>
            x.sha256 === candidate.sha256 ||
            x.normalizedName === candidate.normalizedName
        );
        if (!alreadyInList) {
          next.push(candidate);
        }
      }
      return next;
    });
  };

  const persistDeletedRecord = async (record: DeletedApkRecord) => {
    setLocalDeleted((prev) => {
      const updated = [
        record,
        ...prev.filter(
          (r) =>
            r.sha256 !== record.sha256 &&
            r.normalizedName !== record.normalizedName
        ),
      ];
      try {
        localStorage.setItem(LOCAL_DELETED_KEY, JSON.stringify(updated));
      } catch {
        // ignore
      }
      return updated;
    });

    if (user && user.emailVerified) {
      const docId = sanitizeDocId(record.id);
      const path = `users/${user.uid}/deleted_apks/${docId}`;
      try {
        await setDoc(doc(db, path), {
          ownerId: user.uid,
          sha256: record.sha256,
          fileName: record.fileName.slice(0, 255),
          normalizedName: record.normalizedName.slice(0, 255),
          fileSize: Math.max(0, Math.round(record.fileSize)),
          packageHint: record.packageHint.slice(0, 200),
          deletionMethod: record.deletionMethod,
          riskLevel: record.riskLevel,
          deletedAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, path);
      }
    }
  };

  const handlePermanentlyDeleteApk = async (
    item: ScannedApkItem
  ): Promise<{ diskRemoved: boolean; error?: string }> => {
    let diskRemoved = false;
    let errorMsg: string | undefined;

    if (item.source === 'directory_handle' && item.parentDirHandle) {
      try {
        await item.parentDirHandle.removeEntry(item.fileName);
        diskRemoved = true;
      } catch (err) {
        errorMsg =
          err instanceof Error
            ? `Disk delete permission denied (${err.message}). Suppressed permanently in console.`
            : 'Folder write permission unavailable; suppressed permanently in console.';
      }
    }

    const record: DeletedApkRecord = {
      id: sanitizeDocId(`del_${item.sha256.slice(0, 16)}_${Date.now()}`),
      sha256: item.sha256,
      fileName: item.fileName,
      normalizedName: item.normalizedName,
      fileSize: item.fileSize,
      packageHint: item.packageHint,
      deletionMethod: diskRemoved ? 'disk_removed' : 'suppressed_permanently',
      riskLevel: item.riskLevel,
      deletedAtIso: new Date().toISOString(),
    };

    setActiveApks((prev) =>
      prev.filter(
        (x) => x.sha256 !== item.sha256 && x.normalizedName !== item.normalizedName
      )
    );

    await persistDeletedRecord(record);
    return { diskRemoved, error: errorMsg };
  };

  const handleDeleteAllApks = async () => {
    const snapshot = [...activeApks];
    for (const item of snapshot) {
      await handlePermanentlyDeleteApk(item);
    }
  };

  const handleToggleHardeningStep = async (stepId: string, nextVal: boolean) => {
    setHardeningMap((prev) => {
      const updated = { ...prev, [stepId]: nextVal };
      try {
        localStorage.setItem(LOCAL_HARDENING_KEY, JSON.stringify(updated));
      } catch {
        // ignore
      }
      return updated;
    });

    if (user && user.emailVerified) {
      const safeStepId = sanitizeDocId(stepId);
      const path = `users/${user.uid}/hardening_state/${safeStepId}`;
      try {
        await setDoc(doc(db, path), {
          ownerId: user.uid,
          stepKey: safeStepId,
          completed: nextVal,
          updatedAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.WRITE, path);
      }
    }
  };

  const handleAnalysisComplete = async (item: AnalysisHistoryItem) => {
    setLocalAnalyses((prev) => {
      const updated = [item, ...prev].slice(0, 20);
      try {
        localStorage.setItem(LOCAL_ANALYSES_KEY, JSON.stringify(updated));
      } catch {
        // ignore
      }
      return updated;
    });

    if (user && user.emailVerified) {
      const safeId = sanitizeDocId(item.id);
      const path = `users/${user.uid}/threat_analyses/${safeId}`;
      try {
        await setDoc(doc(db, path), {
          ownerId: user.uid,
          fileName: item.fileName.slice(0, 255),
          verdict: item.verdict,
          summary: `${item.headline}: ${item.summary}`.slice(0, 1500),
          analyzedAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, path);
      }
    }
  };

  const handlePurgeAllRecords = async () => {
    setLocalDeleted([]);
    try {
      localStorage.removeItem(LOCAL_DELETED_KEY);
    } catch {
      // ignore
    }

    if (user && user.emailVerified) {
      for (const rec of cloudDeleted) {
        const path = `users/${user.uid}/deleted_apks/${rec.id}`;
        try {
          await deleteDoc(doc(db, path));
        } catch (err) {
          handleFirestoreError(err, OperationType.DELETE, path);
        }
      }
    }
  };

  const hardeningCompletedCount = HARDENING_STEPS.filter(
    (s) => hardeningMap[s.id]
  ).length;

  return (
    <div className="min-h-screen bg-[#080C14] text-slate-100 pb-24 md:pb-12">
      {/* Top Bar Contract: Brand wordmark — 4 single-line nav links — 1 primary action */}
      <header className="sticky top-0 z-30 bg-[#080C14]/90 backdrop-blur-md border-b border-slate-800/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-8">
          <a
            href="#top"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('scanner');
            }}
            className="text-lg font-bold tracking-tight text-slate-50 font-display whitespace-nowrap shrink-0"
          >
            Kavach
          </a>

          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-300">
            <button
              type="button"
              onClick={() => setActiveTab('scanner')}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors ${
                activeTab === 'scanner'
                  ? 'text-emerald-400 underline underline-offset-8 decoration-2'
                  : 'hover:text-white'
              }`}
            >
              {isHi ? 'APK स्कैनर' : 'APK Scanner'}
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('analyzer')}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors ${
                activeTab === 'analyzer'
                  ? 'text-emerald-400 underline underline-offset-8 decoration-2'
                  : 'hover:text-white'
              }`}
            >
              {isHi ? 'स्क्रीनशॉट जांच' : 'Threat Analyzer'}
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('hardening')}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors ${
                activeTab === 'hardening'
                  ? 'text-emerald-400 underline underline-offset-8 decoration-2'
                  : 'hover:text-white'
              }`}
            >
              {isHi ? 'एंटी-हैक गाइड' : 'Anti-Hack Guide'}
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('vault')}
              className={`whitespace-nowrap shrink-0 py-1 transition-colors ${
                activeTab === 'vault'
                  ? 'text-emerald-400 underline underline-offset-8 decoration-2'
                  : 'hover:text-white'
              }`}
            >
              {isHi ? 'डिलीट वॉल्ट' : 'Suppression Vault'}
            </button>
          </nav>

          <div className="flex items-center shrink-0">
            <button
              type="button"
              onClick={() => void handleAuthAction()}
              className="inline-flex items-center gap-2 min-h-[40px] px-3.5 py-2 rounded-lg bg-slate-100 text-slate-950 text-xs font-semibold hover:bg-white transition-colors whitespace-nowrap shrink-0"
            >
              {user ? (
                <>
                  <LogOut className="w-3.5 h-3.5" />
                  <span>{isHi ? 'साइन आउट' : 'Sign Out'}</span>
                </>
              ) : (
                <>
                  <LogIn className="w-3.5 h-3.5" />
                  <span>{isHi ? 'क्लाउड सिंक (Google)' : 'Sync with Google'}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 pt-5 space-y-6">
        {/* Workspace Toolbar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
          <div className="text-xs text-slate-400 flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>
              {isHi
                ? 'नागरिक मोबाइल साइबर सुरक्षा कंसोल'
                : 'Citizen Mobile Security & APK Hygiene Console'}
            </span>
            <span aria-hidden="true">·</span>
            <span>
              {user
                ? `${isHi ? 'सिंक सक्रिय' : 'Cloud sync active'}: ${user.email}`
                : isHi
                  ? 'लोकल सुरक्षा वॉल्ट सक्रिय'
                  : 'Local suppression vault active'}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 self-start sm:self-auto">
            <PWAInstallButton language={language} />
            <div className="flex items-center gap-1 p-1 bg-[#0F1623] border border-slate-800 rounded-lg">
              <button
                type="button"
                onClick={() => handleSetLanguage('hi')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  language === 'hi'
                    ? 'bg-emerald-500 text-slate-950 font-semibold'
                    : 'text-slate-300 hover:text-white'
                }`}
              >
                हिन्दी
              </button>
              <button
                type="button"
                onClick={() => handleSetLanguage('en')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  language === 'en'
                    ? 'bg-emerald-500 text-slate-950 font-semibold'
                    : 'text-slate-300 hover:text-white'
                }`}
              >
                English
              </button>
            </div>
          </div>
        </div>

        {authError && (
          <div className="bg-amber-950/40 border border-amber-800 rounded-xl px-4 py-3 text-xs text-amber-200">
            {authError}
          </div>
        )}

        {/* 4-Column Real Telemetry KPI Strip */}
        <section className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-4 space-y-1">
            <div className="text-xs text-slate-400">
              {isHi ? 'दिख रही APK फ़ाइलें' : 'Active APKs Visible'}
            </div>
            <div
              className={`text-2xl font-bold font-mono tabular-nums ${
                activeApks.length > 0 ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {activeApks.length}
            </div>
          </div>

          <div className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-4 space-y-1">
            <div className="text-xs text-slate-400">
              {isHi ? 'परमानेंट डिलीट / छिपाई गईं' : 'Permanently Suppressed'}
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-slate-50">
              {deletedRecords.length}
            </div>
          </div>

          <div className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-4 space-y-1">
            <div className="text-xs text-slate-400">
              {isHi ? 'एंटी-हैक सुरक्षा जांच' : 'Hardening Checks'}
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
              {hardeningCompletedCount} / {HARDENING_STEPS.length}
            </div>
          </div>

          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noopener noreferrer"
            className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-4 space-y-1 hover:border-slate-600 transition-colors block"
          >
            <div className="text-xs text-slate-400 flex items-center gap-1.5">
              <PhoneCall className="w-3.5 h-3.5 text-emerald-400" />
              {isHi ? 'साइबर हेल्पलाइन (भारत)' : 'Citizen Cyber Helpline'}
            </div>
            <div className="text-xl font-bold font-mono tabular-nums text-slate-50">
              1930 · cybercrime.gov.in
            </div>
          </a>
        </section>

        {/* Active View */}
        {activeTab === 'scanner' && (
          <ApkScannerPanel
            language={language}
            activeApks={activeApks}
            deletedRecords={deletedRecords}
            onAddScannedApks={handleAddScannedApks}
            onPermanentlyDeleteApk={handlePermanentlyDeleteApk}
            onDeleteAllApks={handleDeleteAllApks}
            lastScanStats={lastScanStats}
            onOpenHardening={() => setActiveTab('hardening')}
            onOpenAnalyzer={() => setActiveTab('analyzer')}
          />
        )}

        {activeTab === 'analyzer' && (
          <ThreatAnalyzerPanel
            language={language}
            analyses={analyses}
            onAnalysisComplete={handleAnalysisComplete}
            suppressedApkCount={deletedRecords.length}
            hardeningCompletedCount={hardeningCompletedCount}
            hardeningTotalCount={HARDENING_STEPS.length}
          />
        )}

        {activeTab === 'hardening' && (
          <HardeningPanel
            language={language}
            completedMap={hardeningMap}
            onToggleStep={handleToggleHardeningStep}
          />
        )}

        {activeTab === 'vault' && (
          <DeletedRegistryPanel
            language={language}
            deletedRecords={deletedRecords}
            onPurgeAllRecords={handlePurgeAllRecords}
          />
        )}
      </main>

      {/* Mobile Fixed Bottom Navigation Bar (stays within 15% mobile sticky cap) */}
      <nav
        aria-label="Mobile Navigation"
        className="md:hidden fixed bottom-0 left-0 right-0 z-40 bg-[#080C14]/95 backdrop-blur-md border-t border-slate-800/90 grid grid-cols-4 h-16"
      >
        <button
          type="button"
          onClick={() => setActiveTab('scanner')}
          className={`flex flex-col items-center justify-center min-h-[44px] ${
            activeTab === 'scanner' ? 'text-emerald-400' : 'text-slate-400'
          }`}
        >
          <Shield className="w-5 h-5" />
          <span className="text-[10px] font-medium tracking-tight mt-1">
            {isHi ? 'स्कैनर' : 'Scanner'}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('analyzer')}
          className={`flex flex-col items-center justify-center min-h-[44px] ${
            activeTab === 'analyzer' ? 'text-emerald-400' : 'text-slate-400'
          }`}
        >
          <ScanSearch className="w-5 h-5" />
          <span className="text-[10px] font-medium tracking-tight mt-1">
            {isHi ? 'स्क्रीनशॉट' : 'Analyzer'}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('hardening')}
          className={`flex flex-col items-center justify-center min-h-[44px] ${
            activeTab === 'hardening' ? 'text-emerald-400' : 'text-slate-400'
          }`}
        >
          <ListChecks className="w-5 h-5" />
          <span className="text-[10px] font-medium tracking-tight mt-1">
            {isHi ? 'सुरक्षा' : 'Hardening'}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('vault')}
          className={`flex flex-col items-center justify-center min-h-[44px] ${
            activeTab === 'vault' ? 'text-emerald-400' : 'text-slate-400'
          }`}
        >
          <ArchiveX className="w-5 h-5" />
          <span className="text-[10px] font-medium tracking-tight mt-1">
            {isHi ? 'वॉल्ट' : 'Vault'}
          </span>
        </button>
      </nav>

      <OfflineIndicator language={language} />
    </div>
  );
}
