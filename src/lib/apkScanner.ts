export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';
export type DeletionMethod = 'disk_removed' | 'suppressed_permanently' | 'manual_confirmed';
export type ThreatCategory = 'file' | 'app' | 'link' | 'sms' | 'call';

export interface ScannedApkItem {
  id: string;
  category?: ThreatCategory;
  fileName: string;
  normalizedName: string;
  relativePath: string;
  fileSize: number;
  lastModified: number;
  sha256: string;
  packageHint: string;
  riskLevel: RiskLevel;
  findings: string[];
  hasManifest: boolean;
  hasDex: boolean;
  nativeArchCount: number;
  embeddedApkCount: number;
  source: 'directory_handle' | 'file_picker' | 'manual_entry';
  parentDirHandle?: FileSystemDirectoryHandle;
}

export interface DeletedApkRecord {
  id: string;
  sha256: string;
  fileName: string;
  normalizedName: string;
  fileSize: number;
  packageHint: string;
  deletionMethod: DeletionMethod;
  riskLevel: RiskLevel;
  deletedAtIso: string;
}

const APK_EXTENSIONS = ['.apk', '.xapk', '.apks', '.aab'];

const HIGH_RISK_NAME_PATTERNS: { pattern: RegExp; reason: string; level: RiskLevel }[] = [
  {
    pattern: /(kyc|bank|sbi|hdfc|icici|axis|kotak|upi|paytm|phonepe|gpay|aadhaar|pan_card|challan|e-?challan|rto|electricity|bill|refund|loan)/i,
    reason: 'Filename mimics banking, KYC, government utility, or payment lure',
    level: 'critical',
  },
  {
    pattern: /(mod|crack|hack|cheat|keygen|bypass|spy|rat|payload|stealth|hidden|inject|trojan)/i,
    reason: 'Filename matches unofficial mod, exploit, or remote-access lure',
    level: 'critical',
  },
  {
    pattern: /(update|installer|system_update|chrome_update|whatsapp_plus|gbwhatsapp|fmwhatsapp|telegram_mod)/i,
    reason: 'Filename impersonates system updater or modified messaging client',
    level: 'high',
  },
];

export function normalizeApkName(name: string): string {
  return name.trim().toLowerCase();
}

export function isApkFileName(name: string): boolean {
  const lower = name.toLowerCase();
  return APK_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

const SUSPICIOUS_PAYLOAD_EXTENSIONS = ['.dex', '.jar', '.sh', '.bat', '.vbs', '.ps1', '.exe'];

export function isSuspiciousPayloadFileName(name: string): boolean {
  const lower = name.toLowerCase();
  return SUSPICIOUS_PAYLOAD_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

export interface PackageAuditResult {
  packageName: string;
  riskLevel: RiskLevel;
  reason: string;
}

export function auditInstalledPackageList(rawInput: string): PackageAuditResult[] {
  const lines = rawInput
    .split(/[\n,;]+/)
    .map((l) => l.replace(/^package:/i, '').trim())
    .filter((l) => l.length > 0);

  const results: PackageAuditResult[] = [];
  for (const pkg of lines) {
    let matched = false;
    for (const rule of HIGH_RISK_NAME_PATTERNS) {
      if (rule.pattern.test(pkg)) {
        results.push({
          packageName: pkg,
          riskLevel: rule.level,
          reason: rule.reason,
        });
        matched = true;
        break;
      }
    }
    if (
      !matched &&
      !pkg.startsWith('com.google.') &&
      !pkg.startsWith('com.android.') &&
      !pkg.startsWith('com.sec.') &&
      !pkg.startsWith('com.samsung.')
    ) {
      if (/(remote|teamviewer|anydesk|screen|mirror|clone|dual|parallel|record|tracker|monitor)/i.test(pkg)) {
        results.push({
          packageName: pkg,
          riskLevel: 'high',
          reason:
            'Remote-control, screen-sharing, or monitoring app indicator — verify if you installed this intentionally.',
        });
      }
    }
  }
  return results;
}

export function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export async function computeSha256Hex(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function computeStringSha256Hex(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  return computeSha256Hex(data.buffer);
}

/**
 * Parses ZIP/APK central directory entries in memory without external libraries
 * to verify Android package structure (AndroidManifest.xml, classes.dex, native libs, embedded APKs).
 */
export function inspectApkArchiveBuffer(buffer: ArrayBuffer): {
  isValidZip: boolean;
  hasManifest: boolean;
  hasDex: boolean;
  nativeArchCount: number;
  embeddedApkCount: number;
  signedCertCount: number;
} {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  if (bytes.length < 22) {
    return {
      isValidZip: false,
      hasManifest: false,
      hasDex: false,
      nativeArchCount: 0,
      embeddedApkCount: 0,
      signedCertCount: 0,
    };
  }

  // Locate End of Central Directory (EOCD: 0x06054b50) scanning backwards from end
  const maxSearch = Math.max(0, bytes.length - 65557);
  let eocdOffset = -1;
  for (let i = bytes.length - 22; i >= maxSearch; i--) {
    if (
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x05 &&
      bytes[i + 3] === 0x06
    ) {
      eocdOffset = i;
      break;
    }
  }

  const isValidZip = bytes[0] === 0x50 && bytes[1] === 0x4b;
  if (eocdOffset === -1) {
    return {
      isValidZip,
      hasManifest: false,
      hasDex: false,
      nativeArchCount: 0,
      embeddedApkCount: 0,
      signedCertCount: 0,
    };
  }

  const totalEntries = view.getUint16(eocdOffset + 10, true);
  const cdOffset = view.getUint32(eocdOffset + 16, true);

  let offset = cdOffset;
  let hasManifest = false;
  let hasDex = false;
  const nativeArches = new Set<string>();
  let embeddedApkCount = 0;
  let signedCertCount = 0;

  const decoder = new TextDecoder('utf-8', { fatal: false });
  const maxEntries = Math.min(totalEntries, 4000);

  for (let idx = 0; idx < maxEntries && offset + 46 <= bytes.length; idx++) {
    const sig = view.getUint32(offset, true);
    if (sig !== 0x02014b50) break;

    const nameLen = view.getUint16(offset + 28, true);
    const extraLen = view.getUint16(offset + 30, true);
    const commentLen = view.getUint16(offset + 32, true);

    const nameStart = offset + 46;
    const nameEnd = Math.min(nameStart + nameLen, bytes.length);
    const entryName = decoder.decode(bytes.subarray(nameStart, nameEnd));

    if (entryName === 'AndroidManifest.xml') hasManifest = true;
    if (/^classes\d*\.dex$/i.test(entryName)) hasDex = true;
    if (entryName.startsWith('lib/')) {
      const parts = entryName.split('/');
      if (parts[1]) nativeArches.add(parts[1]);
    }
    if (entryName.toLowerCase().endsWith('.apk') && entryName !== 'AndroidManifest.xml') {
      embeddedApkCount++;
    }
    if (/^META-INF\/.*\.(RSA|DSA|EC)$/i.test(entryName)) {
      signedCertCount++;
    }

    offset = nameStart + nameLen + extraLen + commentLen;
  }

  return {
    isValidZip,
    hasManifest,
    hasDex,
    nativeArchCount: nativeArches.size,
    embeddedApkCount,
    signedCertCount,
  };
}

export async function analyzeLocalApkFile(
  file: File,
  relativePath: string,
  source: 'directory_handle' | 'file_picker',
  parentDirHandle?: FileSystemDirectoryHandle
): Promise<ScannedApkItem> {
  const buffer = await file.arrayBuffer();
  const sha256 = await computeSha256Hex(buffer);
  const archive = inspectApkArchiveBuffer(buffer);

  const findings: string[] = [];
  let riskLevel: RiskLevel = 'medium';

  for (const rule of HIGH_RISK_NAME_PATTERNS) {
    if (rule.pattern.test(file.name)) {
      findings.push(rule.reason);
      if (rule.level === 'critical') {
        riskLevel = 'critical';
      } else if (riskLevel !== 'critical') {
        riskLevel = 'high';
      }
    }
  }

  if (archive.embeddedApkCount > 0) {
    findings.push(`Contains ${archive.embeddedApkCount} nested APK payload(s) inside archive`);
    riskLevel = 'critical';
  }

  if (archive.hasManifest && archive.hasDex) {
    findings.push('Executable AndroidManifest.xml + Dalvik classes.dex bytecode detected');
    if (archive.signedCertCount === 0) {
      findings.push('No v1 META-INF signature block detected (verify origin before trusting)');
      if (riskLevel === 'medium') riskLevel = 'high';
    }
  } else if (!archive.isValidZip) {
    findings.push('File header is not a standard ZIP/APK container (potentially disguised binary)');
    riskLevel = 'high';
  } else {
    findings.push('Sideloadable Android package installer stored outside Play Store');
  }

  if (archive.nativeArchCount > 0) {
    findings.push(`Bundles native C/C++ binaries for ${archive.nativeArchCount} CPU ABI(s)`);
  }

  return {
    id: `apk_${sha256.slice(0, 16)}_${normalizeApkName(file.name).replace(/[^a-z0-9]/g, '_')}`.slice(0, 120),
    fileName: file.name,
    normalizedName: normalizeApkName(file.name),
    relativePath,
    fileSize: file.size,
    lastModified: file.lastModified,
    sha256,
    packageHint: archive.hasManifest ? 'Android APK Package' : 'Installer Archive',
    riskLevel,
    findings,
    hasManifest: archive.hasManifest,
    hasDex: archive.hasDex,
    nativeArchCount: archive.nativeArchCount,
    embeddedApkCount: archive.embeddedApkCount,
    source,
    parentDirHandle,
  };
}

export async function createManualApkEntry(
  rawName: string,
  locationHint: string
): Promise<ScannedApkItem> {
  const cleanName = rawName.trim();
  const finalName = isApkFileName(cleanName) ? cleanName : `${cleanName}.apk`;
  const normalizedName = normalizeApkName(finalName);
  const sha256 = await computeStringSha256Hex(`manual:${normalizedName}`);

  const findings: string[] = [
    'Flagged manually from mobile Downloads or external security alert',
  ];
  let riskLevel: RiskLevel = 'high';

  for (const rule of HIGH_RISK_NAME_PATTERNS) {
    if (rule.pattern.test(finalName)) {
      findings.push(rule.reason);
      if (rule.level === 'critical') riskLevel = 'critical';
    }
  }

  return {
    id: `apk_manual_${sha256.slice(0, 16)}`,
    category: 'file',
    fileName: finalName,
    normalizedName,
    relativePath: locationHint.trim() || `/Download/${finalName}`,
    fileSize: 0,
    lastModified: Date.now(),
    sha256,
    packageHint: 'Flagged Sideload APK',
    riskLevel,
    findings,
    hasManifest: true,
    hasDex: true,
    nativeArchCount: 0,
    embeddedApkCount: 0,
    source: 'manual_entry',
  };
}

export async function analyzeSuspiciousLink(rawInput: string): Promise<ScannedApkItem[]> {
  const lines = rawInput
    .split(/[\n\s]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 3);

  const unique = Array.from(new Set(lines)).slice(0, 20);
  const items: ScannedApkItem[] = [];

  for (const rawUrl of unique) {
    const normalized = normalizeApkName(rawUrl);
    const sha256 = await computeStringSha256Hex(`link:${normalized}`);
    const findings: string[] = [];
    let riskLevel: RiskLevel = 'medium';

    const lower = rawUrl.toLowerCase();
    if (/\.apk(\?|$|#)/i.test(lower) || /\.xapk(\?|$|#)/i.test(lower)) {
      findings.push('Direct sideload APK download URL — high risk of banking trojan or spyware installation');
      riskLevel = 'critical';
    }
    if (/^http:\/\//i.test(lower)) {
      findings.push('Unencrypted HTTP link — traffic and downloads can be intercepted or tampered with');
      if (riskLevel === 'medium') riskLevel = 'high';
    }
    if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/i.test(lower)) {
      findings.push('Direct IP address host instead of a verified domain name');
      riskLevel = 'critical';
    }
    if (/xn--/i.test(lower)) {
      findings.push('Punycode IDN domain detected (possible look-alike phishing URL)');
      riskLevel = 'high';
    }
    if (/(bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|t\.co|shorturl|is\.gd|ow\.ly)/i.test(lower)) {
      findings.push('Shortened redirect link obscures final destination domain');
      if (riskLevel === 'medium') riskLevel = 'high';
    }
    for (const rule of HIGH_RISK_NAME_PATTERNS) {
      if (rule.pattern.test(rawUrl)) {
        findings.push(rule.reason);
        if (rule.level === 'critical') riskLevel = 'critical';
      }
    }
    if (findings.length === 0) {
      findings.push('External link queued for inspection and permanent suppression if unwanted');
    }

    items.push({
      id: `link_${sha256.slice(0, 16)}`,
      category: 'link',
      fileName: rawUrl.slice(0, 250),
      normalizedName: normalized.slice(0, 250),
      relativePath: 'Shared / Browser Link',
      fileSize: 0,
      lastModified: Date.now(),
      sha256,
      packageHint: 'Category: Link',
      riskLevel,
      findings,
      hasManifest: false,
      hasDex: false,
      nativeArchCount: 0,
      embeddedApkCount: 0,
      source: 'manual_entry',
    });
  }

  return items;
}

export async function analyzeSmsOrCallInput(
  rawText: string,
  mode: 'sms' | 'call'
): Promise<ScannedApkItem[]> {
  const entries = rawText
    .split(/\n+/)
    .map((line) => line.trim())
    .filter((line) => line.length >= 3)
    .slice(0, 25);

  const items: ScannedApkItem[] = [];

  for (const entry of entries) {
    const normalized = normalizeApkName(`${mode}:${entry}`);
    const sha256 = await computeStringSha256Hex(normalized);
    const findings: string[] = [];
    let riskLevel: RiskLevel = 'medium';

    if (/(\*21\*|\*401\*|\*61\*|\*\*21\*|#21#)/i.test(entry)) {
      findings.push(
        'Call-forwarding USSD hijack code detected (*21* / *401*) — dial ##002# immediately on phone to disable forwarding'
      );
      riskLevel = 'critical';
    }
    if (/(https?:\/\/|bit\.ly|tinyurl|\.apk)/i.test(entry)) {
      findings.push('Contains clickable external URL or APK sideload lure inside message');
      riskLevel = 'critical';
    }
    if (/(anydesk|teamviewer|quicksupport|rustdesk|screen\s*share|otp|kyc|block|suspend|challan|aadhaar|pan\s*update|lottery|prize)/i.test(entry)) {
      findings.push('Matches financial KYC/OTP phishing or remote-access scam pattern');
      if (riskLevel !== 'critical') riskLevel = 'high';
    }
    if (mode === 'call' && /(\+\d{1,3}|\b\d{10,13}\b)/.test(entry)) {
      findings.push('Caller number queued — block number in Phone app and report spam/fraud calls at sancharsaathi.gov.in (Chakshu)');
    }
    if (findings.length === 0) {
      findings.push(
        mode === 'sms'
          ? 'SMS entry flagged — delete thread from Android Messages and report spam sender'
          : 'Call entry flagged — block caller in Android Phone app and check call-forwarding status (##002#)'
      );
    }

    items.push({
      id: `${mode}_${sha256.slice(0, 16)}`,
      category: mode,
      fileName: entry.slice(0, 250),
      normalizedName: normalized.slice(0, 250),
      relativePath: mode === 'sms' ? 'SMS Inbox Entry' : 'Call Log / Number',
      fileSize: 0,
      lastModified: Date.now(),
      sha256,
      packageHint: mode === 'sms' ? 'Category: SMS' : 'Category: Call',
      riskLevel,
      findings,
      hasManifest: false,
      hasDex: false,
      nativeArchCount: 0,
      embeddedApkCount: 0,
      source: 'manual_entry',
    });
  }

  return items;
}

export function isApkSuppressed(
  candidate: { sha256: string; normalizedName: string },
  deletedRecords: DeletedApkRecord[]
): boolean {
  return deletedRecords.some(
    (rec) =>
      rec.sha256 === candidate.sha256 ||
      rec.normalizedName === candidate.normalizedName
  );
}

export async function scanDirectoryHandleForApks(
  dirHandle: FileSystemDirectoryHandle,
  deletedRecords: DeletedApkRecord[],
  prefix = '',
  depth = 0
): Promise<{
  items: ScannedApkItem[];
  suppressedCount: number;
  totalFilesVisited: number;
  cleanFilesCount: number;
}> {
  const items: ScannedApkItem[] = [];
  let suppressedCount = 0;
  let totalFilesVisited = 0;
  let cleanFilesCount = 0;

  if (depth > 6) {
    return { items, suppressedCount, totalFilesVisited, cleanFilesCount };
  }

  for await (const [name, handle] of (dirHandle as unknown as {
    entries: () => AsyncIterableIterator<[string, FileSystemHandle]>;
  }).entries()) {
    const currentPath = prefix ? `${prefix}/${name}` : name;

    if (handle.kind === 'directory') {
      const sub = await scanDirectoryHandleForApks(
        handle as FileSystemDirectoryHandle,
        deletedRecords,
        currentPath,
        depth + 1
      );
      items.push(...sub.items);
      suppressedCount += sub.suppressedCount;
      totalFilesVisited += sub.totalFilesVisited;
      cleanFilesCount += sub.cleanFilesCount;
    } else if (handle.kind === 'file') {
      totalFilesVisited++;
      const fileHandle = handle as FileSystemFileHandle;
      const file = await fileHandle.getFile();

      const hasApkExt = isApkFileName(name);
      const hasPayloadExt = isSuspiciousPayloadFileName(name);

      // Magic-byte header check on smaller files (< 80MB) to detect disguised/renamed APKs
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
        cleanFilesCount++;
        continue;
      }

      const analyzed = await analyzeLocalApkFile(
        file,
        currentPath,
        'directory_handle',
        dirHandle
      );

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
        items.push(analyzed);
      }
    }
  }

  return { items, suppressedCount, totalFilesVisited, cleanFilesCount };
}
