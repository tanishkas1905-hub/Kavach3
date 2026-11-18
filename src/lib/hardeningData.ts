export type Language = 'en' | 'hi';

export interface HardeningStep {
  id: string;
  title: { en: string; hi: string };
  subtitle: { en: string; hi: string };
  androidPath: { en: string; hi: string };
  steps: { en: string[]; hi: string[] };
  severity: 'critical' | 'high' | 'medium';
}

export const HARDENING_STEPS: HardeningStep[] = [
  {
    id: 'empty_files_trash',
    title: {
      en: 'Delete APK from Downloads & Empty Trash Permanently',
      hi: 'Downloads से APK डिलीट करें और Trash खाली करें',
    },
    subtitle: {
      en: 'Android Files keeps deleted APKs in Trash for 30 days unless emptied manually.',
      hi: 'Android Files ऐप डिलीट की गई APK को 30 दिन तक Trash में रखता है, इसलिए Trash खाली करना ज़रूरी है।',
    },
    androidPath: {
      en: 'Files by Google -> Browse -> Downloads -> Delete -> Menu -> Trash -> Empty Trash',
      hi: 'Files ऐप -> Browse -> Downloads -> APK डिलीट करें -> Menu -> Trash -> Empty Trash',
    },
    steps: {
      en: [
        'Open the Files app on your Android phone and go to Downloads or Installation files (APKs).',
        'Select any .apk file you recognize as unwanted or suspicious and tap Delete.',
        'Open the side menu -> Trash -> Select all -> Delete permanently so the APK cannot be restored.',
      ],
      hi: [
        'अपने फोन में Files ऐप खोलें और Downloads या Apps -> App install files (APKs) में जाएं।',
        'जो भी अनचाही या संदिग्ध .apk फाइल दिखे, उसे चुनें और Delete पर टैप करें।',
        'अब साइड मेन्यू खोलें -> Trash में जाएं -> सभी चुनें -> Delete permanently दबाएं ताकि फाइल वापस न आ सके।',
      ],
    },
    severity: 'critical',
  },
  {
    id: 'revoke_accessibility_admin',
    title: {
      en: 'Revoke Suspicious Accessibility & Device Admin Apps',
      hi: 'संदिग्ध Accessibility और Device Admin अनुमतियां बंद करें',
    },
    subtitle: {
      en: 'Spyware and banking trojans abuse Accessibility and Device Admin to block uninstallation.',
      hi: 'हैकर्स और स्पाइवेयर ऐप खुद को डिलीट होने से रोकने के लिए Accessibility और Device Admin का इस्तेमाल करते हैं।',
    },
    androidPath: {
      en: 'Settings -> Accessibility -> Downloaded apps / Settings -> Security -> Device admin apps',
      hi: 'Settings -> Accessibility -> Downloaded apps / Settings -> Security -> Device admin apps',
    },
    steps: {
      en: [
        'Open Settings -> Accessibility -> Downloaded services and turn OFF any unknown app.',
        'Open Settings -> Security & privacy -> More security -> Device admin apps and deactivate unknown apps.',
        'Once deactivated, you can immediately uninstall the suspicious app cleanly.',
      ],
      hi: [
        'Settings -> Accessibility -> Downloaded apps में जाएं और किसी भी अनजान ऐप की अनुमति OFF करें।',
        'Settings -> Security -> Device admin apps में जाकर किसी भी अनजान ऐप को Deactivate करें।',
        'इसके बाद आप उस संदिग्ध ऐप को आसानी से Uninstall कर पाएंगे।',
      ],
    },
    severity: 'critical',
  },
  {
    id: 'uninstall_unknown_apps',
    title: {
      en: 'Remove Unknown or Blank-Icon Installed Apps',
      hi: 'अनजान या बिना नाम/आइकन वाले ऐप्स Uninstall करें',
    },
    subtitle: {
      en: 'Malicious APKs often hide with blank icons or generic names like "Update" or "System Service".',
      hi: 'खतरनाक APK इंस्टॉल होने के बाद "Update" या बिना नाम के आइकन में छिप जाते हैं।',
    },
    androidPath: {
      en: 'Settings -> Apps -> See all apps -> Sort by Last updated / Check bottom of list',
      hi: 'Settings -> Apps -> See all apps -> अनजान ऐप्स जांचें और Uninstall करें',
    },
    steps: {
      en: [
        'Go to Settings -> Apps -> See all apps and scroll carefully through the full list.',
        'Look for blank app names, generic "System Update" icons, or loan/KYC apps you never installed from Play Store.',
        'Tap the app -> Storage & cache -> Clear storage -> Back -> Uninstall.',
      ],
      hi: [
        'Settings -> Apps -> See all apps में जाएं और पूरी लिस्ट ध्यान से देखें।',
        'बिना नाम वाला ऐप, नकली "System Update", या अनजान Loan/KYC ऐप दिखे तो उस पर टैप करें।',
        'पहले Clear storage करें और फिर Uninstall बटन दबाकर ऐप को पूरी तरह हटा दें।',
      ],
    },
    severity: 'high',
  },
  {
    id: 'block_install_unknown',
    title: {
      en: 'Block "Install Unknown Apps" for Browsers & Messengers',
      hi: 'Chrome और WhatsApp के लिए "Install Unknown Apps" बंद करें',
    },
    subtitle: {
      en: 'Stops Chrome, WhatsApp, or Telegram from installing downloaded APK files automatically.',
      hi: 'इससे Chrome, WhatsApp या Telegram से कोई भी खतरनाक APK फाइल इंस्टॉल नहीं हो पाएगी।',
    },
    androidPath: {
      en: 'Settings -> Apps -> Special app access -> Install unknown apps',
      hi: 'Settings -> Apps -> Special app access -> Install unknown apps',
    },
    steps: {
      en: [
        'Open Settings -> Apps -> Special app access -> Install unknown apps.',
        'Toggle OFF permission for Chrome, WhatsApp, Telegram, File Manager, and all browsers.',
      ],
      hi: [
        'Settings -> Apps -> Special app access -> Install unknown apps खोलें।',
        'Chrome, WhatsApp, Telegram और File Manager के लिए "Allow from this source" को OFF कर दें।',
      ],
    },
    severity: 'high',
  },
  {
    id: 'run_play_protect',
    title: {
      en: 'Run Google Play Protect Deep Device Scan',
      hi: 'Google Play Protect से पूरा फोन स्कैन करें',
    },
    subtitle: {
      en: 'Verifies every installed package signature against Google malware intelligence.',
      hi: 'Play Protect फोन में मौजूद हर ऐप को स्कैन करके खतरनाक ऐप्स को पहचानता और ब्लॉक करता है।',
    },
    androidPath: {
      en: 'Google Play Store -> Profile Icon -> Play Protect -> Scan',
      hi: 'Google Play Store -> ऊपर प्रोफाइल आइकन -> Play Protect -> Scan',
    },
    steps: {
      en: [
        'Open Google Play Store -> Tap your Profile photo -> Play Protect.',
        'Tap Settings gear -> Enable "Scan apps with Play Protect" and "Improve harmful app detection".',
        'Tap Scan and uninstall anything flagged immediately.',
      ],
      hi: [
        'Play Store खोलें -> दाईं ओर Profile आइकन -> Play Protect पर टैप करें।',
        'Settings आइकन में "Scan apps with Play Protect" को ON रखें।',
        'Scan बटन दबाएं और कोई भी खतरनाक ऐप मिले तो तुरंत हटाएं।',
      ],
    },
    severity: 'medium',
  },
  {
    id: 'audit_sessions_2fa',
    title: {
      en: 'Audit Google Sessions, Banking Apps & Enable 2FA',
      hi: 'Google लॉगिन डिवाइस जांचें और 2-Step Verification चालू करें',
    },
    subtitle: {
      en: 'Sign out unrecognized devices and change banking/UPI PINs if a malicious APK was opened.',
      hi: 'अगर कोई संदिग्ध APK खुल गया था, तो अनजान लॉगिन हटाएं और पासवर्ड/UPI पिन बदलें।',
    },
    androidPath: {
      en: 'Settings -> Google -> Manage your Google Account -> Security -> Your devices',
      hi: 'Settings -> Google -> Manage your Google Account -> Security -> Your devices',
    },
    steps: {
      en: [
        'Check Security -> Your devices and sign out any device you do not recognize.',
        'Turn ON 2-Step Verification and review active WhatsApp Linked Devices.',
        'If financial fraud occurred, call India National Cyber Crime Helpline 1930 or report at cybercrime.gov.in.',
      ],
      hi: [
        'Google Account -> Security -> Your devices में अनजान डिवाइस को Sign out करें।',
        '2-Step Verification चालू करें और WhatsApp में Linked Devices भी चेक करें।',
        'अगर कोई फ्रॉड हुआ है तो तुरंत हेल्पलाइन 1930 पर कॉल करें या cybercrime.gov.in पर रिपोर्ट करें।',
      ],
    },
    severity: 'medium',
  },
];

export const CITIZEN_PORTALS = [
  {
    name: 'National Cyber Crime Reporting Portal',
    url: 'https://cybercrime.gov.in',
    detail: {
      en: 'Official portal for reporting cyber fraud, hacked accounts, and malicious apps.',
      hi: 'साइबर फ्रॉड, हैक किए गए अकाउंट और खतरनाक ऐप्स की शिकायत दर्ज करने का आधिकारिक पोर्टल।',
    },
    actionLabel: 'cybercrime.gov.in · Helpline 1930',
  },
  {
    name: 'Sanchar Saathi · Chakshu',
    url: 'https://sancharsaathi.gov.in',
    detail: {
      en: 'Report suspected fraud SMS, WhatsApp APK phishing messages, and check active SIMs.',
      hi: 'संदिग्ध फ्रॉड SMS, WhatsApp APK लिंक की रिपोर्ट करें और अपने नाम पर सक्रिय सिम जांचें।',
    },
    actionLabel: 'sancharsaathi.gov.in',
  },
  {
    name: 'Google Account Device Activity',
    url: 'https://myaccount.google.com/device-activity',
    detail: {
      en: 'Inspect and revoke unrecognized phones or browsers signed into your Google account.',
      hi: 'अपने Google अकाउंट में लॉगिन सभी अनजान मोबाइल और ब्राउज़र को तुरंत हटाएं।',
    },
    actionLabel: 'myaccount.google.com',
  },
];
