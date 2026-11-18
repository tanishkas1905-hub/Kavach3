import React, { useState } from 'react';
import {
  CheckSquare,
  Square,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';
import {
  CITIZEN_PORTALS,
  HARDENING_STEPS,
  type Language,
} from '../lib/hardeningData';

interface HardeningPanelProps {
  language: Language;
  completedMap: Record<string, boolean>;
  onToggleStep: (stepId: string, nextVal: boolean) => Promise<void>;
}

export const HardeningPanel: React.FC<HardeningPanelProps> = ({
  language,
  completedMap,
  onToggleStep,
}) => {
  const [expandedId, setExpandedId] = useState<string>(HARDENING_STEPS[0].id);
  const isHi = language === 'hi';

  const completedCount = HARDENING_STEPS.filter((s) => completedMap[s.id]).length;
  const pct = Math.round((completedCount / HARDENING_STEPS.length) * 100);

  return (
    <div className="space-y-6">
      {/* Progress Summary */}
      <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-5 sm:p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <h1 className="text-xl sm:text-2xl font-semibold text-slate-50">
              {isHi
                ? 'मोबाइल को हैकिंग से पूरी तरह सुरक्षित करने की गाइड'
                : 'Android Anti-Hacking Hardening Checklist'}
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed">
              {isHi
                ? 'APK डिलीट करने के बाद नीचे दिए गए 6 सुरक्षित कदम पूरे करें ताकि कोई भी हैकर या संदिग्ध ऐप आपके फोन तक न पहुंच सके।'
                : 'Complete these 6 verified Android hardening checks to permanently remove hidden installers, revoke spyware permissions, and secure your accounts.'}
            </p>
          </div>

          <div className="bg-[#080C14] border border-slate-800 rounded-xl px-4 py-3 shrink-0 min-w-[160px]">
            <div className="text-xs text-slate-400">
              {isHi ? 'सुरक्षा प्रगति' : 'Checks Completed'}
            </div>
            <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400 mt-0.5">
              {completedCount} / {HARDENING_STEPS.length}
            </div>
          </div>
        </div>

        <div className="w-full h-2 bg-[#080C14] rounded-full overflow-hidden border border-slate-800">
          <div
            className="h-full bg-emerald-500 transition-all duration-300"
            style={{ width: `${pct}%` }}
          />
        </div>
      </section>

      {/* Checklist Steps */}
      <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl divide-y divide-slate-800/80 overflow-hidden">
        {HARDENING_STEPS.map((step, index) => {
          const isDone = Boolean(completedMap[step.id]);
          const isOpen = expandedId === step.id;

          return (
            <div key={step.id} className="p-4 sm:p-5 space-y-3">
              <div className="flex items-start justify-between gap-3">
                <button
                  type="button"
                  onClick={() => void onToggleStep(step.id, !isDone)}
                  className="flex items-start gap-3 text-left min-h-[44px] flex-1"
                >
                  <span className="mt-0.5 text-emerald-400 shrink-0">
                    {isDone ? (
                      <CheckSquare className="w-5 h-5" />
                    ) : (
                      <Square className="w-5 h-5 text-slate-500" />
                    )}
                  </span>
                  <span className="space-y-1">
                    <span
                      className={`block text-sm sm:text-base font-semibold ${
                        isDone ? 'text-slate-400 line-through' : 'text-slate-100'
                      }`}
                    >
                      0{index + 1}. {step.title[language]}
                    </span>
                    <span className="block text-xs text-slate-400 leading-relaxed">
                      {step.subtitle[language]}
                    </span>
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => setExpandedId(isOpen ? '' : step.id)}
                  aria-label="Toggle instructions"
                  className="min-h-[44px] min-w-[44px] flex items-center justify-center rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800/70 transition-colors shrink-0"
                >
                  {isOpen ? (
                    <ChevronUp className="w-4 h-4" />
                  ) : (
                    <ChevronDown className="w-4 h-4" />
                  )}
                </button>
              </div>

              {isOpen && (
                <div className="pl-8 space-y-3 pt-1">
                  <div className="text-xs font-mono text-emerald-300 bg-[#080C14] border border-slate-800 rounded-lg px-3 py-2 break-words">
                    {step.androidPath[language]}
                  </div>
                  <ol className="space-y-1.5 text-sm text-slate-300 list-decimal list-inside">
                    {step.steps[language].map((line, i) => (
                      <li key={i} className="leading-relaxed">
                        {line}
                      </li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
          );
        })}
      </section>

      {/* Public Citizen Cyber-Safety Reporting Portals */}
      <section className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-5 sm:p-6 space-y-4">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
          <h2 className="text-base font-semibold text-slate-100">
            {isHi
              ? 'आधिकारिक नागरिक साइबर सुरक्षा सहायता पोर्टल'
              : 'Official Citizen Cyber-Safety & Fraud Reporting Resources'}
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {CITIZEN_PORTALS.map((portal) => (
            <a
              key={portal.url}
              href={portal.url}
              target="_blank"
              rel="noopener noreferrer"
              className="bg-[#080C14] border border-slate-800 rounded-xl p-4 flex flex-col justify-between gap-3 hover:border-slate-600 transition-colors"
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-slate-100">
                    {portal.name}
                  </h3>
                  <ExternalLink className="w-4 h-4 text-slate-400 shrink-0" />
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {portal.detail[language]}
                </p>
              </div>
              <span className="text-xs font-mono text-emerald-400">
                {portal.actionLabel}
              </span>
            </a>
          ))}
        </div>
      </section>
    </div>
  );
};
