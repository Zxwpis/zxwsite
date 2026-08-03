import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown } from 'lucide-react';
import { useSectionReveal } from '../lib/anim';
import { HeadingFlip } from '../components/HeadingFlip';

interface ChangelogEntry {
  version: string;
  date: string;
  type: 'major' | 'minor' | 'patch';
  changes: {
    type: 'feature' | 'fix' | 'improvement' | 'security';
    description: string;
  }[];
}

const changelogData: ChangelogEntry[] = [
  {
    version: '3.0.0',
    date: 'July 2026',
    type: 'major',
    changes: [
      { type: 'feature', description: 'Complete UI redesign with modern interface' },
      { type: 'feature', description: 'Added 50+ new tweak options' },
      { type: 'feature', description: 'New automatic restore point system' },
      { type: 'improvement', description: '3x faster tweak application speed' },
      { type: 'improvement', description: 'Enhanced Windows 11 compatibility' },
      { type: 'security', description: 'Improved safety checks before applying tweaks' },
      { type: 'fix', description: 'Fixed rare crash on startup' },
      { type: 'fix', description: 'Resolved power plan conflicts' },
    ],
  },
  {
    version: '2.0.0',
    date: 'February 2026',
    type: 'major',
    changes: [
      { type: 'feature', description: 'Complete UI redesign with modern interface' },
      { type: 'feature', description: 'Added 50+ new tweak options' },
      { type: 'feature', description: 'New automatic restore point system' },
      { type: 'improvement', description: '3x faster tweak application speed' },
      { type: 'improvement', description: 'Enhanced Windows 11 compatibility' },
      { type: 'security', description: 'Improved safety checks before applying tweaks' },
      { type: 'fix', description: 'Fixed rare crash on startup' },
      { type: 'fix', description: 'Resolved power plan conflicts' },
    ],
  },
  {
    version: '1.5.2',
    date: 'January 2026',
    type: 'patch',
    changes: [
      { type: 'fix', description: 'Fixed GPU tweak not applying on some systems' },
      { type: 'fix', description: 'Corrected registry backup path' },
      { type: 'improvement', description: 'Better error messages' },
    ],
  },
  {
    version: '1.5.0',
    date: 'December 2025',
    type: 'minor',
    changes: [
      { type: 'feature', description: 'Added BIOS optimization guide' },
      { type: 'feature', description: 'New latency reduction module' },
      { type: 'improvement', description: 'Updated service disable list' },
      { type: 'security', description: 'Added digital signature verification' },
    ],
  },
  {
    version: '1.4.1',
    date: 'November 2025',
    type: 'patch',
    changes: [
      { type: 'fix', description: 'Fixed memory leak in monitoring module' },
      { type: 'fix', description: 'Resolved compatibility issue with AMD systems' },
    ],
  },
  {
    version: '1.4.0',
    date: 'October 2025',
    type: 'minor',
    changes: [
      { type: 'feature', description: 'Added custom power plan creator' },
      { type: 'feature', description: 'New game mode toggle' },
      { type: 'improvement', description: 'Reduced application size by 30%' },
    ],
  },
];

const typeLabels = {
  feature: 'New Feature',
  fix: 'Bug Fix',
  improvement: 'Improvement',
  security: 'Security',
};

export function Changelog() {
  const ref = useSectionReveal();
  const [expandedVersions, setExpandedVersions] = useState<string[]>(['3.0.0']);

  const toggleVersion = (version: string) => {
    setExpandedVersions((prev) =>
      prev.includes(version)
        ? prev.filter((v) => v !== version)
        : [...prev, version]
    );
  };

  return (
    <section id="changelog" ref={ref} className="section-shell bg-transparent">
      <div className="section-glow bottom-0 h-[380px] w-[640px] opacity-35" />

      <div className="section-container relative z-10 max-w-3xl">
        <div className="section-head" data-reveal>
          <span className="pill-outline">Updates</span>
          <HeadingFlip
            className="section-title"
            front={[{ text: 'Changelog', lime: true }]}
            back={[{ text: 'Always shipping', lime: true }]}
          />
          <p className="section-lede">
            Track all updates and improvements to ZXWY. See what&apos;s new in V3
            and browse our version history.
          </p>
        </div>

        {/* Editorial timeline */}
        <div className="relative">
          <div
            className="absolute bottom-4 left-[19px] top-4 w-px bg-[#16191a]/10 md:left-[23px]"
            aria-hidden="true"
          />

          <div className="space-y-5">
            {changelogData.map((entry, index) => {
              const isExpanded = expandedVersions.includes(entry.version);
              const isLatest = index === 0;

              return (
                <div key={entry.version} data-reveal className="relative pl-12 md:pl-14">
                  {/* Timeline node */}
                  <span
                    className={`absolute left-0 top-8 grid h-10 w-10 place-items-center rounded-full border md:h-12 md:w-12 ${
                      isLatest
                        ? 'border-[#36FE35]/40 bg-[#36FE35]'
                        : 'border-[#16191a]/10 bg-white'
                    }`}
                    aria-hidden="true"
                  >
                    <span
                      className={`h-2 w-2 rounded-full ${
                        isLatest ? 'bg-[#16191a]' : 'bg-[#16191a]/30'
                      }`}
                    />
                  </span>

                  <article
                    className={
                      isLatest
                        ? 'card-ink !p-0'
                        : 'card-paper !p-0'
                    }
                  >
                    <button
                      type="button"
                      onClick={() => toggleVersion(entry.version)}
                      className="flex w-full items-start gap-4 p-6 text-left md:p-7"
                      aria-expanded={isExpanded}
                      aria-controls={`changelog-${entry.version}`}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="mb-3 flex flex-wrap items-center gap-2">
                          <span className={isLatest ? 'pill-lime' : 'pill-ink'}>
                            v{entry.version}
                          </span>
                          {entry.type === 'major' && (
                            <span
                              className={
                                isLatest
                                  ? 'rounded-full border border-white/20 px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-[0.16em] text-white/70'
                                  : 'pill-outline'
                              }
                            >
                              Major
                            </span>
                          )}
                          {isLatest && (
                            <span className="rounded-full border border-[#36FE35]/40 bg-[#36FE35]/15 px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-[0.16em] text-[#36FE35]">
                              Latest
                            </span>
                          )}
                        </div>
                        <div className="flex flex-wrap items-center gap-3">
                          <h3
                            className={`text-lg font-semibold tracking-tight md:text-xl ${
                              isLatest ? 'text-white' : 'text-[#16191a]'
                            }`}
                          >
                            Version {entry.version}
                          </h3>
                          <span
                            className={`index-tag ${
                              isLatest ? 'text-white/50 opacity-100' : ''
                            }`}
                          >
                            {entry.date}
                          </span>
                        </div>
                      </div>

                      <span
                        className={`grid h-9 w-9 shrink-0 place-items-center rounded-full border transition-transform duration-300 ${
                          isExpanded ? 'rotate-180' : ''
                        } ${
                          isLatest
                            ? 'border-white/15 text-white/70'
                            : 'border-[#16191a]/10 text-[#16191a]/55'
                        }`}
                        aria-hidden="true"
                      >
                        <ChevronDown className="h-4 w-4" />
                      </span>
                    </button>

                    <AnimatePresence initial={false}>
                      {isExpanded && (
                        <motion.div
                          id={`changelog-${entry.version}`}
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.28, ease: [0.23, 1, 0.32, 1] }}
                          className="overflow-hidden"
                        >
                          <div
                            className={`mx-6 mb-6 border-t pt-5 md:mx-7 md:mb-7 ${
                              isLatest ? 'border-white/10' : 'border-[#16191a]/10'
                            }`}
                          >
                            <ul className="space-y-3">
                              {entry.changes.map((change, changeIndex) => (
                                <li
                                  key={changeIndex}
                                  className="flex items-start gap-3"
                                >
                                  <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-[#36FE35]" />
                                  <div className="min-w-0 flex-1">
                                    <span
                                      className={`mb-1 inline-block font-mono text-[10px] font-bold uppercase tracking-[0.18em] ${
                                        isLatest
                                          ? 'text-[#36FE35]/80'
                                          : 'text-[#16191a]/45'
                                      }`}
                                    >
                                      {typeLabels[change.type]}
                                    </span>
                                    <p
                                      className={`text-sm leading-relaxed ${
                                        isLatest
                                          ? 'text-white/70'
                                          : 'text-[#16191a]/70'
                                      }`}
                                    >
                                      {change.description}
                                    </p>
                                  </div>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </article>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
