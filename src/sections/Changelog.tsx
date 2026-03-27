import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { GitCommit, Sparkles, Bug, Zap, Shield, ChevronDown, Calendar } from 'lucide-react';

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
    version: '2.0.0',
    date: 'February 2025',
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
    date: 'January 2025',
    type: 'patch',
    changes: [
      { type: 'fix', description: 'Fixed GPU tweak not applying on some systems' },
      { type: 'fix', description: 'Corrected registry backup path' },
      { type: 'improvement', description: 'Better error messages' },
    ],
  },
  {
    version: '1.5.0',
    date: 'December 2024',
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
    date: 'November 2024',
    type: 'patch',
    changes: [
      { type: 'fix', description: 'Fixed memory leak in monitoring module' },
      { type: 'fix', description: 'Resolved compatibility issue with AMD systems' },
    ],
  },
  {
    version: '1.4.0',
    date: 'October 2024',
    type: 'minor',
    changes: [
      { type: 'feature', description: 'Added custom power plan creator' },
      { type: 'feature', description: 'New game mode toggle' },
      { type: 'improvement', description: 'Reduced application size by 30%' },
    ],
  },
];

const typeIcons = {
  feature: Sparkles,
  fix: Bug,
  improvement: Zap,
  security: Shield,
};

const typeLabels = {
  feature: 'New Feature',
  fix: 'Bug Fix',
  improvement: 'Improvement',
  security: 'Security',
};

const typeColors = {
  feature: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  fix: 'text-red-400 bg-red-400/10 border-red-400/30',
  improvement: 'text-green-400 bg-green-400/10 border-green-400/30',
  security: 'text-purple-400 bg-purple-400/10 border-purple-400/30',
};

export function Changelog() {
  const [expandedVersions, setExpandedVersions] = useState<string[]>(['2.0.0']);

  const toggleVersion = (version: string) => {
    setExpandedVersions((prev) =>
      prev.includes(version)
        ? prev.filter((v) => v !== version)
        : [...prev, version]
    );
  };

  return (
    <section id="changelog" className="relative py-24 md:py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-[#22c55e]/5 rounded-full blur-[150px]" />
      </div>

      <div className="section-container relative z-10 max-w-4xl mx-auto">
        {/* Section Header */}
        <motion.div 
          className="text-center max-w-3xl mx-auto mb-16"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#22c55e]/10 border border-[#22c55e]/30 mb-6">
            <GitCommit className="w-4 h-4 text-[#22c55e]" />
            <span className="text-sm font-medium text-[#22c55e]">Updates</span>
          </div>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6">
            <span className="gradient-text">Changelog</span>
          </h2>
          <p className="text-lg text-white/60">
            Track all updates and improvements to ZXWY. See what's new in V2 
            and browse our version history.
          </p>
        </motion.div>

        {/* Changelog Entries */}
        <div className="space-y-4">
          {changelogData.map((entry, index) => {
            const isExpanded = expandedVersions.includes(entry.version);
            const isLatest = index === 0;

            return (
              <motion.div
                key={entry.version}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.1, duration: 0.5 }}
              >
                <div 
                  className={`
                    relative rounded-2xl border overflow-hidden transition-all duration-300
                    ${isLatest 
                      ? 'bg-[#22c55e]/5 border-[#22c55e]/30' 
                      : 'glass-card'
                    }
                  `}
                >
                  {/* Latest Badge */}
                  {isLatest && (
                    <div className="absolute top-4 right-4">
                      <span className="px-3 py-1 rounded-full bg-[#22c55e] text-black text-xs font-semibold">
                        Latest
                      </span>
                    </div>
                  )}

                  {/* Header */}
                  <button
                    onClick={() => toggleVersion(entry.version)}
                    className="w-full p-6 flex items-center gap-4 text-left"
                  >
                    {/* Version Icon */}
                    <div className={`
                      w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0
                      ${entry.type === 'major' 
                        ? 'bg-[#22c55e]/20 text-[#22c55e]' 
                        : entry.type === 'minor'
                        ? 'bg-[#22c55e]/10 text-[#22c55e]/80'
                        : 'bg-white/5 text-white/50'
                      }
                    `}>
                      <GitCommit className="w-6 h-6" />
                    </div>

                    {/* Version Info */}
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-1">
                        <h3 className="text-xl font-bold">Version {entry.version}</h3>
                        {entry.type === 'major' && (
                          <span className="px-2 py-0.5 rounded bg-[#22c55e]/10 text-[#22c55e] text-xs font-medium">
                            Major
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-sm text-white/50">
                        <Calendar className="w-4 h-4" />
                        {entry.date}
                      </div>
                    </div>

                    {/* Toggle Icon */}
                    <motion.div 
                      className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center"
                      animate={{ rotate: isExpanded ? 180 : 0 }}
                      transition={{ duration: 0.3 }}
                    >
                      <ChevronDown className="w-5 h-5 text-white/50" />
                    </motion.div>
                  </button>

                  {/* Changes List */}
                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        <div className="px-6 pb-6">
                          <div className="border-t border-white/10 pt-4">
                            <div className="space-y-3">
                              {entry.changes.map((change, changeIndex) => {
                                const Icon = typeIcons[change.type];
                                return (
                                  <motion.div
                                    key={changeIndex}
                                    className="flex items-start gap-3 p-3 rounded-xl bg-white/5"
                                    initial={{ opacity: 0, x: -10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: changeIndex * 0.05 }}
                                  >
                                    <div className={`
                                      w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0
                                      border ${typeColors[change.type]}
                                    `}>
                                      <Icon className="w-4 h-4" />
                                    </div>
                                    <div className="flex-1">
                                      <span className={`
                                        text-xs font-medium px-2 py-0.5 rounded mb-1 inline-block
                                        ${typeColors[change.type]}
                                      `}>
                                        {typeLabels[change.type]}
                                      </span>
                                      <p className="text-sm text-white/80">
                                        {change.description}
                                      </p>
                                    </div>
                                  </motion.div>
                                );
                              })}
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
