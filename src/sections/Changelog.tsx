import { useEffect, useState } from 'react';
import { 
  GitCommit, 
  Sparkles, 
  Bug, 
  Zap, 
  Shield,
  ChevronDown,
  ChevronUp,
  Calendar
} from 'lucide-react';
import { Button } from '@/components/ui/button';

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
  feature: 'text-blue-500 bg-blue-500/10 border-blue-500/20',
  fix: 'text-red-500 bg-red-500/10 border-red-500/20',
  improvement: 'text-green-500 bg-green-500/10 border-green-500/20',
  security: 'text-purple-500 bg-purple-500/10 border-purple-500/20',
};

export function Changelog() {
  const [expandedVersions, setExpandedVersions] = useState<string[]>(['2.0.0']);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('in-view');
          }
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px -10% 0px' }
    );

    const elements = document.querySelectorAll('#changelog .animate-on-scroll');
    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  const toggleVersion = (version: string) => {
    setExpandedVersions((prev) =>
      prev.includes(version)
        ? prev.filter((v) => v !== version)
        : [...prev, version]
    );
  };

  return (
    <section id="changelog" className="zxwy-section relative">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-primary/5 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 animate-on-scroll">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
            <GitCommit className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">Updates</span>
          </div>
          <h2 className="text-4xl sm:text-5xl font-bold mb-6">
            <span className="zxwy-gradient-text">Changelog</span>
          </h2>
          <p className="text-lg text-muted-foreground">
            Track all updates and improvements to ZXWY. See what's new in V2 
            and browse our version history.
          </p>
        </div>

        {/* Changelog Entries */}
        <div className="space-y-4">
          {changelogData.map((entry, index) => {
            const isExpanded = expandedVersions.includes(entry.version);
            const isLatest = index === 0;

            return (
              <div
                key={entry.version}
                className={`animate-on-scroll delay-${(index % 3) + 1}`}
              >
                <div 
                  className={`
                    relative rounded-2xl border overflow-hidden transition-all duration-300
                    ${isLatest 
                      ? 'bg-primary/5 border-primary/30' 
                      : 'bg-card border-border hover:border-primary/20'
                    }
                  `}
                >
                  {/* Latest Badge */}
                  {isLatest && (
                    <div className="absolute top-4 right-4">
                      <span className="px-3 py-1 rounded-full bg-primary text-primary-foreground text-xs font-medium">
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
                        ? 'bg-primary/20 text-primary' 
                        : entry.type === 'minor'
                        ? 'bg-primary/10 text-primary/80'
                        : 'bg-muted text-muted-foreground'
                      }
                    `}>
                      <GitCommit className="w-6 h-6" />
                    </div>

                    {/* Version Info */}
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-1">
                        <h3 className="text-xl font-bold">Version {entry.version}</h3>
                        {entry.type === 'major' && (
                          <span className="px-2 py-0.5 rounded bg-primary/10 text-primary text-xs font-medium">
                            Major
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Calendar className="w-4 h-4" />
                        {entry.date}
                      </div>
                    </div>

                    {/* Toggle Icon */}
                    <div className="w-8 h-8 rounded-lg bg-muted flex items-center justify-center">
                      {isExpanded ? (
                        <ChevronUp className="w-5 h-5 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="w-5 h-5 text-muted-foreground" />
                      )}
                    </div>
                  </button>

                  {/* Changes List */}
                  <div 
                    className={`
                      overflow-hidden transition-all duration-300
                      ${isExpanded ? 'max-h-[1000px] opacity-100' : 'max-h-0 opacity-0'}
                    `}
                  >
                    <div className="px-6 pb-6">
                      <div className="border-t border-border pt-4">
                        <div className="space-y-3">
                          {entry.changes.map((change, changeIndex) => {
                            const Icon = typeIcons[change.type];
                            return (
                              <div
                                key={changeIndex}
                                className="flex items-start gap-3 p-3 rounded-xl bg-background/50"
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
                                  <p className="text-sm text-foreground">
                                    {change.description}
                                  </p>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* View All Button */}
        <div className="text-center mt-8 animate-on-scroll">
          <Button variant="outline" className="zxwy-btn-secondary">
            View Full Changelog on GitHub
          </Button>
        </div>
      </div>
    </section>
  );
}
