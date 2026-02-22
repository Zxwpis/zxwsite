import { useEffect } from 'react';
import { 
  Zap, 
  Shield, 
  Cpu, 
  Gauge, 
  RefreshCw, 
  Gamepad2,
  Layers,
  Settings
} from 'lucide-react';

const features = [
  {
    icon: Zap,
    title: 'Performance Boost',
    description: 'Optimize Windows services, registry, and power settings for maximum gaming performance.',
    stat: '+40% FPS',
  },
  {
    icon: Shield,
    title: 'Safe & Reversible',
    description: 'All tweaks include automatic restore points. One-click rollback anytime.',
    stat: '100% Safe',
  },
  {
    icon: Cpu,
    title: 'System Debloat',
    description: 'Remove unnecessary Windows bloatware and background processes.',
    stat: '-15%',
  },
  {
    icon: Gauge,
    title: 'Latency Reduction',
    description: 'Minimize input lag with advanced timer and interrupt optimizations.',
    stat: '-30% Latency',
  },
  {
    icon: RefreshCw,
    title: 'Auto Updates',
    description: 'Get the latest optimizations automatically with our update system.',
    stat: 'Always Current',
  },
  {
    icon: Gamepad2,
    title: 'Gaming Focused',
    description: 'Specifically designed for gamers who demand the best performance.',
    stat: 'Proven Results',
  },
];

const v2Improvements = [
  {
    icon: Layers,
    title: 'New UI',
    description: 'Completely redesigned interface for easier navigation and control.',
  },
  {
    icon: Settings,
    title: 'More Options',
    description: '50+ new tweak options for fine-tuning your system.',
  },
];

export function Features() {
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

    const elements = document.querySelectorAll('#features .animate-on-scroll');
    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  return (
    <section id="features" className="zxwy-section relative">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-primary/5 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 animate-on-scroll">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
            <Zap className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">Powerful Features</span>
          </div>
          <h2 className="text-4xl sm:text-5xl font-bold mb-6">
            Everything You Need for
            <span className="zxwy-gradient-text block mt-2">Maximum Performance</span>
          </h2>
          <p className="text-lg text-muted-foreground">
            ZXWY V2 combines powerful optimization tools with an intuitive interface 
            to give you complete control over your system's performance.
          </p>
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-20">
          {features.map((feature, index) => (
            <div
              key={feature.title}
              className={`zxwy-card group animate-on-scroll delay-${(index % 3) + 1}`}
            >
              {/* Icon */}
              <div className="w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center mb-5 group-hover:bg-primary/20 transition-colors">
                <feature.icon className="w-7 h-7 text-primary" />
              </div>

              {/* Content */}
              <h3 className="text-xl font-semibold mb-2">{feature.title}</h3>
              <p className="text-muted-foreground mb-4">{feature.description}</p>

              {/* Stat Badge */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 text-primary text-sm font-medium">
                {feature.stat}
              </div>
            </div>
          ))}
        </div>

        {/* V2 Improvements */}
        <div className="animate-on-scroll">
          <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-primary/10 via-primary/5 to-transparent border border-primary/20 p-8 md:p-12">
            {/* Background Glow */}
            <div className="absolute top-0 right-0 w-96 h-96 bg-primary/20 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
            
            <div className="relative grid lg:grid-cols-2 gap-12 items-center">
              {/* Left Content */}
              <div>
                <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/20 border border-primary/30 mb-6">
                  <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                  <span className="text-sm font-medium text-primary">What's New in V2</span>
                </div>
                <h3 className="text-3xl md:text-4xl font-bold mb-4">
                  Major Upgrade from
                  <span className="zxwy-gradient-text block mt-1">Version 1</span>
                </h3>
                <p className="text-muted-foreground text-lg mb-8">
                  We've completely rebuilt ZXWY from the ground up with new features, 
                  better performance, and a more intuitive experience.
                </p>
                
                {/* Improvement Stats */}
                <div className="flex flex-wrap gap-4">
                  <div className="px-4 py-2 rounded-xl bg-card border border-border">
                    <div className="text-2xl font-bold text-primary">3x</div>
                    <div className="text-sm text-muted-foreground">Faster</div>
                  </div>
                  <div className="px-4 py-2 rounded-xl bg-card border border-border">
                    <div className="text-2xl font-bold text-primary">50+</div>
                    <div className="text-sm text-muted-foreground">New Tweaks</div>
                  </div>
                  <div className="px-4 py-2 rounded-xl bg-card border border-border">
                    <div className="text-2xl font-bold text-primary">0</div>
                    <div className="text-sm text-muted-foreground">Bugs</div>
                  </div>
                </div>
              </div>

              {/* Right Content - Improvements List */}
              <div className="space-y-4">
                {v2Improvements.map((improvement) => (
                  <div 
                    key={improvement.title}
                    className="flex items-start gap-4 p-5 rounded-2xl bg-card/80 border border-border hover:border-primary/30 transition-colors"
                  >
                    <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <improvement.icon className="w-6 h-6 text-primary" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-lg mb-1">{improvement.title}</h4>
                      <p className="text-muted-foreground text-sm">{improvement.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
