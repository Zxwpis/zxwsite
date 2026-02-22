import { useEffect, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { 
  Download, 
  ArrowRight, 
  Cpu, 
  Gauge, 
  Shield,
  Sparkles,
  TrendingUp,
  Activity
} from 'lucide-react';

export function Hero() {
  const metricsRef = useRef<HTMLDivElement>(null);

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

    const elements = document.querySelectorAll('.animate-on-scroll');
    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  const scrollToDownload = () => {
    const element = document.querySelector('#download');
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const scrollToFeatures = () => {
    const element = document.querySelector('#features');
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <section id="hero" className="relative min-h-screen flex items-center pt-24 pb-16 overflow-hidden">
      {/* Background Decorations */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 right-0 w-[600px] h-[600px] bg-primary/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 left-0 w-[400px] h-[400px] bg-primary/10 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left Content */}
          <div className="space-y-8 animate-on-scroll">
            {/* Badge */}
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20">
              <Sparkles className="w-4 h-4 text-primary" />
              <span className="text-sm font-medium text-primary">
                ZXWY V2 is Now Available
              </span>
            </div>

            {/* Title */}
            <div className="space-y-4">
              <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight">
                <span className="block text-foreground">ZXWY</span>
                <span className="block zxwy-gradient-text">VERSION 2</span>
              </h1>
              <p className="text-xl text-muted-foreground max-w-lg">
                The ultimate PC optimization toolkit. Boost performance, reduce latency, 
                and unlock your system's full potential.
              </p>
            </div>

            {/* Stats */}
            <div className="flex flex-wrap gap-6">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                  <TrendingUp className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <div className="text-2xl font-bold">+40%</div>
                  <div className="text-sm text-muted-foreground">FPS Boost</div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                  <Activity className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <div className="text-2xl font-bold">-30%</div>
                  <div className="text-sm text-muted-foreground">Latency</div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                  <Shield className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <div className="text-2xl font-bold">100%</div>
                  <div className="text-sm text-muted-foreground">Safe</div>
                </div>
              </div>
            </div>

            {/* CTA Buttons */}
            <div className="flex flex-wrap gap-4">
              <Button 
                size="lg" 
                onClick={scrollToDownload}
                className="zxwy-btn-primary gap-2 text-base"
              >
                <Download className="w-5 h-5" />
                Download V2 Free
              </Button>
              <Button 
                size="lg" 
                variant="outline"
                onClick={scrollToFeatures}
                className="zxwy-btn-secondary gap-2 text-base"
              >
                Explore Features
                <ArrowRight className="w-5 h-5" />
              </Button>
            </div>

          </div>

          {/* Right Content - Metrics Panel */}
          <div 
            ref={metricsRef}
            className="animate-on-scroll delay-2"
          >
            <div className="relative">
              {/* Glow Effect */}
              <div className="absolute -inset-4 bg-primary/20 rounded-3xl blur-2xl animate-pulse-glow" />
              
              {/* Panel */}
              <div className="relative bg-card border border-border rounded-2xl overflow-hidden shadow-2xl">
                {/* Panel Header */}
                <div className="flex items-center gap-2 px-4 py-3 bg-muted/50 border-b border-border">
                  <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500" />
                    <div className="w-3 h-3 rounded-full bg-green-500" />
                  </div>
                  <span className="ml-auto text-xs font-mono text-muted-foreground">
                    zxwy_v2_system_monitor.exe
                  </span>
                </div>

                {/* Panel Content */}
                <div className="p-6 space-y-6">
                  {/* Metric 1 - FPS Stability */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Gauge className="w-4 h-4 text-primary" />
                        <span className="text-sm font-medium">FPS Stability</span>
                      </div>
                      <span className="text-sm font-mono text-primary">98.7%</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-primary to-accent rounded-full metric-bar-fill"
                        style={{ animationDelay: '0s' }}
                      />
                    </div>
                  </div>

                  {/* Metric 2 - System Clarity */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-primary" />
                        <span className="text-sm font-medium">System Clarity</span>
                      </div>
                      <span className="text-sm font-mono text-primary">94.2%</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-primary to-accent rounded-full metric-bar-fill"
                        style={{ animationDelay: '0.5s', animationDuration: '3.5s' }}
                      />
                    </div>
                  </div>

                  {/* Metric 3 - Latency */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Activity className="w-4 h-4 text-primary" />
                        <span className="text-sm font-medium">Input Latency</span>
                      </div>
                      <span className="text-sm font-mono text-primary">2.1ms</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-primary to-accent rounded-full metric-bar-fill"
                        style={{ animationDelay: '1s', animationDuration: '4s' }}
                      />
                    </div>
                  </div>

                  {/* Metric 4 - Risk Level */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-green-500" />
                        <span className="text-sm font-medium">Risk Level</span>
                      </div>
                      <span className="text-sm font-mono text-green-500">Minimal</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-green-500 rounded-full"
                        style={{ width: '15%' }}
                      />
                    </div>
                  </div>

                  {/* Info Text */}
                  <div className="pt-4 border-t border-border">
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      <span className="text-primary font-medium">ZXWY V2</span> uses 
                      advanced optimization techniques to enhance gaming performance 
                      without compromising system stability. All tweaks are reversible 
                      and thoroughly tested.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
