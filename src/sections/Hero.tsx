import { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Download, ArrowRight, Cpu, Shield, TrendingUp, Activity, Zap } from 'lucide-react';

const stats = [
  { icon: TrendingUp, value: '+40%', label: 'FPS Boost', color: '#22c55e' },
  { icon: Activity, value: '-30%', label: 'Latency', color: '#4ade80' },
  { icon: Shield, value: '100%', label: 'Safe', color: '#22c55e' },
];

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
    <section id="hero" className="relative min-h-screen flex items-center pt-28 pb-20 overflow-hidden">
      {/* Background Decorations */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/3 right-0 w-[800px] h-[800px] bg-[#22c55e]/5 rounded-full blur-[150px]" />
        <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-[#22c55e]/3 rounded-full blur-[100px]" />
      </div>

      <div className="section-container relative z-10">
        <div className="grid lg:grid-cols-2 gap-16 lg:gap-20 items-center max-w-7xl mx-auto">
          {/* Left Content */}
          <motion.div 
            className="space-y-8"
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, ease: [0.23, 1, 0.32, 1] }}
          >
            {/* Badge */}
            <motion.div 
              className="badge-green"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2, duration: 0.6 }}
            >
              <Zap className="w-4 h-4 text-[#22c55e]" />
              <span className="text-sm font-medium text-[#22c55e]">
                ZXWY V2 is Now Available
              </span>
            </motion.div>

            {/* Title with Logo */}
            <div className="space-y-4">
              <motion.div 
                className="flex items-center gap-5"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3, duration: 0.6 }}
              >
                {/* FIX 1: Added padding around the logo container to prevent glow clipping */}
                <div className="relative flex-shrink-0">
                  <img 
                    src="/logo.png" 
                    alt="ZXWY V2 Logo" 
                    className="w-20 h-20 md:w-24 md:h-24 object-contain"
                    loading="eager"
                    style={{ 
                      filter: 'drop-shadow(0 0 16px rgba(34,197,94,0.7)) drop-shadow(0 0 40px rgba(34,197,94,0.3))',
                      imageRendering: 'crisp-edges'
                    }}
                  />
                </div>
                <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight">
                  <span className="block text-white text-display tracking-widest">ZXWY</span>
                  <span className="block gradient-text text-display">VERSION 2</span>
                </h1>
              </motion.div>
              
              <motion.p 
                className="text-lg md:text-xl text-white/60 max-w-lg leading-relaxed"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4, duration: 0.6 }}
              >
                The ultimate PC optimization toolkit. Boost performance, reduce latency, 
                and unlock your system's full potential with our advanced tweaking software.
              </motion.p>
            </div>

            {/* Stats */}
            <motion.div 
              className="flex flex-wrap gap-6"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5, duration: 0.6 }}
            >
              {stats.map((stat, index) => (
                <motion.div 
                  key={stat.label}
                  className="flex items-center gap-3"
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.6 + index * 0.1, duration: 0.5 }}
                  whileHover={{ scale: 1.05 }}
                >
                  <div 
                    className="w-12 h-12 rounded-xl flex items-center justify-center"
                    style={{ background: `${stat.color}15` }}
                  >
                    <stat.icon className="w-6 h-6" style={{ color: stat.color }} />
                  </div>
                  <div>
                    <div className="text-2xl font-bold" style={{ color: stat.color }}>{stat.value}</div>
                    <div className="text-sm text-white/50">{stat.label}</div>
                  </div>
                </motion.div>
              ))}
            </motion.div>

            {/* CTA Buttons */}
            <motion.div 
              className="flex flex-wrap gap-4"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7, duration: 0.6 }}
            >
              <motion.button 
                onClick={scrollToDownload}
                className="btn-neon gap-2"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <Download className="w-5 h-5" />
                Download Free
              </motion.button>
              <motion.button 
                onClick={scrollToFeatures}
                className="btn-secondary gap-2"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                Explore Features
                <ArrowRight className="w-4 h-4" />
              </motion.button>
            </motion.div>
          </motion.div>

          {/* Right Content - Metrics Panel */}
          <motion.div
            ref={metricsRef}
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.3, ease: [0.23, 1, 0.32, 1] }}
          >
            <div className="relative">
              {/* Glow */}
              <div className="absolute -inset-4 bg-[#22c55e]/20 rounded-3xl blur-2xl opacity-50 animate-pulse" />
              
              {/* FIX 2: Removed overflow-hidden from glass-card — add it only to the inner content div instead */}
              <div className="relative glass-card">
                {/* Panel Header */}
                <div className="flex items-center gap-3 px-5 py-4 bg-white/5 border-b border-white/10 rounded-t-[inherit]">
                  <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <div className="w-3 h-3 rounded-full bg-green-500/80" />
                  </div>
                  <span className="ml-auto text-xs font-mono text-white/40">
                    zxwy_v2_system_monitor.exe
                  </span>
                </div>

                {/* Panel Content */}
                <div className="p-6 space-y-5 overflow-hidden rounded-b-[inherit]">
                  {/* Metrics */}
                  {[
                    { label: 'FPS Stability', value: '98.7%', color: '#22c55e', width: 98.7 },
                    { label: 'System Clarity', value: '94.2%', color: '#4ade80', width: 94.2 },
                    { label: 'Input Latency', value: '2.1ms', color: '#22c55e', width: 85 },
                    { label: 'Risk Level', value: 'Minimal', color: '#22c55e', width: 15, isRisk: true },
                  ].map((metric, index) => (
                    <motion.div 
                      key={metric.label}
                      className="space-y-2"
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.5 + index * 0.1, duration: 0.5 }}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {metric.isRisk ? (
                            <Shield className="w-4 h-4 text-[#22c55e]" />
                          ) : (
                            <Cpu className="w-4 h-4 text-[#22c55e]" />
                          )}
                          <span className="text-sm font-medium text-white/70">{metric.label}</span>
                        </div>
                        <span className="text-sm font-mono" style={{ color: metric.color }}>{metric.value}</span>
                      </div>
                      <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                        <motion.div 
                          className="h-full rounded-full"
                          style={{ 
                            background: metric.isRisk 
                              ? '#22c55e' 
                              : `linear-gradient(90deg, ${metric.color}, ${metric.color}88)` 
                          }}
                          initial={{ width: 0 }}
                          animate={{ width: `${metric.width}%` }}
                          transition={{ delay: 0.8 + index * 0.15, duration: 1, ease: 'easeOut' }}
                        />
                      </div>
                    </motion.div>
                  ))}

                  {/* Info Text */}
                  <div className="pt-4 border-t border-white/10">
                    <p className="text-xs text-white/50 leading-relaxed">
                      <span className="text-[#22c55e] font-medium">ZXWY V2</span> uses 
                      advanced optimization techniques to enhance gaming performance 
                      without compromising system stability.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Scroll Indicator */}
      <motion.div 
        className="absolute bottom-8 left-1/2 -translate-x-1/2"
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.2, duration: 0.6 }}
      >
        <motion.div
          className="w-6 h-10 rounded-full border-2 border-white/20 flex justify-center pt-2"
          animate={{ y: [0, 5, 0] }}
          transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
        >
          <div className="w-1.5 h-1.5 rounded-full bg-[#22c55e]" />
        </motion.div>
      </motion.div>
    </section>
  );
}
