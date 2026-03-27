import { useEffect, useRef, useState } from 'react';
import { motion, useMotionValue, useSpring } from 'framer-motion';
import { Download, ArrowRight, Cpu, Shield, TrendingUp, Activity, Zap, Users, Star } from 'lucide-react';

const stats = [
  { icon: TrendingUp, value: '+40%', label: 'FPS Boost', color: '#22c55e' },
  { icon: Activity, value: '-30%', label: 'Latency', color: '#4ade80' },
  { icon: Shield, value: '100%', label: 'Safe', color: '#22c55e' },
];

const metrics = [
  { label: 'FPS Stability', value: '98.7%', color: '#22c55e', width: 98.7 },
  { label: 'System Clarity', value: '94.2%', color: '#4ade80', width: 94.2 },
  { label: 'Input Latency', value: '2.1ms', color: '#22c55e', width: 85 },
  { label: 'Risk Level', value: 'Minimal', color: '#22c55e', width: 15, isRisk: true },
];

export function Hero() {
  const metricsRef = useRef<HTMLDivElement>(null);
  const sectionRef = useRef<HTMLElement>(null);
  const [isLogoLoaded, setIsLogoLoaded] = useState(false);

  // Parallax mouse effect
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);
  const springX = useSpring(mouseX, { stiffness: 50, damping: 20 });
  const springY = useSpring(mouseY, { stiffness: 50, damping: 20 });

  useEffect(() => {
    const handleMouse = (e: MouseEvent) => {
      const rect = sectionRef.current?.getBoundingClientRect();
      if (!rect) return;
      const x = (e.clientX - rect.left - rect.width / 2) / rect.width;
      const y = (e.clientY - rect.top - rect.height / 2) / rect.height;
      mouseX.set(x * 20);
      mouseY.set(y * 20);
    };
    window.addEventListener('mousemove', handleMouse);
    return () => window.removeEventListener('mousemove', handleMouse);
  }, [mouseX, mouseY]);

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
    if (metricsRef.current) observer.observe(metricsRef.current);

    return () => observer.disconnect();
  }, []);

  const scrollToDownload = () => {
    document.querySelector('#download')?.scrollIntoView({ behavior: 'smooth' });
  };

  const scrollToFeatures = () => {
    document.querySelector('#features')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <section
      ref={sectionRef}
      id="hero"
      className="relative min-h-screen flex items-center pt-28 pb-20 overflow-hidden"
    >
      {/* Background Decorations */}
      <div className="absolute inset-0 pointer-events-none">
        {/* Subtle grid */}
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `linear-gradient(#22c55e 1px, transparent 1px), linear-gradient(90deg, #22c55e 1px, transparent 1px)`,
            backgroundSize: '60px 60px',
          }}
        />
        {/* Parallax glows */}
        <motion.div
          className="absolute top-1/3 right-0 w-[800px] h-[800px] bg-[#22c55e]/5 rounded-full blur-[150px]"
          style={{ x: springX, y: springY }}
        />
        <motion.div
          className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-[#22c55e]/3 rounded-full blur-[100px]"
          style={{ x: springX, y: springY }}
        />
        {/* Floating particles */}
        {[...Array(6)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute w-1 h-1 rounded-full bg-[#22c55e]/40"
            style={{
              left: `${15 + i * 15}%`,
              top: `${20 + (i % 3) * 25}%`,
            }}
            animate={{
              y: [0, -20, 0],
              opacity: [0.2, 0.8, 0.2],
            }}
            transition={{
              duration: 3 + i * 0.5,
              repeat: Infinity,
              delay: i * 0.4,
              ease: 'easeInOut',
            }}
          />
        ))}
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
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#22c55e]/10 border border-[#22c55e]/30 cursor-default"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2, duration: 0.6 }}
              whileHover={{ scale: 1.03, backgroundColor: 'rgba(34,197,94,0.15)' }}
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#22c55e] opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#22c55e]" />
              </span>
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
                {/* Logo — NO border-radius, NO overflow:hidden, glow via filter only */}
                <motion.div
                  className="relative flex-shrink-0"
                  whileHover={{ scale: 1.08 }}
                  transition={{ type: 'spring', stiffness: 300 }}
                >
                  <img
                    src="/logo.png"
                    alt="ZXWY V2 Logo"
                    onLoad={() => setIsLogoLoaded(true)}
                    className="relative w-20 h-20 md:w-24 md:h-24 object-contain"
                    style={{
                      filter: isLogoLoaded
                        ? 'drop-shadow(0 0 12px rgba(34, 197, 94, 0.8)) drop-shadow(0 0 40px rgba(34, 197, 94, 0.35))'
                        : 'none',
                    }}
                  />
                </motion.div>

                <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight">
                  <span className="block text-white">ZXWY</span>
                  <span className="block gradient-text">VERSION 2</span>
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
                  className="flex items-center gap-3 cursor-default"
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.6 + index * 0.1, duration: 0.5 }}
                  whileHover={{ scale: 1.07, y: -2 }}
                >
                  <div
                    className="w-12 h-12 rounded-xl flex items-center justify-center"
                    style={{ background: `${stat.color}15` }}
                  >
                    <stat.icon className="w-6 h-6" style={{ color: stat.color }} />
                  </div>
                  <div>
                    <div className="text-2xl font-bold" style={{ color: stat.color }}>
                      {stat.value}
                    </div>
                    <div className="text-sm text-white/50">{stat.label}</div>
                  </div>
                </motion.div>
              ))}
            </motion.div>

            {/* Social proof */}
            <motion.div
              className="flex items-center gap-4"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.65, duration: 0.6 }}
            >
              <div className="flex -space-x-2">
                {[...Array(4)].map((_, i) => (
                  <div
                    key={i}
                    className="w-8 h-8 rounded-full border-2 border-black bg-gradient-to-br from-[#22c55e]/60 to-[#22c55e]/20 flex items-center justify-center"
                  >
                    <Users className="w-3.5 h-3.5 text-[#22c55e]" />
                  </div>
                ))}
              </div>
              <div className="text-sm text-white/50">
                <span className="text-white font-semibold">10,000+</span> gamers already optimized
              </div>
              <div className="flex items-center gap-0.5 text-yellow-400">
                {[...Array(5)].map((_, i) => (
                  <Star key={i} className="w-3.5 h-3.5 fill-yellow-400" />
                ))}
              </div>
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
                className="btn-neon gap-2 relative overflow-hidden group"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                {/* Shimmer sweep */}
                <span className="absolute inset-0 -translate-x-full group-hover:translate-x-full transition-transform duration-700 bg-gradient-to-r from-transparent via-white/10 to-transparent skew-x-12" />
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
              {/* Animated glow */}
              <motion.div
                className="absolute -inset-4 bg-[#22c55e]/20 rounded-3xl blur-2xl"
                animate={{ opacity: [0.3, 0.6, 0.3] }}
                transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
              />

              {/* Panel — NO overflow-hidden on outer */}
              <div className="relative glass-card">
                {/* Panel Header */}
                <div className="flex items-center gap-3 px-5 py-4 bg-white/5 border-b border-white/10 rounded-t-[inherit]">
                  <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <div className="w-3 h-3 rounded-full bg-green-500/80" />
                  </div>
                  <div className="flex items-center gap-2 ml-auto">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#22c55e] opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-[#22c55e]" />
                    </span>
                    <span className="text-xs font-mono text-white/40">
                      zxwy_v2_system_monitor.exe
                    </span>
                  </div>
                </div>

                {/* Panel Content */}
                <div className="p-6 space-y-5 rounded-b-[inherit]">
                  {metrics.map((metric, index) => (
                    <motion.div
                      key={metric.label}
                      className="space-y-2"
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.5 + index * 0.1, duration: 0.5 }}
                      whileHover={{ x: 4 }}
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
                        <span className="text-sm font-mono" style={{ color: metric.color }}>
                          {metric.value}
                        </span>
                      </div>
                      <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                        <motion.div
                          className="h-full rounded-full relative overflow-hidden"
                          style={{
                            background: metric.isRisk
                              ? '#22c55e'
                              : `linear-gradient(90deg, ${metric.color}, ${metric.color}88)`,
                          }}
                          initial={{ width: 0 }}
                          animate={{ width: `${metric.width}%` }}
                          transition={{ delay: 0.8 + index * 0.15, duration: 1.2, ease: 'easeOut' }}
                        >
                          {/* Shimmer on bar */}
                          <motion.div
                            className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent"
                            animate={{ x: ['-100%', '200%'] }}
                            transition={{
                              duration: 2,
                              repeat: Infinity,
                              delay: 1.5 + index * 0.2,
                              ease: 'linear',
                            }}
                          />
                        </motion.div>
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

                  {/* Status bar */}
                  <div className="flex items-center justify-between pt-1">
                    <div className="flex items-center gap-1.5 text-xs text-white/30">
                      <div className="w-1.5 h-1.5 rounded-full bg-[#22c55e] animate-pulse" />
                      System Optimized
                    </div>
                    <span className="text-xs font-mono text-white/20">v2.0.1</span>
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
          className="w-6 h-10 rounded-full border-2 border-white/20 flex justify-center pt-2 cursor-pointer hover:border-[#22c55e]/50 transition-colors"
          animate={{ y: [0, 5, 0] }}
          transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
          onClick={scrollToFeatures}
        >
          <div className="w-1.5 h-1.5 rounded-full bg-[#22c55e]" />
        </motion.div>
      </motion.div>
    </section>
  );
}
