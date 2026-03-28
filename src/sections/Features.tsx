import { useEffect } from 'react';
import { motion } from 'framer-motion';
import { Zap, Shield, Cpu, Gauge, RefreshCw, Gamepad2, Layers, Settings } from 'lucide-react';

const features = [
  {
    icon: Zap,
    title: 'Performance Boost',
    description: 'Optimize Windows services, registry, and power settings for maximum gaming performance.',
    stat: '+40% FPS',
    gradient: 'from-[#22c55e] to-[#4ade80]',
  },
  {
    icon: Shield,
    title: 'Safe & Reversible',
    description: 'All tweaks include automatic restore points. One-click rollback anytime.',
    stat: '100% Safe',
    gradient: 'from-[#4ade80] to-[#22c55e]',
  },
  {
    icon: Cpu,
    title: 'System Debloat',
    description: 'Remove unnecessary Windows bloatware and background processes.',
    stat: '-15%',
    gradient: 'from-[#22c55e] to-[#16a34a]',
  },
  {
    icon: Gauge,
    title: 'Latency Reduction',
    description: 'Minimize input lag with advanced timer and interrupt optimizations.',
    stat: '-30% Latency',
    gradient: 'from-[#4ade80] to-[#22c55e]',
  },
  {
    icon: RefreshCw,
    title: 'Auto Updates',
    description: 'Get the latest optimizations automatically with our update system.',
    stat: 'Always Current',
    gradient: 'from-[#22c55e] to-[#4ade80]',
  },
  {
    icon: Gamepad2,
    title: 'Gaming Focused',
    description: 'Specifically designed for gamers who demand the best performance.',
    stat: 'Proven Results',
    gradient: 'from-[#4ade80] to-[#22c55e]',
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

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.6,
    },
  },
};

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
    <section id="features" className="relative py-24 md:py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[1000px] h-[600px] bg-[#22c55e]/5 rounded-full blur-[150px]" />
      </div>

      <div className="section-container relative z-10">
        {/* Section Header */}
        <motion.div 
          className="text-center max-w-3xl mx-auto mb-16"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#22c55e]/10 border border-[#22c55e]/30 mb-6">
            <Zap className="w-4 h-4 text-[#22c55e]" />
            <span className="text-sm font-medium text-[#22c55e]">Powerful Features</span>
          </div>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6">
            Everything You Need for
            <span className="gradient-text block mt-2">Maximum Performance</span>
          </h2>
          <p className="text-lg text-white/60">
            ZXWY V2 combines powerful optimization tools with an intuitive interface 
            to give you complete control over your system's performance.
          </p>
        </motion.div>

        {/* Features Grid */}
        <motion.div 
          className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-20"
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-100px' }}
        >
          {features.map((feature) => (
            <motion.div
              key={feature.title}
              variants={itemVariants}
              whileHover={{ y: -8, transition: { duration: 0.3 } }}
              className="feature-card group cursor-pointer"
            >
              {/* Icon */}
              <div className={`
                w-14 h-14 rounded-xl flex items-center justify-center mb-5
                bg-gradient-to-br ${feature.gradient} bg-opacity-10
                group-hover:scale-110 transition-transform duration-500
              `}>
                <feature.icon className="w-7 h-7 text-white" />
              </div>

              {/* Content */}
              <h3 className="text-xl font-semibold mb-2 text-white group-hover:text-[#22c55e] transition-colors duration-300 text-display tracking-wide">
                {feature.title}
              </h3>
              <p className="text-white/50 mb-4 text-sm leading-relaxed">
                {feature.description}
              </p>

              {/* Stat Badge */}
              <div className={`
                inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-semibold
                bg-gradient-to-r ${feature.gradient} bg-opacity-10 text-white
                border border-white/10
              `}>
                {feature.stat}
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* V2 Improvements */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8, ease: [0.23, 1, 0.32, 1] }}
        >
          <div className="relative overflow-hidden rounded-3xl glass-card p-8 md:p-12">
            {/* Background Glow */}
            <div className="absolute top-0 right-0 w-96 h-96 bg-[#22c55e]/10 rounded-full blur-[100px] -translate-y-1/2 translate-x-1/2" />
            
            <div className="relative grid lg:grid-cols-2 gap-12 items-center">
              {/* Left Content */}
              <div>
                <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#22c55e]/20 border border-[#22c55e]/40 mb-6">
                  <span className="w-2 h-2 rounded-full bg-[#22c55e] animate-pulse" />
                  <span className="text-sm font-medium text-[#22c55e]">What's New in V2</span>
                </div>
                <h3 className="text-3xl md:text-4xl font-bold mb-4">
                  Major Upgrade from
                  <span className="gradient-text block mt-1">Version 1</span>
                </h3>
                <p className="text-white/60 text-lg mb-8">
                  We've completely rebuilt ZXWY from the ground up with new features, 
                  better performance, and a more intuitive experience.
                </p>
                
                {/* Improvement Stats */}
                <div className="flex flex-wrap gap-4">
                  {[
                    { value: '3x', label: 'Faster' },
                    { value: '50+', label: 'New Tweaks' },
                  ].map((stat) => (
                    <motion.div 
                      key={stat.label}
                      className="px-5 py-3 rounded-xl glass-card"
                      whileHover={{ scale: 1.05 }}
                    >
                      <div className="text-2xl font-bold text-[#22c55e]">{stat.value}</div>
                      <div className="text-sm text-white/50">{stat.label}</div>
                    </motion.div>
                  ))}
                </div>
              </div>

              {/* Right Content - Improvements List */}
              <div className="space-y-4">
                {v2Improvements.map((improvement) => (
                  <motion.div
                    key={improvement.title}
                    className="flex items-start gap-4 p-5 rounded-2xl glass-card hover:border-[#22c55e]/30 transition-all duration-300"
                    initial={{ opacity: 0, x: 30 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.15, duration: 0.5 }}
                    whileHover={{ x: 5 }}
                  >
                    <div className="w-12 h-12 rounded-xl bg-[#22c55e]/10 flex items-center justify-center flex-shrink-0">
                      <improvement.icon className="w-6 h-6 text-[#22c55e]" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-lg mb-1">{improvement.title}</h4>
                      <p className="text-white/50 text-sm">{improvement.description}</p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
