import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Header } from './sections/Header';
import { Hero } from './sections/Hero';
import { Features } from './sections/Features';
import { Download } from './sections/Download';
import { Changelog } from './sections/Changelog';
import { Pricing } from './sections/Pricing';
import { FAQ } from './sections/FAQ';
import { Contact } from './sections/Contact';
import { Warning } from './sections/Warning';
import { Footer } from './sections/Footer';
import { BotCheck } from './components/BotCheck';
import { Toaster } from './components/ui/sonner';

// Loading screen with animated logo + progress bar
function LoadingScreen() {
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState(0);
  const phases = ['Initializing...', 'Loading assets...', 'Almost ready...'];

  useEffect(() => {
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) { clearInterval(interval); return 100; }
        return prev + Math.random() * 18 + 4;
      });
    }, 80);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (progress > 33) setPhase(1);
    if (progress > 66) setPhase(2);
  }, [progress]);

  return (
    <motion.div
      className="fixed inset-0 bg-[#0a0a0a] flex flex-col items-center justify-center z-50"
      exit={{ opacity: 0, scale: 1.05 }}
      transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
    >
      {/* Background grid */}
      <div className="absolute inset-0 bg-grid opacity-30" />

      {/* Radial glow */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="w-[600px] h-[600px] bg-[#35fe34]/5 rounded-full blur-[120px]" />
      </div>

      <motion.div
        className="relative flex flex-col items-center gap-8 z-10"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        {/* Logo with spinning ring */}
        <div className="relative">
          {/* Outer spinning ring */}
          <motion.div
            className="absolute inset-[-20px] rounded-full border border-dashed border-[#35fe34]/20"
            animate={{ rotate: 360 }}
            transition={{ duration: 10, repeat: Infinity, ease: 'linear' }}
          />
          {/* Inner spinning ring */}
          <motion.div
            className="absolute inset-[-10px] rounded-full border border-[#35fe34]/10"
            animate={{ rotate: -360 }}
            transition={{ duration: 7, repeat: Infinity, ease: 'linear' }}
          />
          {/* Glow pulse */}
          <motion.div
            className="absolute inset-0 bg-[#35fe34]/20 rounded-full blur-2xl"
            animate={{ scale: [1, 1.3, 1], opacity: [0.3, 0.6, 0.3] }}
            transition={{ duration: 2, repeat: Infinity }}
          />
          <img
            src="/logo.png"
            alt="ZXWY V2"
            className="relative w-20 h-20 object-contain"
            loading="eager"
            style={{ filter: 'drop-shadow(0 0 16px rgba(53,254,52,0.6))' }}
          />
        </div>

        {/* Brand name */}
        <div className="text-center">
          <h1 className="text-display text-3xl font-bold tracking-widest text-white mb-1">
            ZXWY <span className="text-[#35fe34]">V2</span>
          </h1>
          <p className="text-xs tracking-[0.3em] text-white/30 uppercase">PC Optimization</p>
        </div>

        {/* Progress bar */}
        <div className="w-64 space-y-2">
          <div className="h-[2px] bg-white/5 rounded-full overflow-hidden">
            <motion.div
              className="h-full rounded-full"
              style={{
                background: 'linear-gradient(90deg, #35fe34, #5fff5e)',
                boxShadow: '0 0 8px #35fe34',
              }}
              animate={{ width: `${Math.min(progress, 100)}%` }}
              transition={{ duration: 0.15, ease: 'easeOut' }}
            />
          </div>
          <div className="flex justify-between items-center">
            <motion.p
              key={phase}
              className="text-xs text-white/30 font-mono"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.3 }}
            >
              {phases[phase]}
            </motion.p>
            <span className="text-xs font-mono text-[#35fe34]/60">
              {Math.min(Math.round(progress), 100)}%
            </span>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}

function App() {
  const [isVerified, setIsVerified] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const verified = localStorage.getItem('zxwy_v2_verified') === 'true';
    setIsVerified(verified);
    const timer = setTimeout(() => setIsLoading(false), 1800);
    return () => clearTimeout(timer);
  }, []);

  const handleVerification = () => {
    localStorage.setItem('zxwy_v2_verified', 'true');
    setIsVerified(true);
  };

  return (
    <>
      <AnimatePresence mode="wait">
        {isLoading && <LoadingScreen key="loading" />}
      </AnimatePresence>

      {!isLoading && (
        <div className="relative min-h-screen bg-[#0a0a0a] text-white overflow-x-hidden">
          {/* Fixed background */}
          <div className="fixed inset-0 pointer-events-none z-0">
            <div className="absolute inset-0 bg-grid opacity-40" />
            <div className="absolute top-0 left-1/4 w-[900px] h-[700px] bg-[#35fe34]/4 rounded-full blur-[160px]" />
            <div className="absolute bottom-0 right-1/4 w-[700px] h-[500px] bg-[#35fe34]/3 rounded-full blur-[140px]" />
            <div className="absolute inset-0 bg-noise" />
          </div>

          {/* Bot check */}
          <AnimatePresence>
            {!isVerified && <BotCheck onVerify={handleVerification} />}
          </AnimatePresence>

          {/* Main */}
          <motion.div
            className="relative z-10"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5 }}
          >
            <Header />
            <main>
              <Hero />
              <div className="section-divider" />
              <Features />
              <div className="section-divider" />
              <Download />
              <div className="section-divider" />
              <Changelog />
              <div className="section-divider" />
              <Pricing />
              <div className="section-divider" />
              <FAQ />
              <div className="section-divider" />
              <Contact />
              <Warning />
            </main>
            <Footer />
          </motion.div>

          <Toaster
            position="bottom-right"
            toastOptions={{
              style: {
                background: '#141414',
                border: '1px solid rgba(53,254,52,0.25)',
                color: '#fff',
                fontFamily: 'var(--font-body)',
                borderRadius: '12px',
                backdropFilter: 'blur(12px)',
              },
            }}
          />
        </div>
      )}
    </>
  );
}

export default App;
