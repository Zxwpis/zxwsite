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

function App() {
  const [isVerified, setIsVerified] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check if user is already verified
    const verified = localStorage.getItem('zxwy_v2_verified') === 'true';
    setIsVerified(verified);
    
    // Simulate loading for smooth entry
    const timer = setTimeout(() => setIsLoading(false), 500);
    return () => clearTimeout(timer);
  }, []);

  const handleVerification = () => {
    localStorage.setItem('zxwy_v2_verified', 'true');
    setIsVerified(true);
  };

  if (isLoading) {
    return (
      <div className="fixed inset-0 bg-[#0a0a0a] flex items-center justify-center z-50">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="relative"
        >
          <div className="absolute inset-0 bg-[#22c55e]/20 rounded-2xl blur-xl animate-pulse" />
          <img 
            src="/logo.png" 
            alt="ZXWY V2" 
            className="relative w-20 h-20 rounded-2xl object-cover"
          />
        </motion.div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen bg-[#0a0a0a] text-white overflow-x-hidden">
      {/* Background Effects */}
      <div className="fixed inset-0 pointer-events-none z-0">
        {/* Grid Pattern */}
        <div className="absolute inset-0 bg-grid opacity-50" />
        
        {/* Gradient Orbs */}
        <div className="absolute top-0 left-1/4 w-[800px] h-[800px] bg-[#22c55e]/5 rounded-full blur-[150px]" />
        <div className="absolute bottom-0 right-1/4 w-[600px] h-[600px] bg-[#22c55e]/3 rounded-full blur-[120px]" />
        
        {/* Noise Texture */}
        <div className="absolute inset-0 bg-noise" />
      </div>

      {/* Bot Check Overlay */}
      <AnimatePresence>
        {!isVerified && <BotCheck onVerify={handleVerification} />}
      </AnimatePresence>

      {/* Main Content */}
      <div className="relative z-10">
        <Header />
        <main>
          <Hero />
          <Features />
          <Download />
          <Changelog />
          <Pricing />
          <FAQ />
          <Contact />
          <Warning />
        </main>
        <Footer />
      </div>

      {/* Toast Notifications */}
      <Toaster 
        position="bottom-right"
        toastOptions={{
          style: {
            background: '#1a1a1a',
            border: '1px solid rgba(34, 197, 94, 0.3)',
            color: '#fff',
          },
        }}
      />
    </div>
  );
}

export default App;
