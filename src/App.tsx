import { useEffect, useState } from 'react';
import { ThemeProvider } from './hooks/use-theme';
import { BotCheck } from './components/BotCheck';
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

function App() {
  const [isVerified, setIsVerified] = useState(false);

  useEffect(() => {
    // Check if user is already verified
    const verified = localStorage.getItem('zxwy_v2_verified') === 'true';
    setIsVerified(verified);
  }, []);

  const handleVerification = () => {
    localStorage.setItem('zxwy_v2_verified', 'true');
    setIsVerified(true);
  };

  return (
    <ThemeProvider defaultTheme="dark" storageKey="zxwy-v2-theme">
      <div className="relative min-h-screen bg-background text-foreground overflow-x-hidden">
        {/* Bot Check Overlay */}
        {!isVerified && <BotCheck onVerify={handleVerification} />}
        
        {/* Background Effects */}
        <div className="fixed inset-0 pointer-events-none z-0">
          {/* Grid Pattern */}
          <div className="absolute inset-0 bg-grid-pattern opacity-50" />
          
          {/* Radial Gradient */}
          <div className="absolute inset-0 bg-radial-gradient" />
          
          {/* Floating Orbs */}
          <div className="absolute top-20 left-10 w-72 h-72 bg-primary/10 rounded-full blur-3xl animate-float" />
          <div className="absolute bottom-40 right-10 w-96 h-96 bg-primary/5 rounded-full blur-3xl animate-float" style={{ animationDelay: '1.5s' }} />
        </div>
        
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
      </div>
    </ThemeProvider>
  );
}

export default App;
