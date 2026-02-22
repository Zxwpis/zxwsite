import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { 
  Download as DownloadIcon, 
  Check, 
  AlertTriangle,
  FileArchive,
  ExternalLink,
  Copy,
  CheckCircle2
} from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';

const requirements = [
  'Windows 10 or Windows 11',
  'Administrator privileges',
  'Internet connection for updates',
  '50MB free disk space',
];

const steps = [
  {
    step: 1,
    title: 'Download',
    description: 'Get ZXWY V2 from our secure Google Drive folder.',
  },
  {
    step: 2,
    title: 'Extract',
    description: 'Extract the ZIP file to your desired location.',
  },
  {
    step: 3,
    title: 'Run',
    description: 'Right-click and run ZXWY_V2.exe as Administrator.',
  },
  {
    step: 4,
    title: 'Optimize',
    description: 'Select your desired tweaks and apply them.',
  },
];

export function Download() {
  const [copied, setCopied] = useState(false);

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

    const elements = document.querySelectorAll('#download .animate-on-scroll');
    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  const handleCopyLink = () => {
    navigator.clipboard.writeText('https://drive.google.com/drive/folders/17UcwGUs-j4MrOIpu04aaLiXbC-eahWQM?usp=drive_link');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="download" className="zxwy-section relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 animate-on-scroll">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
            <DownloadIcon className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">Get Started</span>
          </div>
          <h2 className="text-4xl sm:text-5xl font-bold mb-6">
            Download <span className="zxwy-gradient-text">ZXWY V2</span>
          </h2>
          <p className="text-lg text-muted-foreground">
            Get the latest version of ZXWY V2 for free. Start optimizing your PC 
            in minutes with our easy-to-use toolkit.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-12 items-start">
          {/* Left - Download Card */}
          <div className="animate-on-scroll delay-1">
            <div className="relative">
              {/* Glow */}
              <div className="absolute -inset-4 bg-primary/20 rounded-3xl blur-2xl opacity-50" />
              
              {/* Card */}
              <div className="relative bg-card border border-border rounded-2xl p-8 shadow-xl">
                {/* Version Badge */}
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <div className="w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center">
                      <FileArchive className="w-7 h-7 text-primary" />
                    </div>
                    <div>
                      <h3 className="text-xl font-bold">ZXWY V2</h3>
                      <p className="text-sm text-muted-foreground">Latest Version</p>
                    </div>
                  </div>
                  <div className="px-3 py-1 rounded-full bg-green-500/10 border border-green-500/20 text-green-500 text-sm font-medium">
                    Free
                  </div>
                </div>

                {/* File Info */}
                <div className="space-y-3 mb-8 p-4 rounded-xl bg-muted/50">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Version</span>
                    <span className="font-medium">2.0.0</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">File Size</span>
                    <span className="font-medium">~15 MB</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Format</span>
                    <span className="font-medium">ZIP Archive</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Updated</span>
                    <span className="font-medium">February 2025</span>
                  </div>
                </div>

                {/* Download Button */}
                <a
                  href="https://drive.google.com/drive/folders/17UcwGUs-j4MrOIpu04aaLiXbC-eahWQM?usp=drive_link"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block w-full"
                >
                  <Button size="lg" className="w-full zxwy-btn-primary gap-2 text-base">
                    <DownloadIcon className="w-5 h-5" />
                    Download from Google Drive
                    <ExternalLink className="w-4 h-4 ml-auto" />
                  </Button>
                </a>

                {/* Copy Link */}
                <button
                  onClick={handleCopyLink}
                  className="w-full mt-3 flex items-center justify-center gap-2 py-3 px-4 rounded-xl border border-border hover:border-primary/50 hover:bg-primary/5 transition-colors text-sm text-muted-foreground"
                >
                  {copied ? (
                    <>
                      <CheckCircle2 className="w-4 h-4 text-green-500" />
                      Link copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4" />
                      Copy download link
                    </>
                  )}
                </button>

                {/* Warning */}
                <div className="flex items-start gap-3 mt-6 p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/20">
                  <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                  <div className="text-sm">
                    <p className="font-medium text-yellow-500 mb-1">Important</p>
                    <p className="text-muted-foreground">
                      Always create a system restore point before applying tweaks. 
                      Use at your own risk.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Right - Installation Steps */}
          <div className="space-y-8 animate-on-scroll delay-2">
            {/* Requirements */}
            <div>
              <h3 className="text-xl font-semibold mb-4">System Requirements</h3>
              <div className="space-y-3">
                {requirements.map((req) => (
                  <div key={req} className="flex items-center gap-3">
                    <div className="w-5 h-5 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <Check className="w-3 h-3 text-primary" />
                    </div>
                    <span className="text-muted-foreground">{req}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Steps */}
            <div>
              <h3 className="text-xl font-semibold mb-4">Installation Steps</h3>
              <div className="space-y-4">
                {steps.map((step) => (
                  <div 
                    key={step.step}
                    className="flex items-start gap-4 p-4 rounded-xl bg-card border border-border hover:border-primary/30 transition-colors"
                  >
                    <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <span className="text-primary font-bold">{step.step}</span>
                    </div>
                    <div>
                      <h4 className="font-medium mb-1">{step.title}</h4>
                      <p className="text-sm text-muted-foreground">{step.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Support */}
            <Dialog>
              <DialogTrigger asChild>
                <button className="w-full p-4 rounded-xl bg-primary/5 border border-primary/20 hover:bg-primary/10 transition-colors text-left">
                  <p className="text-sm text-muted-foreground mb-1">Need help?</p>
                  <p className="font-medium text-primary">Contact our support team →</p>
                </button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Need Help?</DialogTitle>
                  <DialogDescription>
                    If you're having trouble downloading or installing ZXWY V2, 
                    reach out to us on Discord or Telegram.
                  </DialogDescription>
                </DialogHeader>
                <div className="flex flex-col gap-3 mt-4">
                  <a
                    href="https://discord.gg/UQmBUXct"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-[#5865F2]/10 border border-[#5865F2]/20 text-[#5865F2] font-medium hover:bg-[#5865F2]/20 transition-colors"
                  >
                    Join Discord Server
                  </a>
                  <a
                    href="https://t.me/ZXWYTWEAKING"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-[#0088cc]/10 border border-[#0088cc]/20 text-[#0088cc] font-medium hover:bg-[#0088cc]/20 transition-colors"
                  >
                    Message on Telegram
                  </a>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </div>
    </section>
  );
}
