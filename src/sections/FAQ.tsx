import { useEffect, useState } from 'react';
import { 
  HelpCircle, 
  ChevronDown,
  MessageCircle
} from 'lucide-react';

interface FAQItem {
  question: string;
  answer: string;
}

const faqData: FAQItem[] = [
  {
    question: 'Are these tweaks safe to use?',
    answer: 'Yes, all ZXWY V2 tweaks are thoroughly tested and designed to be reversible. We never modify critical system files or disable essential security features like Windows Defender. Each tweak creates an automatic restore point before making changes, allowing you to roll back anytime.',
  },
  {
    question: 'Do I need to disable my antivirus?',
    answer: 'Absolutely not. You should never disable Windows Defender or your antivirus software to use ZXWY V2. Our tool is designed to work alongside your security software. If your antivirus flags ZXWY, simply add it to your exclusions list.',
  },
  {
    question: 'Will I get more FPS in games?',
    answer: 'While results vary depending on your hardware and current system state, most users see a 10-40% improvement in FPS and significantly reduced stuttering. The tweaks focus on eliminating background processes, optimizing power settings, and reducing input latency.',
  },
  {
    question: 'Can I undo the tweaks?',
    answer: 'Yes! ZXWY V2 automatically creates restore points before applying any changes. You can revert all tweaks with a single click from the application, or use Windows System Restore to go back to a previous state.',
  },
  {
    question: 'What operating systems are supported?',
    answer: 'ZXWY V2 supports Windows 10 (version 1903 and later) and Windows 11. Both 64-bit versions are fully compatible. We do not support Windows 7, 8, or 32-bit systems.',
  },
  {
    question: 'Is ZXWY V2 free?',
    answer: 'Yes! The core ZXWY V2 toolkit is completely free to download and use. We also offer premium plans with additional advanced optimizations and personalized support for users who want the absolute best performance.',
  },
  {
    question: 'How often is ZXWY updated?',
    answer: 'We release updates regularly to add new optimizations, improve compatibility with Windows updates, and fix any reported issues. V2 users receive automatic update notifications within the application.',
  },
  {
    question: 'Will this void my warranty?',
    answer: 'No, using ZXWY V2 will not void your hardware warranty. We only modify software settings within Windows. However, we recommend creating a restore point before making any changes, just to be safe.',
  },
  {
    question: 'Can I use ZXWY on multiple PCs?',
    answer: 'The free version can be used on unlimited personal devices. Premium plans are licensed per user and can be used on multiple PCs you own. Commercial use requires a separate license.',
  },
  {
    question: 'Where can I get support?',
    answer: 'We offer support through our Discord community and Telegram channel. Premium users also get access to priority email support with faster response times.',
  },
];

export function FAQ() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

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

    const elements = document.querySelectorAll('#faq .animate-on-scroll');
    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  const toggleQuestion = (index: number) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  return (
    <section id="faq" className="zxwy-section relative">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/5 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 animate-on-scroll">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
            <HelpCircle className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">FAQ</span>
          </div>
          <h2 className="text-4xl sm:text-5xl font-bold mb-6">
            Frequently Asked <span className="zxwy-gradient-text">Questions</span>
          </h2>
          <p className="text-lg text-muted-foreground">
            Got questions? We've got answers. If you can't find what you're looking for, 
            feel free to reach out to our community.
          </p>
        </div>

        {/* FAQ List */}
        <div className="space-y-4 animate-on-scroll delay-1">
          {faqData.map((item, index) => (
            <div
              key={index}
              className={`
                rounded-2xl border overflow-hidden transition-all duration-300
                ${openIndex === index 
                  ? 'bg-card border-primary/30 shadow-lg' 
                  : 'bg-card/50 border-border hover:border-primary/20'
                }
              `}
            >
              <button
                onClick={() => toggleQuestion(index)}
                className="w-full p-6 flex items-center justify-between text-left"
              >
                <div className="flex items-center gap-4 pr-4">
                  <div className={`
                    w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0
                    ${openIndex === index ? 'bg-primary/20' : 'bg-primary/10'}
                  `}>
                    <span className="text-primary font-bold">{index + 1}</span>
                  </div>
                  <h3 className="font-semibold text-lg">{item.question}</h3>
                </div>
                <ChevronDown 
                  className={`
                    w-5 h-5 text-muted-foreground flex-shrink-0 transition-transform duration-300
                    ${openIndex === index ? 'rotate-180' : ''}
                  `}
                />
              </button>
              
              <div 
                className={`
                  overflow-hidden transition-all duration-300
                  ${openIndex === index ? 'max-h-96' : 'max-h-0'}
                `}
              >
                <div className="px-6 pb-6 pt-0">
                  <div className="pl-14">
                    <p className="text-muted-foreground leading-relaxed">
                      {item.answer}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Contact CTA */}
        <div className="mt-12 animate-on-scroll delay-2">
          <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-primary/10 via-primary/5 to-transparent border border-primary/20 p-8">
            <div className="flex flex-col md:flex-row items-center justify-between gap-6">
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center">
                  <MessageCircle className="w-7 h-7 text-primary" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold mb-1">Still have questions?</h3>
                  <p className="text-muted-foreground">
                    Join our community for personalized help and support.
                  </p>
                </div>
              </div>
              <div className="flex gap-3">
                <a
                  href="https://discord.gg/UQmBUXct"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-6 py-3 rounded-xl bg-[#5865F2] text-white font-medium hover:bg-[#4752C4] transition-colors"
                >
                  Join Discord
                </a>
                <a
                  href="https://t.me/ZXWYTWEAKING"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-6 py-3 rounded-xl bg-[#0088cc] text-white font-medium hover:bg-[#0077b3] transition-colors"
                >
                  Telegram
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
