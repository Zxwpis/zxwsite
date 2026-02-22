import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { 
  Mail, 
  MessageCircle, 
  Gamepad2,
  Send,
  CheckCircle2,
  Clock,
  Users
} from 'lucide-react';

const contactMethods = [
  {
    icon: MessageCircle,
    name: 'Telegram',
    description: 'Fastest response time',
    link: 'https://t.me/ZXWYTWEAKING',
    color: 'bg-[#0088cc]/10 text-[#0088cc] border-[#0088cc]/20',
    hoverColor: 'hover:bg-[#0088cc]/20',
  },
  {
    icon: Gamepad2,
    name: 'Discord',
    description: 'Community support',
    link: 'https://discord.gg/UQmBUXct',
    color: 'bg-[#5865F2]/10 text-[#5865F2] border-[#5865F2]/20',
    hoverColor: 'hover:bg-[#5865F2]/20',
  },
];

const stats = [
  { icon: Clock, value: '< 24h', label: 'Response Time' },
  { icon: Users, value: '5k+', label: 'Community Members' },
];

export function Contact() {
  const [formState, setFormState] = useState({
    name: '',
    email: '',
    message: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);

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

    const elements = document.querySelectorAll('#contact .animate-on-scroll');
    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    
    // Simulate form submission
    await new Promise((resolve) => setTimeout(resolve, 1500));
    
    setIsSubmitting(false);
    setIsSubmitted(true);
    setFormState({ name: '', email: '', message: '' });
    
    // Reset success message after 5 seconds
    setTimeout(() => setIsSubmitted(false), 5000);
  };

  return (
    <section id="contact" className="zxwy-section relative">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-primary/5 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 animate-on-scroll">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
            <Mail className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">Get in Touch</span>
          </div>
          <h2 className="text-4xl sm:text-5xl font-bold mb-6">
            Contact <span className="zxwy-gradient-text">Support</span>
          </h2>
          <p className="text-lg text-muted-foreground">
            Need help with ZXWY V2? Our community and support team are here to assist you.
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-12 animate-on-scroll delay-1">
          {stats.map((stat) => (
            <div 
              key={stat.label}
              className="text-center p-4 rounded-xl bg-card border border-border"
            >
              <stat.icon className="w-6 h-6 text-primary mx-auto mb-2" />
              <div className="text-2xl font-bold">{stat.value}</div>
              <div className="text-sm text-muted-foreground">{stat.label}</div>
            </div>
          ))}
        </div>

        <div className="grid lg:grid-cols-2 gap-12">
          {/* Left - Contact Methods */}
          <div className="space-y-6 animate-on-scroll delay-1">
            <h3 className="text-2xl font-semibold mb-6">Connect With Us</h3>
            
            {/* Contact Cards */}
            <div className="space-y-4">
              {contactMethods.map((method) => (
                <a
                  key={method.name}
                  href={method.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={`
                    flex items-center gap-4 p-5 rounded-2xl border transition-all duration-300
                    ${method.color} ${method.hoverColor}
                  `}
                >
                  <div className="w-14 h-14 rounded-xl bg-background/50 flex items-center justify-center">
                    <method.icon className="w-7 h-7" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-lg">{method.name}</h4>
                    <p className="text-sm opacity-80">{method.description}</p>
                  </div>
                  <div className="w-10 h-10 rounded-lg bg-background/50 flex items-center justify-center">
                    <Send className="w-5 h-5" />
                  </div>
                </a>
              ))}
            </div>

            {/* Info Box */}
            <div className="p-6 rounded-2xl bg-muted/50 border border-border">
              <h4 className="font-semibold mb-3">Support Hours</h4>
              <div className="space-y-2 text-sm text-muted-foreground">
                <p>Our community is active 24/7, but official support responses are typically provided during:</p>
                <div className="flex justify-between py-2 border-b border-border/50">
                  <span>Monday - Friday</span>
                  <span className="text-foreground">9:00 AM - 6:00 PM UTC</span>
                </div>
                <div className="flex justify-between py-2">
                  <span>Weekend</span>
                  <span className="text-foreground">Community Support Only</span>
                </div>
              </div>
            </div>
          </div>

          {/* Right - Contact Form */}
          <div className="animate-on-scroll delay-2">
            <div className="bg-card border border-border rounded-2xl p-8 shadow-xl">
              <h3 className="text-2xl font-semibold mb-2">Send a Message</h3>
              <p className="text-muted-foreground mb-6">
                Fill out the form below and we'll get back to you as soon as possible.
              </p>

              {isSubmitted ? (
                <div className="text-center py-12">
                  <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center mx-auto mb-4">
                    <CheckCircle2 className="w-8 h-8 text-green-500" />
                  </div>
                  <h4 className="text-xl font-semibold mb-2">Message Sent!</h4>
                  <p className="text-muted-foreground">
                    Thank you for reaching out. We'll respond within 24 hours.
                  </p>
                </div>
              ) : (
                <form onSubmit={handleSubmit} className="space-y-5">
                  <div>
                    <label className="block text-sm font-medium mb-2">Your Name</label>
                    <Input
                      type="text"
                      placeholder="John Doe"
                      value={formState.name}
                      onChange={(e) => setFormState({ ...formState, name: e.target.value })}
                      required
                      className="h-12"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Email Address</label>
                    <Input
                      type="email"
                      placeholder="john@example.com"
                      value={formState.email}
                      onChange={(e) => setFormState({ ...formState, email: e.target.value })}
                      required
                      className="h-12"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Message</label>
                    <Textarea
                      placeholder="How can we help you?"
                      value={formState.message}
                      onChange={(e) => setFormState({ ...formState, message: e.target.value })}
                      required
                      rows={5}
                      className="resize-none"
                    />
                  </div>

                  <Button
                    type="submit"
                    disabled={isSubmitting}
                    className="w-full zxwy-btn-primary gap-2"
                  >
                    {isSubmitting ? (
                      <>
                        <div className="w-5 h-5 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
                        Sending...
                      </>
                    ) : (
                      <>
                        <Send className="w-5 h-5" />
                        Send Message
                      </>
                    )}
                  </Button>

                  <p className="text-xs text-muted-foreground text-center">
                    By submitting this form, you agree to our privacy policy.
                  </p>
                </form>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
