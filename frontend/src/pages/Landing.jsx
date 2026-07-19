import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Activity } from 'lucide-react';
import Logo from '../components/Logo';
import DarkVeil from '../components/DarkVeil';
import DecryptedText from '../components/DecryptedText';
import ElectricBorder from '../components/ElectricBorder';
import ChromaGrid from '../components/ChromaGrid';
import Lightfall from '../components/Lightfall';

export default function Landing() {
  const isDark = true;

  return (
    <div className="relative min-h-screen bg-gradient-to-br from-slate-100 via-cyan-50 to-violet-50 dark:from-[#050510] dark:via-[#120a26] dark:to-[#04101a] text-slate-900 dark:text-white transition-colors duration-200 overflow-hidden">
      <div className="absolute inset-0 z-0 opacity-30 dark:opacity-80">
        <DarkVeil
          hueShift={isDark ? 285 : 195}
          noiseIntensity={0.1}
          scanlineIntensity={0.12}
          speed={0.6}
          scanlineFrequency={40}
          warpAmount={0.015}
          resolutionScale={0.5}
        />
      </div>

      <div className="absolute inset-0 z-0 opacity-60 dark:opacity-90 pointer-events-none mix-blend-screen">
        <Lightfall
          colors={isDark ? ['#22D3EE', '#A855F7', '#E879F9'] : ['#0891B2', '#7C3AED', '#C026D3']}
          backgroundColor="#0A29FF"
          speed={0.6}
          streakCount={4}
          streakWidth={1.2}
          streakLength={1.2}
          glow={1}
          density={0.7}
          twinkle={1}
          zoom={3}
          backgroundGlow={0.35}
          opacity={0.9}
          mouseInteraction={true}
          mouseStrength={0.6}
          mouseRadius={0.6}
        />
      </div>

      <div className="relative z-10 flex flex-col min-h-screen">
        <nav className="flex items-center justify-between px-4 sm:px-6 py-4 max-w-7xl mx-auto w-full gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Logo size={32} />
            <span className="text-lg sm:text-xl font-bold text-slate-900 dark:text-white truncate">Vertex Scan</span>
          </div>
          <div className="flex items-center gap-2 sm:gap-4 flex-shrink-0">
            <Link to="/login" className="hidden sm:inline text-slate-600 dark:text-slate-300 hover:text-cyan-600 dark:hover:text-cyan-300 transition-colors">Login</Link>
            <Link to="/register" className="bg-gradient-to-r from-cyan-500 to-fuchsia-600 hover:from-cyan-400 hover:to-fuchsia-500 text-white px-3 sm:px-4 py-2 rounded-lg transition-all text-sm sm:text-base whitespace-nowrap shadow-lg shadow-fuchsia-500/25">
              Get Started
            </Link>
          </div>
        </nav>

        <section className="max-w-7xl mx-auto px-4 sm:px-6 py-12 sm:py-16 lg:py-20 text-center">
          <div className="inline-flex items-center gap-2 bg-slate-900/5 dark:bg-white/10 backdrop-blur-sm border border-cyan-500/30 dark:border-cyan-500/20 text-cyan-700 dark:text-cyan-300 px-4 py-2 rounded-full text-sm mb-6 sm:mb-8">
            <Activity size={16} />
            Web Security Scanning Tool
          </div>
          <h1 className="text-4xl sm:text-5xl lg:text-7xl font-bold mb-6 leading-tight">
            <DecryptedText
              text="Scan Your Website's"
              speed={40}
              maxIterations={12}
              sequential
              revealDirection="start"
              animateOn="view"
              className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 to-violet-400"
              encryptedClassName="text-slate-500 dark:text-slate-400"
            />
            <br />
            <DecryptedText
              text="Security Posture"
              speed={30}
              maxIterations={10}
              sequential
              revealDirection="center"
              animateOn="view"
              className="text-transparent bg-clip-text bg-gradient-to-r from-fuchsia-400 to-gold-300"
              encryptedClassName="text-slate-500 dark:text-slate-400"
            />
          </h1>
          <p className="text-base sm:text-xl text-slate-600 dark:text-slate-300 mb-8 sm:mb-10 max-w-2xl mx-auto">
            Vertex Scan analyzes HTTP security headers, TLS/SSL configuration, and exposed directories
            to help you identify and fix vulnerabilities before attackers do.
          </p>
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-center gap-3 sm:gap-4">
            <Link
              to="/register"
              className="bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white px-6 sm:px-8 py-3 rounded-lg text-base sm:text-lg font-medium transition-all inline-flex items-center justify-center gap-2 shadow-lg shadow-purple-500/30 hover:shadow-xl hover:shadow-purple-500/40"
            >
              Start Scanning Free
              <ArrowRight size={20} />
            </Link>
            <Link
              to="/login"
              className="border border-gray-600 text-gray-300 hover:text-white hover:border-cyan-500 px-6 sm:px-8 py-3 rounded-lg text-base sm:text-lg font-medium transition-colors text-center"
            >
              Sign In
            </Link>
          </div>
        </section>

        <section className="max-w-7xl mx-auto px-4 sm:px-6 py-12 sm:py-16 lg:py-20 w-full">
          <h2 className="text-2xl sm:text-3xl font-bold text-center mb-2 sm:mb-3">
            <DecryptedText
              text="Three Core Scanning Modules"
              speed={40}
              maxIterations={12}
              sequential
              revealDirection="center"
              animateOn="view"
              className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-fuchsia-400 to-violet-400"
              encryptedClassName="text-slate-500 dark:text-slate-400"
            />
          </h2>
          <p className="text-center text-sm text-slate-600 dark:text-slate-300 mb-8 sm:mb-12">
            Click any module to learn more from the original source
          </p>
          <div style={{ height: 'auto', minHeight: '640px', position: 'relative' }}>
            <ChromaGrid
              radius={320}
              damping={0.45}
              fadeOut={0.6}
              ease="power3.out"
              items={[
                {
                  image: 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Security Headers',
                  subtitle: 'HSTS, CSP, X-Frame-Options & 10+ critical headers',
                  handle: 'OWASP Secure Headers',
                  borderColor: '#06B6D4',
                  gradient: 'linear-gradient(145deg, #06B6D4, #040a14)',
                  url: 'https://owasp.org/www-project-secure-headers/',
                  credit: 'Photo by Markus Spiske on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/cyber-security'
                },
                {
                  image: 'https://images.unsplash.com/photo-1563013544-824ae1b704d3?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'TLS / SSL',
                  subtitle: 'Certificate validity, key strength & protocol versions',
                  handle: 'SSL Labs',
                  borderColor: '#A855F7',
                  gradient: 'linear-gradient(210deg, #A855F7, #0a0514)',
                  url: 'https://www.ssllabs.com/ssltest/',
                  credit: 'Photo by Roman Synkevych on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/lock'
                },
                {
                  image: 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Directory Enumeration',
                  subtitle: 'Admin panels, config files & 100+ common paths',
                  handle: 'OWASP DirBuster',
                  borderColor: '#F59E0B',
                  gradient: 'linear-gradient(165deg, #F59E0B, #140a02)',
                  url: 'https://owasp.org/www-project-dirbuster/',
                  credit: 'Photo by Growtika on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/matrix-code'
                },
                {
                  image: 'https://images.unsplash.com/photo-1555949963-aa79dcee981c?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Real-time Alerts',
                  subtitle: 'Instant notifications for critical vulnerabilities',
                  handle: 'OWASP Top 10',
                  borderColor: '#EF4444',
                  gradient: 'linear-gradient(195deg, #EF4444, #140404)',
                  url: 'https://owasp.org/www-project-top-ten/',
                  credit: 'Photo by Carlos Muza on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/led'
                },
                {
                  image: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Compliance Reports',
                  subtitle: 'PCI-DSS, HIPAA & SOC2 scanning and reporting',
                  handle: 'OWASP Compliance',
                  borderColor: '#10B981',
                  gradient: 'linear-gradient(225deg, #10B981, #02140a)',
                  url: 'https://owasp.org/www-community/Compliance',
                  credit: 'Photo by Campaign Creators on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/dashboard'
                },
                {
                  image: 'https://images.unsplash.com/photo-1627398242454-45a1465c2479?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'API Security',
                  subtitle: 'REST endpoint analysis, auth checks & rate-limit tests',
                  handle: 'OWASP API Top 10',
                  borderColor: '#8B5CF6',
                  gradient: 'linear-gradient(135deg, #8B5CF6, #0a0514)',
                  url: 'https://owasp.org/www-project-api-security/',
                  credit: 'Photo by Sigmund on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/code'
                }
              ]}
            />
          </div>
        </section>

        <section className="max-w-7xl mx-auto px-4 sm:px-6 py-12 sm:py-16 lg:py-20 w-full">
          <h2 className="text-2xl sm:text-3xl font-bold text-center mb-2 sm:mb-3">
            <DecryptedText
              text="Trusted Security in Action"
              speed={40}
              maxIterations={12}
              sequential
              revealDirection="center"
              animateOn="view"
              className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-fuchsia-400 to-violet-400"
              encryptedClassName="text-slate-500 dark:text-slate-400"
            />
          </h2>
          <p className="text-center text-sm text-slate-600 dark:text-slate-300 mb-8 sm:mb-12">
            Click any card to explore the topic at its original source
          </p>
          <div style={{ height: 'auto', minHeight: '640px', position: 'relative' }}>
            <ChromaGrid
              radius={320}
              damping={0.45}
              fadeOut={0.6}
              ease="power3.out"
              items={[
                {
                  image: 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Live Attack Surface',
                  subtitle: 'Continuous mapping of exposed assets',
                  handle: 'OWASP ASI',
                  borderColor: '#06B6D4',
                  gradient: 'linear-gradient(145deg, #06B6D4, #040a14)',
                  url: 'https://owasp.org/www-community/attacks/',
                  credit: 'Photo by ThisisEngineering RAEng on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/circuit-board'
                },
                {
                  image: 'https://images.unsplash.com/photo-1551808525-0519e4b46c46?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Threat Detection',
                  subtitle: 'Real-time detection of active threats',
                  handle: 'MITRE ATT&CK',
                  borderColor: '#EF4444',
                  gradient: 'linear-gradient(210deg, #EF4444, #140404)',
                  url: 'https://attack.mitre.org/',
                  credit: 'Photo by Alexandre Debiève on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/network'
                },
                {
                  image: 'https://images.unsplash.com/photo-1510906594845-bc082582c8cc?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Vulnerability Reports',
                  subtitle: 'Detailed findings with remediation steps',
                  handle: 'CVE Database',
                  borderColor: '#A855F7',
                  gradient: 'linear-gradient(165deg, #A855F7, #0a0514)',
                  url: 'https://cve.mitre.org/',
                  credit: 'Photo by AltumCode on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/code'
                },
                {
                  image: 'https://images.unsplash.com/photo-1639322537228-f710d846310a?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Security Grading',
                  subtitle: 'A+ to F grades for every scan',
                  handle: 'Mozilla Observatory',
                  borderColor: '#10B981',
                  gradient: 'linear-gradient(195deg, #10B981, #02140a)',
                  url: 'https://observatory.mozilla.org/',
                  credit: 'Photo by Shubham Dhage on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/circuit'
                },
                {
                  image: 'https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Compliance Dashboards',
                  subtitle: 'Track PCI-DSS, HIPAA & SOC2 posture',
                  handle: 'CIS Controls',
                  borderColor: '#F59E0B',
                  gradient: 'linear-gradient(225deg, #F59E0B, #140a02)',
                  url: 'https://www.cisecurity.org/controls',
                  credit: 'Photo by Luke Chesser on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/laptop'
                },
                {
                  image: 'https://images.unsplash.com/photo-1534796636912-3b95b3ab5986?auto=format&fit=crop&w=400&h=400&q=80',
                  title: 'Secure Deployments',
                  subtitle: 'Scan before every release',
                  handle: 'OWASP DevSecOps',
                  borderColor: '#8B5CF6',
                  gradient: 'linear-gradient(135deg, #8B5CF6, #0a0514)',
                  url: 'https://owasp.org/www-project-devsecops-maturity-model/',
                  credit: 'Photo by NASA on Unsplash',
                  creditUrl: 'https://unsplash.com/s/photos/rocket'
                }
              ]}
            />
          </div>
        </section>

        <section className="max-w-7xl mx-auto px-4 sm:px-6 py-12 sm:py-16 lg:py-20 text-center w-full">
          <ElectricBorder color={isDark ? '#C026D3' : '#06B6D4'} speed={1} chaos={0.12} borderRadius={24} style={{ borderRadius: 24 }}>
            <div className="bg-gradient-to-r from-cyan-600 via-violet-600 to-fuchsia-600 rounded-2xl p-8 sm:p-12 shadow-xl shadow-fuchsia-500/20">
              <h2 className="text-2xl sm:text-3xl font-bold text-white mb-4">
                <DecryptedText
                  text="Ready to Secure Your Website?"
                  speed={40}
                  maxIterations={10}
                  sequential
                  revealDirection="start"
                  animateOn="view"
                  className="text-white"
                  encryptedClassName="text-white/50"
                />
              </h2>
              <p className="text-white/80 mb-6 sm:mb-8 max-w-xl mx-auto">
                Get a comprehensive security analysis of your website in minutes. No credit card required.
              </p>
              <Link
                to="/register"
                className="bg-white text-violet-700 hover:bg-slate-100 px-6 sm:px-8 py-3 rounded-lg text-base sm:text-lg font-medium transition-colors inline-flex items-center gap-2 shadow-lg"
              >
                Create Free Account
                <ArrowRight size={20} />
              </Link>
            </div>
          </ElectricBorder>
        </section>

        <footer className="border-t border-slate-200 dark:border-white/10 py-8 text-center text-slate-600 dark:text-gray-300 text-sm mt-auto">
          <p>Vertex Scan v1.0.0 — Web Security Scanning Tool</p>
          <p className="mt-1">Built for security engineers and developers</p>
        </footer>
      </div>
    </div>
  );
}