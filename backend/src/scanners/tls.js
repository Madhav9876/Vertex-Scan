// Vertex Scan - TLS/SSL Scanner
// Analyzes TLS configuration, certificate validity, and protocol support
// v2.0 - Uses pinned request utility for proper Host header handling

const tls = require('tls');
const https = require('https');
const { pinnedGet } = require('../utils/request');

async function scanTLS(target) {
  const findings = [];
  const hostname = (target && target.hostname) || new URL(target.normalized).hostname;
  const port = (target && target.port) || 443;

  // Check if HTTPS is supported
  try {
    const httpsSupported = await checkHTTPS(target);
    
    if (!httpsSupported) {
      findings.push({
        category: 'tls',
        severity: 'critical',
        title: 'HTTPS Not Supported',
        description: `${hostname} does not support HTTPS connections on port ${port}. All traffic is unencrypted.`,
        impact: 'All data transmitted is in plaintext and vulnerable to interception (MITM attacks).',
        remediation: 'Install an SSL/TLS certificate and redirect all HTTP traffic to HTTPS.',
        current_value: `Port ${port}: no HTTPS response`,
        recommended_value: 'HTTPS enabled with valid certificate',
        confidence: 'high',
        cwe_id: 'CWE-319'
      });
      return findings;
    }

    // Get certificate details
    const certInfo = await getCertificateInfo(target);

    if (!certInfo) {
      findings.push({
        category: 'tls',
        severity: 'high',
        title: 'Unable to Retrieve TLS Certificate',
        description: `Could not retrieve the TLS certificate from ${hostname}:${port}.`,
        impact: 'Unable to verify certificate validity, strength, or configuration.',
        remediation: 'Ensure the server is accessible and has a properly configured TLS certificate.',
        current_value: 'No certificate data',
        recommended_value: 'Valid TLS certificate installed',
        confidence: 'medium'
      });
      return findings;
    }

    // Check certificate expiration
    const now = new Date();
    const expiryDate = new Date(certInfo.validTo);
    const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));

    if (daysUntilExpiry < 0) {
      findings.push({
        category: 'tls',
        severity: 'critical',
        title: 'SSL/TLS Certificate Expired',
        description: `The certificate for ${hostname} expired ${Math.abs(daysUntilExpiry)} days ago on ${certInfo.validTo}.`,
        impact: 'Users will see browser security warnings and the site may be inaccessible over HTTPS.',
        remediation: 'Renew the SSL/TLS certificate immediately with your certificate authority.',
        current_value: `Expired ${Math.abs(daysUntilExpiry)} days ago`,
        recommended_value: 'Valid certificate with at least 30 days until expiry',
        confidence: 'high',
        cwe_id: 'CWE-295'
      });
    } else if (daysUntilExpiry < 30) {
      findings.push({
        category: 'tls',
        severity: 'high',
        title: 'SSL/TLS Certificate Expiring Soon',
        description: `The certificate for ${hostname} expires in ${daysUntilExpiry} days on ${certInfo.validTo}.`,
        impact: 'Service disruption risk if certificate is not renewed before expiry.',
        remediation: 'Renew the certificate before it expires to avoid service interruption.',
        current_value: `Expires in ${daysUntilExpiry} days`,
        recommended_value: 'Certificate valid for at least 30 days',
        confidence: 'high',
        cwe_id: 'CWE-295'
      });
    }

    // Check certificate issuer
    if (certInfo.issuer && certInfo.issuer.O) {
      const trustedIssuers = [
        "Let's Encrypt", 'DigiCert', 'Comodo', 'Sectigo', 'GlobalSign',
        'Amazon', 'Google Trust Services', 'Cloudflare', 'GTS', 'ZeroSSL'
      ];
      const issuerName = certInfo.issuer.O;
      const isTrusted = trustedIssuers.some(ti => issuerName.toLowerCase().includes(ti.toLowerCase()));

      if (!isTrusted && !issuerName.includes('Self-Signed')) {
        findings.push({
          category: 'tls',
          severity: 'info',
          title: 'Uncommon Certificate Authority',
          description: `The certificate is issued by "${issuerName}". Verify this is a trusted CA.`,
          impact: 'Uncommon or self-signed CAs may not be trusted by all browsers.',
          remediation: 'Use a well-known certificate authority for better browser compatibility.',
          current_value: `Issuer: ${issuerName}`,
          recommended_value: 'Trusted public CA (Let\'s Encrypt, DigiCert, etc.)',
          confidence: 'low',
          cwe_id: 'CWE-295'
        });
      }
    }

    // Check for self-signed certificates
    if (certInfo.selfSigned || (certInfo.issuer && certInfo.subject && 
        JSON.stringify(certInfo.issuer) === JSON.stringify(certInfo.subject))) {
      findings.push({
        category: 'tls',
        severity: 'critical',
        title: 'Self-Signed Certificate Detected',
        description: `${hostname} uses a self-signed certificate, which is not trusted by browsers.`,
        impact: 'Users will see untrusted certificate warnings. The connection could be intercepted.',
        remediation: 'Replace the self-signed certificate with one from a trusted certificate authority.',
        current_value: 'Self-signed certificate',
        recommended_value: 'Certificate from trusted CA (e.g., Let\'s Encrypt)',
        confidence: 'high',
        cwe_id: 'CWE-295'
      });
    }

    // Check key strength
    if (certInfo.keyStrength) {
      const keyStrength = parseInt(certInfo.keyStrength);
      if (keyStrength < 2048) {
        findings.push({
          category: 'tls',
          severity: 'high',
          title: 'Weak Certificate Key Strength',
          description: `The certificate uses a ${keyStrength}-bit key, which is below the recommended minimum of 2048 bits.`,
          impact: 'Weak keys are susceptible to brute-force attacks and can be compromised.',
          remediation: 'Generate a new certificate with at least a 2048-bit RSA key (4096-bit recommended).',
          current_value: `${keyStrength}-bit key`,
          recommended_value: '2048-bit or stronger key',
          confidence: 'high',
          cwe_id: 'CWE-326'
        });
      }
      if (keyStrength >= 4096) {
        findings.push({
          category: 'tls',
          severity: 'info',
          title: 'Strong Certificate Key',
          description: `The certificate uses a strong ${keyStrength}-bit key.`,
          impact: 'Strong key provides robust encryption. No action needed.',
          current_value: `${keyStrength}-bit key`,
          recommended_value: `${keyStrength}-bit key (meets standards)`,
          confidence: 'high'
        });
      }
    }

    // Check signature algorithm
    if (certInfo.signatureAlgorithm) {
      const weakAlgorithms = ['sha1', 'md5', 'sha-1', 'md2', 'rc4'];
      const sigAlgo = certInfo.signatureAlgorithm.toLowerCase();
      const isWeak = weakAlgorithms.some(wa => sigAlgo.includes(wa));

      if (isWeak) {
        findings.push({
          category: 'tls',
          severity: 'high',
          title: 'Weak Signature Algorithm',
          description: `The certificate uses "${certInfo.signatureAlgorithm}" which is considered weak and deprecated.`,
          impact: 'Weak signature algorithms are vulnerable to collision attacks.',
          remediation: 'Reissue the certificate using SHA-256 or stronger hash algorithm.',
          current_value: certInfo.signatureAlgorithm,
          recommended_value: 'SHA-256 or stronger',
          confidence: 'high',
          cwe_id: 'CWE-327'
        });
      }
    }

    // Check TLS protocol versions
    const protocolVersions = await checkTLSProtocols(target);
    
    if (protocolVersions.tlsv1_0) {
      findings.push({
        category: 'tls',
        severity: 'high',
        title: 'TLS 1.0 Enabled',
        description: `${hostname} supports TLS 1.0, which is deprecated and insecure.`,
        impact: 'TLS 1.0 is vulnerable to several attacks including POODLE and BEAST.',
        remediation: 'Disable TLS 1.0 and 1.1, keep TLS 1.2 and 1.3 enabled.',
        current_value: 'TLS 1.0 enabled',
        recommended_value: 'TLS 1.2 and 1.3 only',
        confidence: 'high',
        cwe_id: 'CWE-326'
      });
    }
    
    if (protocolVersions.tlsv1_1) {
      findings.push({
        category: 'tls',
        severity: 'medium',
        title: 'TLS 1.1 Enabled',
        description: `${hostname} supports TLS 1.1, which is deprecated.`,
        impact: 'TLS 1.1 lacks modern security features and is being phased out.',
        remediation: 'Disable TLS 1.1 and keep TLS 1.2 and 1.3 enabled.',
        current_value: 'TLS 1.1 enabled',
        recommended_value: 'TLS 1.2 and 1.3 only',
        confidence: 'high',
        cwe_id: 'CWE-326'
      });
    }

    if (!protocolVersions.tlsv1_2 && !protocolVersions.tlsv1_3) {
      findings.push({
        category: 'tls',
        severity: 'critical',
        title: 'No Modern TLS Versions',
        description: `${hostname} does not support TLS 1.2 or 1.3, which are required for secure communications.`,
        impact: 'Connections may use obsolete and insecure protocol versions.',
        remediation: 'Enable TLS 1.2 and TLS 1.3 on the server.',
        current_value: 'TLS 1.2/1.3 not detected',
        recommended_value: 'TLS 1.2 and 1.3 enabled',
        confidence: 'high',
        cwe_id: 'CWE-326'
      });
    }

    if (protocolVersions.tlsv1_3) {
      findings.push({
        category: 'tls',
        severity: 'info',
        title: 'TLS 1.3 Supported',
        description: `${hostname} supports TLS 1.3, the latest secure protocol version.`,
        impact: 'Modern, secure protocol with improved performance and security.',
        current_value: 'TLS 1.3 supported',
        recommended_value: 'TLS 1.3 (current best practice)',
        confidence: 'high'
      });
    }

    // Check for HSTS (using pinnedGet for proper Host header)
    try {
      const hstsResult = await pinnedGet(target, '/', { timeout: 8000, maxBodySize: 1024 });
      if (hstsResult && hstsResult.headers) {
        const hstsHeader = hstsResult.headers['strict-transport-security'] || hstsResult.headers['Strict-Transport-Security'];
        if (hstsHeader) {
          findings.push({
            category: 'tls',
            severity: 'info',
            title: 'HSTS Implemented',
            description: `${hostname} implements HTTP Strict Transport Security (HSTS).`,
            impact: 'Browsers will enforce HTTPS connections, preventing downgrade attacks.',
            current_value: hstsHeader,
            recommended_value: 'HSTS configured correctly',
            confidence: 'high'
          });
        }
      }
    } catch (e) {
      // HSTS check failed, skip
    }

  } catch (err) {
    findings.push({
      category: 'tls',
      severity: 'high',
      title: 'TLS Scan Error',
      description: `An error occurred while scanning TLS configuration: ${err.message}`,
      impact: 'Unable to complete TLS security assessment.',
      remediation: 'Ensure the target is accessible and has a valid TLS configuration.',
      current_value: err.message,
      recommended_value: 'Successful TLS assessment',
      confidence: 'high'
    });
  }

  return findings;
}

function checkHTTPS(target) {
  return new Promise((resolve) => {
    const options = {
      hostname: target.resolvedAddress,
      host: target.resolvedAddress,
      port: target.port || 443,
      path: '/',
      method: 'GET',
      rejectUnauthorized: false,
      servername: target.hostname,
      timeout: 8000,
      headers: {
        'Host': target.hostname,
        'User-Agent': 'Vertex-Scan/1.0'
      }
    };

    const req = https.get(options, (res) => {
      res.resume();
      resolve(true);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

function getCertificateInfo(target) {
  return new Promise((resolve) => {
    const hostname = target.resolvedAddress;
    const port = target.port || 443;
    const sniHostname = target.hostname;

    const socket = tls.connect({
      host: hostname,
      port: port,
      servername: sniHostname || hostname,
      rejectUnauthorized: false,
      timeout: 8000
    }, () => {
      const cert = socket.getPeerCertificate(true);
      if (Object.keys(cert).length === 0) {
        socket.end();
        resolve(null);
        return;
      }

      const info = {
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        fingerprint: cert.fingerprint,
        serialNumber: cert.serialNumber,
        keyStrength: cert.bits || null,
        signatureAlgorithm: cert.sigalg || null,
        subjectAltName: cert.subjectaltname || null,
        selfSigned: false
      };

      // Check if self-signed
      if (cert.subject && cert.issuer) {
        const sub = JSON.stringify(cert.subject);
        const iss = JSON.stringify(cert.issuer);
        info.selfSigned = sub === iss;
      }

      socket.end();
      resolve(info);
    });

    socket.on('error', () => {
      resolve(null);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

function checkTLSProtocols(target) {
  const protocols = {
    tlsv1_0: false,
    tlsv1_1: false,
    tlsv1_2: false,
    tlsv1_3: false
  };

  const hostname = target.resolvedAddress;
  const port = target.port || 443;
  const sniHostname = target.hostname;

  return new Promise((resolve) => {
    const versions = [
      { name: 'tlsv1_0', min: 'TLSv1', max: 'TLSv1' },
      { name: 'tlsv1_1', min: 'TLSv1.1', max: 'TLSv1.1' },
      { name: 'tlsv1_2', min: 'TLSv1.2', max: 'TLSv1.2' },
    ];

    let completed = 0;
    const total = versions.length + 1; // +1 for TLS 1.3

    versions.forEach(ver => {
      try {
        const socket = tls.connect({
          host: hostname,
          port: port,
          servername: sniHostname,
          rejectUnauthorized: false,
          minVersion: ver.min,
          maxVersion: ver.max,
          timeout: 3000
        }, () => {
          protocols[ver.name] = true;
          socket.end();
          checkDone();
        });

        socket.on('error', () => checkDone());
        socket.on('timeout', () => {
          socket.destroy();
          checkDone();
        });
      } catch (e) {
        checkDone();
      }
    });

    // Check TLS 1.3 separately
    try {
      const tls13Socket = tls.connect({
        host: hostname,
        port: port,
        servername: sniHostname,
        rejectUnauthorized: false,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        timeout: 3000
      }, () => {
        protocols.tlsv1_3 = true;
        tls13Socket.end();
        checkDone();
      });
      tls13Socket.on('error', () => checkDone());
      tls13Socket.on('timeout', () => {
        tls13Socket.destroy();
        checkDone();
      });
    } catch (e) {
      checkDone();
    }

    function checkDone() {
      completed++;
      if (completed >= total) {
        resolve(protocols);
      }
    }
  });
}

module.exports = { scanTLS };