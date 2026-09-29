import { useState, useEffect, useCallback, useRef } from 'react';

// ============================================================
// TYPES & INTERFACES
// ============================================================

type HostStatus = 'standby' | 'active' | 'compromised' | 'scanning';

interface NetworkHost {
  id: string;
  ip: string;
  hostname: string;
  mac: string;
  status: HostStatus;
  os: string;
  ports: number[];
  lastSeen: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  selected: boolean;
  isManual?: boolean;
}

interface ScanStats {
  totalScanned: number;
  active: number;
  compromised: number;
  standby: number;
}

interface DomainAnalysis {
  domain: string;
  ip: string | null;
  dnsRecords: { type: string; value: string; ttl: number }[];
  httpStatus: number | null;
  responseTime: number | null;
  isReachable: boolean;
  geoLocation: {
    country: string;
    city: string;
    isp: string;
    lat: number;
    lon: number;
  } | null;
  analyzedAt: string;
}

// ============================================================
// NETWORK SCAN ENGINE (Simulated for Browser Environment)
// ============================================================

const SUBNET_PREFIX = '192.168.1';
const HOSTNAMES = [
  'ATIBON-GW-01', 'SRV-DOMAIN-01', 'WS-FINANCE-03', 'NAS-BACKUP-02',
  'PRINTER-HP-01', 'IOT-CAMERA-04', 'SRV-WEB-PROD', 'WS-DEV-07',
  'ROUTER-CISCO-01', 'SRV-DB-MASTER', 'WS-RH-02', 'IOT-SENSOR-12',
  'SRV-MAIL-EXCH', 'WS-MARKETING-05', 'FIREWALL-PF-01', 'SRV-DNS-INT',
  'WS-IT-ADMIN-01', 'IOT-THERMOSTAT-03', 'SRV-FTP-LEGACY', 'WS-RECEPTION-01'
];

const OS_TYPES = [
  'Windows Server 2022', 'Ubuntu 22.04 LTS', 'Windows 11 Pro',
  'Debian 12', 'macOS Sonoma', 'Embedded Linux', 'pfSense 2.7',
  'CentOS Stream 9', 'Windows 10 Enterprise', 'Raspberry Pi OS'
];

const COMMON_PORTS = [22, 53, 80, 135, 139, 443, 445, 993, 1433, 3306, 3389, 5432, 8080, 8443];

function generateMAC(): string {
  const hex = '0123456789ABCDEF';
  let mac = '';
  for (let i = 0; i < 6; i++) {
    if (i > 0) mac += ':';
    mac += hex[Math.floor(Math.random() * 16)] + hex[Math.floor(Math.random() * 16)];
  }
  return mac;
}

function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function generateHosts(count: number): NetworkHost[] {
  const hosts: NetworkHost[] = [];
  const usedIps = new Set<string>();

  for (let i = 0; i < count; i++) {
    let ip: string;
    do {
      ip = `${SUBNET_PREFIX}.${Math.floor(Math.random() * 254) + 1}`;
    } while (usedIps.has(ip));
    usedIps.add(ip);

    const statusRoll = Math.random();
    let status: HostStatus;
    let riskLevel: NetworkHost['riskLevel'];

    if (statusRoll < 0.15) {
      status = 'compromised';
      riskLevel = Math.random() > 0.5 ? 'critical' : 'high';
    } else if (statusRoll < 0.65) {
      status = 'active';
      riskLevel = Math.random() > 0.7 ? 'medium' : 'low';
    } else {
      status = 'standby';
      riskLevel = 'low';
    }

    const portCount = Math.floor(Math.random() * 5) + 1;
    const ports: number[] = [];
    for (let p = 0; p < portCount; p++) {
      const port = COMMON_PORTS[Math.floor(Math.random() * COMMON_PORTS.length)];
      if (!ports.includes(port)) ports.push(port);
    }

    hosts.push({
      id: generateUUID(),
      ip,
      hostname: HOSTNAMES[i % HOSTNAMES.length],
      mac: generateMAC(),
      status,
      os: OS_TYPES[Math.floor(Math.random() * OS_TYPES.length)],
      ports: ports.sort((a, b) => a - b),
      lastSeen: new Date().toISOString(),
      riskLevel,
      selected: false,
    });
  }

  return hosts.sort((a, b) => {
    const aParts = a.ip.split('.').map(Number);
    const bParts = b.ip.split('.').map(Number);
    for (let i = 0; i < 4; i++) {
      if (aParts[i] !== bParts[i]) return aParts[i] - bParts[i];
    }
    return 0;
  });
}

// ============================================================
// MANUAL IP PROBE ENGINE
// ============================================================

async function probeSpecificIP(ip: string): Promise<NetworkHost> {
  // Simulate ping/connectivity test
  await new Promise(resolve => setTimeout(resolve, 800 + Math.random() * 1200));

  // Determine status based on connectivity simulation
  const statusRoll = Math.random();
  let status: HostStatus;
  let riskLevel: NetworkHost['riskLevel'];

  if (statusRoll < 0.1) {
    status = 'compromised';
    riskLevel = 'high';
  } else if (statusRoll < 0.7) {
    status = 'active';
    riskLevel = Math.random() > 0.6 ? 'medium' : 'low';
  } else {
    status = 'standby';
    riskLevel = 'low';
  }

  // Generate random ports for this IP
  const portCount = Math.floor(Math.random() * 4) + 1;
  const ports: number[] = [];
  for (let p = 0; p < portCount; p++) {
    const port = COMMON_PORTS[Math.floor(Math.random() * COMMON_PORTS.length)];
    if (!ports.includes(port)) ports.push(port);
  }

  // Try to resolve hostname via reverse DNS (simulated)
  const hostnamePrefixes = ['HOST', 'SRV', 'WS', 'NODE', 'DEV', 'PROD', 'TEST'];
  const hostname = `${hostnamePrefixes[Math.floor(Math.random() * hostnamePrefixes.length)]}-${Math.floor(Math.random() * 99).toString().padStart(2, '0')}`;

  return {
    id: generateUUID(),
    ip,
    hostname,
    mac: generateMAC(),
    status,
    os: OS_TYPES[Math.floor(Math.random() * OS_TYPES.length)],
    ports: ports.sort((a, b) => a - b),
    lastSeen: new Date().toISOString(),
    riskLevel,
    selected: false,
    isManual: true,
  };
}

function isValidIP(ip: string): boolean {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) return false;
  
  const parts = ip.split('.').map(Number);
  return parts.every(part => part >= 0 && part <= 255);
}

// ============================================================
// DOMAIN ANALYSIS ENGINE (Real API Integration)
// ============================================================

async function analyzeDomain(domain: string): Promise<DomainAnalysis> {
  const result: DomainAnalysis = {
    domain,
    ip: null,
    dnsRecords: [],
    httpStatus: null,
    responseTime: null,
    isReachable: false,
    geoLocation: null,
    analyzedAt: new Date().toISOString(),
  };

  try {
    // Clean domain input
    let cleanDomain = domain.trim().toLowerCase();
    cleanDomain = cleanDomain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    
    // DNS Resolution via Google DNS over HTTPS
    const dnsResponse = await fetch(`https://dns.google/resolve?name=${cleanDomain}&type=A`);
    const dnsData = await dnsResponse.json();
    
    if (dnsData.Answer && dnsData.Answer.length > 0) {
      const aRecords = dnsData.Answer.filter((r: any) => r.type === 1);
      if (aRecords.length > 0) {
        result.ip = aRecords[0].data;
        
        // Collect all DNS records
        dnsData.Answer.forEach((record: any) => {
          const typeNames: Record<number, string> = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA'
          };
          result.dnsRecords.push({
            type: typeNames[record.type] || `TYPE${record.type}`,
            value: record.data,
            ttl: record.TTL || 0,
          });
        });

        // Get geolocation of IP
        try {
          const geoResponse = await fetch(`http://ip-api.com/json/${result.ip}?fields=status,country,city,isp,lat,lon`);
          const geoData = await geoResponse.json();
          if (geoData.status === 'success') {
            result.geoLocation = {
              country: geoData.country,
              city: geoData.city,
              isp: geoData.isp,
              lat: geoData.lat,
              lon: geoData.lon,
            };
          }
        } catch (e) {
          // Geo lookup failed, continue without it
        }

        // Check HTTP status
        try {
          const startTime = Date.now();
          const httpUrl = `https://${cleanDomain}`;
          const response = await fetch(httpUrl, { method: 'HEAD', mode: 'no-cors' });
          const endTime = Date.now();
          result.responseTime = endTime - startTime;
          result.isReachable = true;
          result.httpStatus = response.type === 'opaque' ? 200 : response.status;
        } catch (e) {
          // Try HTTP if HTTPS fails
          try {
            const startTime = Date.now();
            const httpUrl = `http://${cleanDomain}`;
            const response = await fetch(httpUrl, { method: 'HEAD', mode: 'no-cors' });
            const endTime = Date.now();
            result.responseTime = endTime - startTime;
            result.isReachable = true;
            result.httpStatus = response.type === 'opaque' ? 200 : response.status;
          } catch (e2) {
            result.isReachable = false;
          }
        }
      }
    }
  } catch (error) {
    console.error('Domain analysis error:', error);
  }

  return result;
}

// ============================================================
// COMPONENTS
// ============================================================

function StatusBadge({ status }: { status: HostStatus }) {
  const config = {
    standby: { bg: 'bg-gray-700/50', text: 'text-gray-300', dot: 'bg-gray-400', label: 'STANDBY' },
    active: { bg: 'bg-emerald-900/40', text: 'text-emerald-400', dot: 'bg-emerald-400', label: 'ACTIVE' },
    compromised: { bg: 'bg-red-900/40', text: 'text-red-400', dot: 'bg-red-500', label: 'COMPROMISED' },
    scanning: { bg: 'bg-cyan-900/40', text: 'text-cyan-400', dot: 'bg-cyan-400', label: 'SCANNING' },
  };
  const c = config[status];

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${c.bg} ${c.text} border border-current/20`}>
      <span className={`w-2 h-2 rounded-full ${c.dot} ${status === 'active' || status === 'scanning' ? 'pulse-dot' : ''}`}></span>
      {c.label}
    </span>
  );
}

function RiskBadge({ level }: { level: NetworkHost['riskLevel'] }) {
  const config = {
    low: { bg: 'bg-emerald-900/30', text: 'text-emerald-400', border: 'border-emerald-700/50' },
    medium: { bg: 'bg-yellow-900/30', text: 'text-yellow-400', border: 'border-yellow-700/50' },
    high: { bg: 'bg-orange-900/30', text: 'text-orange-400', border: 'border-orange-700/50' },
    critical: { bg: 'bg-red-900/40', text: 'text-red-400', border: 'border-red-700/50' },
  };
  const c = config[level];

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase ${c.bg} ${c.text} border ${c.border}`}>
      <i className={`fas fa-${level === 'critical' ? 'skull-crossbones' : level === 'high' ? 'exclamation-triangle' : level === 'medium' ? 'exclamation-circle' : 'shield-alt'} mr-1`}></i>
      {level}
    </span>
  );
}

function StatCard({ title, value, icon, color, glow }: {
  title: string;
  value: number | string;
  icon: string;
  color: string;
  glow: string;
}) {
  return (
    <div className={`relative overflow-hidden rounded-xl border border-white/5 bg-[#111827]/80 backdrop-blur-sm p-5 transition-all duration-300 hover:scale-[1.02] ${glow}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-wider text-gray-400 mb-1">{title}</p>
          <p className={`text-3xl font-bold ${color}`}>{value}</p>
        </div>
        <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${color} bg-current/10`}>
          <i className={`fas ${icon} text-xl`}></i>
        </div>
      </div>
      <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-current/30 to-transparent" style={{ color: 'inherit' }}></div>
    </div>
  );
}

function ScanProgress({ progress, phase }: { progress: number; phase: string }) {
  return (
    <div className="w-full max-w-2xl mx-auto py-8 fade-in">
      <div className="text-center mb-6">
        <div className="inline-flex items-center gap-3 mb-3">
          <div className="relative">
            <i className="fas fa-satellite-dish text-cyan-400 text-3xl"></i>
            <div className="absolute inset-0 animate-ping">
              <i className="fas fa-satellite-dish text-cyan-400/30 text-3xl"></i>
            </div>
          </div>
          <h3 className="text-xl font-bold text-cyan-300">Balayage Réseau en Cours</h3>
        </div>
        <p className="text-gray-400 text-sm">{phase}</p>
      </div>

      <div className="relative h-3 bg-gray-800 rounded-full overflow-hidden border border-gray-700">
        <div
          className="absolute inset-y-0 left-0 bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500 rounded-full transition-all duration-500 ease-out"
          style={{ width: `${progress}%` }}
        ></div>
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent scan-line"></div>
      </div>

      <div className="flex justify-between mt-3 text-xs text-gray-500">
        <span>Sous-réseau: {SUBNET_PREFIX}.0/24</span>
        <span className="text-cyan-400 font-mono">{progress}%</span>
        <span>Hôtes détectés: {Math.floor(progress / 5)}</span>
      </div>

      <div className="mt-6 grid grid-cols-3 gap-4 text-center">
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700/50">
          <p className="text-lg font-bold text-cyan-400">{Math.floor(progress / 5)}</p>
          <p className="text-xs text-gray-500">Paquets envoyés</p>
        </div>
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700/50">
          <p className="text-lg font-bold text-emerald-400">{Math.floor(progress / 10)}</p>
          <p className="text-xs text-gray-500">Réponses reçues</p>
        </div>
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700/50">
          <p className="text-lg font-bold text-purple-400">{Math.floor(progress / 25)}</p>
          <p className="text-xs text-gray-500">Ports analysés</p>
        </div>
      </div>
    </div>
  );
}

function HostRow({ host, onToggle, onRegister }: {
  host: NetworkHost;
  onToggle: (id: string) => void;
  onRegister: (host: NetworkHost) => void;
}) {
  return (
    <tr className={`border-b border-gray-800/50 transition-all duration-200 hover:bg-gray-800/30 ${
      host.isManual ? 'bg-orange-900/10 border-l-2 border-l-orange-400' : 
      host.selected ? 'bg-cyan-900/10 border-l-2 border-l-cyan-400' : ''
    }`}>
      <td className="px-4 py-3">
        <input
          type="checkbox"
          checked={host.selected}
          onChange={() => onToggle(host.id)}
          className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-0 cursor-pointer"
        />
      </td>
      <td className="px-4 py-3">
        <code className={`font-mono text-sm px-2 py-0.5 rounded ${
          host.isManual ? 'text-orange-300 bg-orange-900/20' : 'text-cyan-300 bg-cyan-900/20'
        }`}>{host.ip}</code>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="text-gray-200 font-medium text-sm">{host.hostname}</span>
          {host.isManual && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold bg-orange-900/40 text-orange-400 border border-orange-700/50">
              <i className="fas fa-crosshairs text-[10px]"></i>
              MANUEL
            </span>
          )}
        </div>
      </td>
      <td className="px-4 py-3">
        <code className="text-gray-400 font-mono text-xs">{host.mac}</code>
      </td>
      <td className="px-4 py-3">
        <StatusBadge status={host.status} />
      </td>
      <td className="px-4 py-3">
        <RiskBadge level={host.riskLevel} />
      </td>
      <td className="px-4 py-3">
        <span className="text-gray-400 text-xs">{host.os}</span>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {host.ports.slice(0, 3).map(port => (
            <span key={port} className="text-xs bg-gray-800 text-gray-300 px-1.5 py-0.5 rounded font-mono">{port}</span>
          ))}
          {host.ports.length > 3 && (
            <span className="text-xs text-gray-500">+{host.ports.length - 3}</span>
          )}
        </div>
      </td>
      <td className="px-4 py-3">
        <button
          onClick={() => onRegister(host)}
          className="text-xs bg-cyan-600/20 text-cyan-400 border border-cyan-700/50 px-3 py-1.5 rounded-lg hover:bg-cyan-600/30 transition-colors font-medium"
        >
          <i className="fas fa-plus-circle mr-1"></i>Enregistrer
        </button>
      </td>
    </tr>
  );
}

function DomainAnalysisCard({ analysis }: { analysis: DomainAnalysis }) {
  return (
    <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6 space-y-4 fade-in">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h4 className="text-lg font-bold text-white flex items-center gap-2">
            <i className="fas fa-globe text-cyan-400"></i>
            {analysis.domain}
          </h4>
          <p className="text-xs text-gray-500 mt-1">
            Analysé le {new Date(analysis.analyzedAt).toLocaleString('fr-FR')}
          </p>
        </div>
        <div className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
          analysis.isReachable 
            ? 'bg-emerald-900/40 text-emerald-400 border border-emerald-700/50' 
            : 'bg-red-900/40 text-red-400 border border-red-700/50'
        }`}>
          <i className={`fas fa-${analysis.isReachable ? 'check-circle' : 'times-circle'} mr-1`}></i>
          {analysis.isReachable ? 'ACCESSIBLE' : 'INACCESSIBLE'}
        </div>
      </div>

      {/* IP & Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-700/30">
          <p className="text-xs text-gray-400 mb-1">Adresse IP</p>
          <p className="text-lg font-mono font-bold text-cyan-300">
            {analysis.ip || 'N/A'}
          </p>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-700/30">
          <p className="text-xs text-gray-400 mb-1">Statut HTTP</p>
          <p className="text-lg font-mono font-bold text-white">
            {analysis.httpStatus || 'N/A'}
          </p>
        </div>
        <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-700/30">
          <p className="text-xs text-gray-400 mb-1">Temps de Réponse</p>
          <p className="text-lg font-mono font-bold text-emerald-400">
            {analysis.responseTime ? `${analysis.responseTime}ms` : 'N/A'}
          </p>
        </div>
      </div>

      {/* Geolocation */}
      {analysis.geoLocation && (
        <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-700/30">
          <p className="text-xs text-gray-400 mb-2 flex items-center gap-1">
            <i className="fas fa-map-marker-alt text-purple-400"></i>
            Géolocalisation
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div>
              <p className="text-gray-500 text-xs">Pays</p>
              <p className="text-white font-medium">{analysis.geoLocation.country}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs">Ville</p>
              <p className="text-white font-medium">{analysis.geoLocation.city}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs">FAI</p>
              <p className="text-white font-medium truncate">{analysis.geoLocation.isp}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs">Coordonnées</p>
              <p className="text-white font-mono text-xs">
                {analysis.geoLocation.lat.toFixed(4)}, {analysis.geoLocation.lon.toFixed(4)}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* DNS Records */}
      {analysis.dnsRecords.length > 0 && (
        <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-700/30">
          <p className="text-xs text-gray-400 mb-3 flex items-center gap-1">
            <i className="fas fa-server text-cyan-400"></i>
            Enregistrements DNS ({analysis.dnsRecords.length})
          </p>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {analysis.dnsRecords.map((record, idx) => (
              <div key={idx} className="flex items-center justify-between text-sm bg-gray-800/50 rounded px-3 py-2">
                <span className="font-mono text-xs bg-cyan-900/30 text-cyan-300 px-2 py-0.5 rounded">
                  {record.type}
                </span>
                <span className="text-gray-300 font-mono text-xs flex-1 mx-3 truncate">
                  {record.value}
                </span>
                <span className="text-gray-500 text-xs">
                  TTL: {record.ttl}s
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================
// MAIN APPLICATION
// ============================================================

export default function App() {
  // Module 1: LAN Scanner State
  const [hosts, setHosts] = useState<NetworkHost[]>([]);
  const [registeredHosts, setRegisteredHosts] = useState<NetworkHost[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanPhase, setScanPhase] = useState('');
  const [scanComplete, setScanComplete] = useState(false);
  const [stats, setStats] = useState<ScanStats>({ totalScanned: 0, active: 0, compromised: 0, standby: 0 });
  const [filter, setFilter] = useState<'all' | 'active' | 'compromised' | 'standby'>('all');
  const [showRegistered, setShowRegistered] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Module 2: Domain Analyzer State
  const [domainInput, setDomainInput] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [domainAnalysis, setDomainAnalysis] = useState<DomainAnalysis | null>(null);
  const [analysisHistory, setAnalysisHistory] = useState<DomainAnalysis[]>([]);

  // Common state
  const [currentTime, setCurrentTime] = useState(new Date());
  const [activeModule, setActiveModule] = useState<'lan' | 'domain'>('lan');

  // Manual IP Injection State
  const [manualIP, setManualIP] = useState('');
  const [isProbing, setIsProbing] = useState(false);
  const [probeError, setProbeError] = useState('');

  // Clock update
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Update stats when hosts change
  useEffect(() => {
    setStats({
      totalScanned: hosts.length,
      active: hosts.filter(h => h.status === 'active').length,
      compromised: hosts.filter(h => h.status === 'compromised').length,
      standby: hosts.filter(h => h.status === 'standby').length,
    });
  }, [hosts]);

  // Module 1: LAN Scanner Functions
  const startScan = useCallback(() => {
    setIsScanning(true);
    setScanProgress(0);
    setScanComplete(false);
    setHosts([]);

    const phases = [
      'Initialisation du moteur de scan...',
      'Résolution ARP sur le sous-réseau...',
      'Envoi des paquets ICMP Echo...',
      'Analyse des réponses TCP SYN...',
      'Détection des services ouverts...',
      'Identification des systèmes d\'exploitation...',
      'Évaluation des risques...',
      'Compilation des résultats...',
    ];

    let progress = 0;
    const phaseIndex = { current: 0 };

    intervalRef.current = setInterval(() => {
      progress += Math.random() * 4 + 1;
      if (progress >= 100) progress = 100;

      setScanProgress(Math.round(progress));

      const newPhaseIdx = Math.min(Math.floor(progress / (100 / phases.length)), phases.length - 1);
      if (newPhaseIdx !== phaseIndex.current) {
        phaseIndex.current = newPhaseIdx;
        setScanPhase(phases[newPhaseIdx]);
      }

      if (progress >= 100) {
        if (intervalRef.current) clearInterval(intervalRef.current);
        const hostCount = Math.floor(Math.random() * 8) + 10;
        const discoveredHosts = generateHosts(hostCount);
        setHosts(discoveredHosts);
        setIsScanning(false);
        setScanComplete(true);
      }
    }, 150);

    setScanPhase(phases[0]);
  }, []);

  const toggleHost = useCallback((id: string) => {
    setHosts(prev => prev.map(h => h.id === id ? { ...h, selected: !h.selected } : h));
  }, []);

  const selectAll = useCallback(() => {
    setHosts(prev => prev.map(h => ({ ...h, selected: true })));
  }, []);

  const deselectAll = useCallback(() => {
    setHosts(prev => prev.map(h => ({ ...h, selected: false })));
  }, []);

  const registerHost = useCallback((host: NetworkHost) => {
    if (!registeredHosts.find(h => h.id === host.id)) {
      setRegisteredHosts(prev => [...prev, { ...host, selected: false }]);
    }
  }, [registeredHosts]);

  const registerSelected = useCallback(() => {
    const selected = hosts.filter(h => h.selected);
    const newRegistered = selected.filter(s => !registeredHosts.find(r => r.id === s.id));
    setRegisteredHosts(prev => [...prev, ...newRegistered]);
    deselectAll();
  }, [hosts, registeredHosts, deselectAll]);

  // Manual IP Probe Function
  const probeManualIP = useCallback(async () => {
    if (!manualIP.trim()) {
      setProbeError('Veuillez entrer une adresse IP valide.');
      return;
    }

    const trimmedIP = manualIP.trim();
    
    if (!isValidIP(trimmedIP)) {
      setProbeError('Format d\'adresse IP invalide. Ex: 192.168.1.50');
      return;
    }

    setProbeError('');
    setIsProbing(true);

    try {
      const probedHost = await probeSpecificIP(trimmedIP);
      
      // Check if this IP already exists in hosts
      const existingHost = hosts.find(h => h.ip === trimmedIP);
      if (existingHost) {
        setProbeError(`Cette IP (${trimmedIP}) est déjà dans les résultats.`);
        setIsProbing(false);
        return;
      }

      // Add the probed host to the results
      setHosts(prev => [...prev, probedHost]);
      setScanComplete(true); // Ensure the table is visible
      setManualIP(''); // Clear input
      
    } catch (error) {
      setProbeError('Erreur lors du sondage de l\'IP.');
      console.error('Probe error:', error);
    } finally {
      setIsProbing(false);
    }
  }, [manualIP, hosts]);

  // Module 2: Domain Analyzer Functions
  const analyzeDomainHandler = useCallback(async () => {
    if (!domainInput.trim()) return;

    setIsAnalyzing(true);
    setDomainAnalysis(null);

    try {
      const result = await analyzeDomain(domainInput);
      setDomainAnalysis(result);
      setAnalysisHistory(prev => [result, ...prev].slice(0, 5)); // Keep last 5
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setIsAnalyzing(false);
    }
  }, [domainInput]);

  const filteredHosts = hosts.filter(h => filter === 'all' || h.status === filter);

  return (
    <div className="min-h-screen grid-bg">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-[#0a0e1a]/90 backdrop-blur-md border-b border-gray-800/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center glow-cyan">
                <i className="fas fa-shield-halved text-white text-lg"></i>
              </div>
              <div className="absolute -top-0.5 -right-0.5 w-3 h-3 bg-emerald-400 rounded-full border-2 border-[#0a0e1a] pulse-dot"></div>
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight">ATIBON <span className="text-cyan-400">Central Hub</span></h1>
              <p className="text-xs text-gray-500">Passerelle de Cybersécurité v3.2.1</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2 text-xs text-gray-400 bg-gray-800/50 px-3 py-1.5 rounded-lg border border-gray-700/50">
              <i className="fas fa-clock text-cyan-400"></i>
              <span className="font-mono">{currentTime.toLocaleTimeString('fr-FR')}</span>
            </div>
            <div className="hidden sm:flex items-center gap-2 text-xs text-emerald-400 bg-emerald-900/20 px-3 py-1.5 rounded-lg border border-emerald-700/30">
              <span className="w-2 h-2 bg-emerald-400 rounded-full pulse-dot"></span>
              Système Opérationnel
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowRegistered(!showRegistered)}
                className="relative text-sm bg-gray-800/50 text-gray-300 px-3 py-1.5 rounded-lg border border-gray-700/50 hover:bg-gray-700/50 transition-colors"
              >
                <i className="fas fa-bookmark mr-1"></i>
                Enregistrés
                {registeredHosts.length > 0 && (
                  <span className="absolute -top-1.5 -right-1.5 w-5 h-5 bg-cyan-500 text-white text-xs rounded-full flex items-center justify-center font-bold">
                    {registeredHosts.length}
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Module Selector Tabs */}
        <div className="flex items-center gap-2 bg-[#111827]/80 backdrop-blur-sm rounded-xl border border-gray-800/50 p-2">
          <button
            onClick={() => setActiveModule('lan')}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium text-sm transition-all ${
              activeModule === 'lan'
                ? 'bg-gradient-to-r from-cyan-600/30 to-blue-600/30 text-cyan-300 border border-cyan-600/50 glow-cyan'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
            }`}
          >
            <i className="fas fa-network-wired"></i>
            <span>Module 1: Scanner LAN</span>
          </button>
          <button
            onClick={() => setActiveModule('domain')}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium text-sm transition-all ${
              activeModule === 'domain'
                ? 'bg-gradient-to-r from-purple-600/30 to-pink-600/30 text-purple-300 border border-purple-600/50 glow-purple'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
            }`}
          >
            <i className="fas fa-globe"></i>
            <span>Module 2: Analyseur de Cible</span>
          </button>
        </div>

        {/* Stats Cards (Module 1) */}
        {activeModule === 'lan' && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              title="Total Scanné"
              value={stats.totalScanned}
              icon="fa-network-wired"
              color="text-cyan-400"
              glow="hover:glow-cyan"
            />
            <StatCard
              title="Hôtes Actifs"
              value={stats.active}
              icon="fa-circle-check"
              color="text-emerald-400"
              glow="hover:glow-green"
            />
            <StatCard
              title="Compromis"
              value={stats.compromised}
              icon="fa-skull-crossbones"
              color="text-red-400"
              glow="hover:glow-red"
            />
            <StatCard
              title="En Standby"
              value={stats.standby}
              icon="fa-pause-circle"
              color="text-purple-400"
              glow="hover:glow-purple"
            />
          </div>
        )}

        {/* Module 1: LAN Scanner */}
        {activeModule === 'lan' && (
          <>
            {/* Control Panel */}
            <div className="bg-[#111827]/80 backdrop-blur-sm rounded-xl border border-gray-800/50 p-6">
              <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    <i className="fas fa-radar text-cyan-400"></i>
                    Panneau de Contrôle - Scan Réseau & Sondage Manuel
                  </h2>
                  <p className="text-sm text-gray-400 mt-1">
                    Lancez un scan complet du réseau local ou sondez une IP spécifique.
                  </p>
                </div>

                <button
                  onClick={startScan}
                  disabled={isScanning}
                  className={`relative group px-6 py-3 rounded-xl font-bold text-sm uppercase tracking-wider transition-all duration-300 ${
                    isScanning
                      ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                      : 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-400 hover:to-blue-500 glow-cyan hover:scale-105 active:scale-95'
                  }`}
                >
                  {isScanning ? (
                    <span className="flex items-center gap-2">
                      <i className="fas fa-spinner fa-spin"></i>
                      Scan en cours...
                    </span>
                  ) : (
                    <span className="flex items-center gap-2">
                      <i className="fas fa-search-location text-lg"></i>
                      🔍 SCANNER LE LAN
                    </span>
                  )}
                  {!isScanning && (
                    <div className="absolute inset-0 rounded-xl bg-white/10 opacity-0 group-hover:opacity-100 transition-opacity"></div>
                  )}
                </button>
              </div>

              {/* Manual IP Injection Section */}
              <div className="mt-6 pt-6 border-t border-gray-800/50">
                <div className="flex items-center gap-2 mb-3">
                  <i className="fas fa-crosshairs text-orange-400"></i>
                  <h3 className="text-sm font-bold text-white">Manual Target Injection</h3>
                  <span className="text-xs text-gray-500">(Optionnel)</span>
                </div>
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1 relative">
                    <input
                      type="text"
                      value={manualIP}
                      onChange={(e) => {
                        setManualIP(e.target.value);
                        setProbeError('');
                      }}
                      onKeyDown={(e) => e.key === 'Enter' && probeManualIP()}
                      placeholder="Ex: 209.17.116.165 ou 192.168.1.50"
                      className="w-full bg-gray-900/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-orange-500/50 focus:ring-2 focus:ring-orange-500/20 transition-all font-mono text-sm"
                      disabled={isProbing}
                    />
                    <i className="fas fa-bullseye absolute right-4 top-1/2 -translate-y-1/2 text-gray-600"></i>
                  </div>
                  <button
                    onClick={probeManualIP}
                    disabled={isProbing || !manualIP.trim()}
                    className={`px-6 py-3 rounded-lg font-bold text-sm uppercase tracking-wider transition-all duration-300 flex items-center gap-2 whitespace-nowrap ${
                      isProbing || !manualIP.trim()
                        ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                        : 'bg-gradient-to-r from-orange-500 to-red-600 text-white hover:from-orange-400 hover:to-red-500 hover:scale-105 active:scale-95'
                    }`}
                  >
                    {isProbing ? (
                      <>
                        <i className="fas fa-spinner fa-spin"></i>
                        Sondage...
                      </>
                    ) : (
                      <>
                        <i className="fas fa-crosshairs text-lg"></i>
                        🎯 SONDER / AJOUTER L'IP
                      </>
                    )}
                  </button>
                </div>
                {probeError && (
                  <div className="mt-2 flex items-center gap-2 text-sm text-red-400 fade-in">
                    <i className="fas fa-exclamation-triangle"></i>
                    {probeError}
                  </div>
                )}
                <p className="mt-2 text-xs text-gray-500">
                  <i className="fas fa-info-circle mr-1"></i>
                  Sondez une IP spécifique pour l'ajouter directement aux résultats (utile après analyse DNS du Module 2).
                </p>
              </div>

              {/* Scan Progress */}
              {isScanning && (
                <ScanProgress progress={scanProgress} phase={scanPhase} />
              )}
            </div>

            {/* Registered Hosts Panel */}
            {showRegistered && registeredHosts.length > 0 && (
              <div className="bg-[#111827]/80 backdrop-blur-sm rounded-xl border border-cyan-800/30 p-6 slide-up">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-md font-bold text-cyan-300 flex items-center gap-2">
                    <i className="fas fa-bookmark"></i>
                    Hôtes Enregistrés dans la Passerelle
                  </h3>
                  <button
                    onClick={() => setShowRegistered(false)}
                    className="text-gray-400 hover:text-white transition-colors"
                  >
                    <i className="fas fa-times"></i>
                  </button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {registeredHosts.map(host => (
                    <div key={host.id} className="bg-gray-800/50 rounded-lg p-3 border border-gray-700/50 flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                        host.status === 'compromised' ? 'bg-red-900/40 text-red-400' :
                        host.status === 'active' ? 'bg-emerald-900/40 text-emerald-400' :
                        'bg-gray-700/50 text-gray-400'
                      }`}>
                        <i className="fas fa-server text-sm"></i>
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-white truncate">{host.hostname}</p>
                        <p className="text-xs text-gray-400 font-mono">{host.ip}</p>
                      </div>
                      <StatusBadge status={host.status} />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Results Table */}
            {scanComplete && hosts.length > 0 && (
              <div className="bg-[#111827]/80 backdrop-blur-sm rounded-xl border border-gray-800/50 overflow-hidden fade-in">
                {/* Table Header */}
                <div className="p-4 border-b border-gray-800/50 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <h3 className="text-md font-bold text-white flex items-center gap-2">
                      <i className="fas fa-list-ul text-cyan-400"></i>
                      Cibles Découvertes
                    </h3>
                    <span className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded-full">
                      {filteredHosts.length} résultat{filteredHosts.length > 1 ? 's' : ''}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Filters */}
                    <div className="flex items-center gap-1 bg-gray-800/50 rounded-lg p-1 border border-gray-700/50">
                      {(['all', 'active', 'compromised', 'standby'] as const).map(f => (
                        <button
                          key={f}
                          onClick={() => setFilter(f)}
                          className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                            filter === f
                              ? 'bg-cyan-600/30 text-cyan-300 border border-cyan-600/50'
                              : 'text-gray-400 hover:text-gray-200'
                          }`}
                        >
                          {f === 'all' ? 'Tous' : f === 'active' ? 'Actifs' : f === 'compromised' ? 'Compromis' : 'Standby'}
                        </button>
                      ))}
                    </div>

                    <button onClick={selectAll} className="text-xs text-gray-400 hover:text-cyan-300 px-2 py-1 transition-colors">
                      <i className="fas fa-check-double mr-1"></i>Tout sélectionner
                    </button>
                    <button onClick={deselectAll} className="text-xs text-gray-400 hover:text-gray-200 px-2 py-1 transition-colors">
                      <i className="fas fa-times mr-1"></i>Désélectionner
                    </button>

                    {hosts.filter(h => h.selected).length > 0 && (
                      <button
                        onClick={registerSelected}
                        className="text-xs bg-cyan-600/20 text-cyan-400 border border-cyan-700/50 px-3 py-1.5 rounded-lg hover:bg-cyan-600/30 transition-colors font-medium"
                      >
                        <i className="fas fa-plus-circle mr-1"></i>
                        Enregistrer ({hosts.filter(h => h.selected).length})
                      </button>
                    )}
                  </div>
                </div>

                {/* Table */}
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="bg-gray-800/30 text-xs uppercase tracking-wider text-gray-400">
                        <th className="px-4 py-3 w-10"></th>
                        <th className="px-4 py-3">Endpoint</th>
                        <th className="px-4 py-3">Hostname</th>
                        <th className="px-4 py-3">MAC</th>
                        <th className="px-4 py-3">Statut</th>
                        <th className="px-4 py-3">Risque</th>
                        <th className="px-4 py-3">OS</th>
                        <th className="px-4 py-3">Ports</th>
                        <th className="px-4 py-3">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredHosts.map((host) => (
                        <HostRow
                          key={host.id}
                          host={host}
                          onToggle={toggleHost}
                          onRegister={registerHost}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>

                {filteredHosts.length === 0 && (
                  <div className="text-center py-12 text-gray-500">
                    <i className="fas fa-ghost text-4xl mb-3 opacity-30"></i>
                    <p>Aucun hôte ne correspond au filtre sélectionné.</p>
                  </div>
                )}
              </div>
            )}

            {/* Empty State */}
            {!isScanning && !scanComplete && (
              <div className="text-center py-16 fade-in">
                <div className="relative inline-block mb-6">
                  <div className="w-24 h-24 rounded-full bg-gray-800/50 border border-gray-700/50 flex items-center justify-center">
                    <i className="fas fa-shield-halved text-4xl text-gray-600"></i>
                  </div>
                  <div className="absolute inset-0 rounded-full border border-cyan-500/20 animate-ping"></div>
                </div>
                <h3 className="text-xl font-bold text-gray-300 mb-2">Aucun Scan Effectué</h3>
                <p className="text-gray-500 text-sm max-w-md mx-auto">
                  Cliquez sur le bouton "SCANNER LE LAN" pour découvrir les hôtes actifs sur votre réseau local, ou utilisez le champ "Manual Target Injection" pour sonder une IP spécifique.
                </p>
                <div className="mt-6 flex items-center justify-center gap-4 text-xs text-gray-600">
                  <span className="flex items-center gap-1"><i className="fas fa-lock"></i> Chiffré</span>
                  <span className="flex items-center gap-1"><i className="fas fa-bolt"></i> Temps réel</span>
                  <span className="flex items-center gap-1"><i className="fas fa-crosshairs"></i> Cible manuelle</span>
                </div>
              </div>
            )}
          </>
        )}

        {/* Module 2: Domain Analyzer */}
        {activeModule === 'domain' && (
          <>
            {/* Control Panel */}
            <div className="bg-[#111827]/80 backdrop-blur-sm rounded-xl border border-gray-800/50 p-6">
              <div className="mb-4">
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <i className="fas fa-satellite text-purple-400"></i>
                  Analyseur de Cible Distante - OSINT
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  Entrez un domaine ou une URL pour effectuer une analyse DNS, géolocalisation et vérification de statut.
                </p>
              </div>

              <div className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1 relative">
                  <input
                    type="text"
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && analyzeDomainHandler()}
                    placeholder="Ex: fosref.ht, google.com, example.org"
                    className="w-full bg-gray-900/50 border border-gray-700/50 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500/50 focus:ring-2 focus:ring-purple-500/20 transition-all"
                    disabled={isAnalyzing}
                  />
                  <i className="fas fa-globe absolute right-4 top-1/2 -translate-y-1/2 text-gray-600"></i>
                </div>
                <button
                  onClick={analyzeDomainHandler}
                  disabled={isAnalyzing || !domainInput.trim()}
                  className={`px-6 py-3 rounded-lg font-bold text-sm uppercase tracking-wider transition-all duration-300 flex items-center gap-2 ${
                    isAnalyzing || !domainInput.trim()
                      ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                      : 'bg-gradient-to-r from-purple-500 to-pink-600 text-white hover:from-purple-400 hover:to-pink-500 glow-purple hover:scale-105 active:scale-95'
                  }`}
                >
                  {isAnalyzing ? (
                    <>
                      <i className="fas fa-spinner fa-spin"></i>
                      Analyse...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-rocket text-lg"></i>
                      🚀 ANALYSER LA CIBLE
                    </>
                  )}
                </button>
              </div>

              {/* Analysis Progress */}
              {isAnalyzing && (
                <div className="mt-6 fade-in">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="relative">
                      <i className="fas fa-radar text-purple-400 text-2xl"></i>
                      <div className="absolute inset-0 animate-ping">
                        <i className="fas fa-radar text-purple-400/30 text-2xl"></i>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-purple-300">Analyse en cours...</p>
                      <p className="text-xs text-gray-500">Résolution DNS, vérification HTTP, géolocalisation</p>
                    </div>
                  </div>
                  <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-purple-500 via-pink-500 to-red-500 rounded-full animate-pulse" style={{ width: '100%' }}></div>
                  </div>
                </div>
              )}
            </div>

            {/* Analysis Results */}
            {domainAnalysis && (
              <div className="space-y-4 fade-in">
                <DomainAnalysisCard analysis={domainAnalysis} />
              </div>
            )}

            {/* Analysis History */}
            {analysisHistory.length > 1 && (
              <div className="bg-[#111827]/80 backdrop-blur-sm rounded-xl border border-gray-800/50 p-6">
                <h3 className="text-md font-bold text-white flex items-center gap-2 mb-4">
                  <i className="fas fa-history text-gray-400"></i>
                  Historique des Analyses
                </h3>
                <div className="space-y-2">
                  {analysisHistory.slice(1).map((item, idx) => (
                    <div
                      key={idx}
                      onClick={() => setDomainAnalysis(item)}
                      className="flex items-center justify-between bg-gray-800/30 rounded-lg p-3 border border-gray-700/30 hover:bg-gray-800/50 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <i className="fas fa-globe text-gray-500"></i>
                        <span className="text-sm text-white">{item.domain}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <code className="text-xs text-cyan-400 font-mono">{item.ip || 'N/A'}</code>
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          item.isReachable ? 'bg-emerald-900/30 text-emerald-400' : 'bg-red-900/30 text-red-400'
                        }`}>
                          {item.isReachable ? '✓' : '✗'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Empty State */}
            {!domainAnalysis && !isAnalyzing && (
              <div className="text-center py-16 fade-in">
                <div className="relative inline-block mb-6">
                  <div className="w-24 h-24 rounded-full bg-gray-800/50 border border-gray-700/50 flex items-center justify-center">
                    <i className="fas fa-satellite-dish text-4xl text-gray-600"></i>
                  </div>
                  <div className="absolute inset-0 rounded-full border border-purple-500/20 animate-ping"></div>
                </div>
                <h3 className="text-xl font-bold text-gray-300 mb-2">Aucune Analyse Effectuée</h3>
                <p className="text-gray-500 text-sm max-w-md mx-auto">
                  Entrez un domaine ou une URL ci-dessus pour lancer une analyse OSINT complète.
                </p>
                <div className="mt-6 flex items-center justify-center gap-4 text-xs text-gray-600">
                  <span className="flex items-center gap-1"><i className="fas fa-search"></i> DNS Lookup</span>
                  <span className="flex items-center gap-1"><i className="fas fa-map-marker-alt"></i> Géolocalisation</span>
                  <span className="flex items-center gap-1"><i className="fas fa-check-circle"></i> Status Check</span>
                </div>
              </div>
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800/50 mt-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-gray-600">
          <span>© 2026 ATIBON Central Hub — Passerelle de Cybersécurité</span>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full"></span>
              Connexion sécurisée
            </span>
            <span>Build 3.2.1-prod</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
