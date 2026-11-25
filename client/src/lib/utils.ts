import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const ATTACK_TECHNIQUE_RE = /\b(lateral\s+movement|privilege\s+escalation|initial\s+access|credential\s+(dump|stuff|harvest|theft)|brute\s+force|command\s+and\s+control|data\s+exfiltration|defense\s+evasion|phishing|spear\s+phishing|social\s+engineering|exploit[-\s]chain|ransomware|supply[\s-]chain\s+attack|man[\s-]in[\s-]the[\s-]middle|buffer\s+overflow|sql\s+injection|cross[\s-]site|remote\s+code\s+execution|denial[\s-]of[\s-]service)\b/gi;
const MITRE_CVE_RE = /\b(T\d{4}(\.\d{3})?|CVE-\d{4}-\d{4,}|ATT&CK|MITRE)\b/g;

export function sanitizeDriverText(text: string | undefined | null): string {
  if (!text) return "";
  let s = text.replace(MITRE_CVE_RE, "").replace(ATTACK_TECHNIQUE_RE, (match) => {
    const lower = match.toLowerCase().trim();
    if (lower.includes("lateral")) return "internal propagation";
    if (lower.includes("privilege") || lower.includes("escalation")) return "access elevation";
    if (lower.includes("initial access")) return "entry point exploitation";
    if (lower.includes("credential")) return "authentication weakness";
    if (lower.includes("brute")) return "automated access attempts";
    if (lower.includes("command and control")) return "adversary communication";
    if (lower.includes("exfiltration")) return "data loss pathway";
    if (lower.includes("defense evasion")) return "control bypass";
    if (lower.includes("phishing") || lower.includes("social engineering")) return "targeted deception";
    if (lower.includes("exploit") || lower.includes("chain")) return "attack progression";
    if (lower.includes("ransomware")) return "disruptive payload";
    if (lower.includes("supply") && lower.includes("chain")) return "third-party compromise path";
    if (lower.includes("injection") || lower.includes("overflow") || lower.includes("cross-site")) return "input exploitation";
    if (lower.includes("remote code")) return "remote compromise";
    if (lower.includes("denial")) return "availability disruption";
    return "structural weakness";
  });
  return s.replace(/\s{2,}/g, " ").trim();
}
