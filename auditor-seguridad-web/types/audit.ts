export type FindingStatus = "PASS" | "FAIL";
export type FindingSeverity = "HIGH" | "MEDIUM" | "LOW";

export interface SecurityCheck {
  header: string;
  present: boolean;
  status: FindingStatus;
  value: string | null;
  severity: FindingSeverity;
  description: string;
  recommendation: string;
}

export interface AuditApiResponse {
  target: string;
  score: number;
  isHttps: boolean;
  checks: SecurityCheck[];
  timestamp: string;
}

export interface ErrorResponse {
  error: string;
}
