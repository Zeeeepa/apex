/**
 * Types for ReportGeneratorAgent
 */

export interface Finding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  impact: string;
  evidence: string;
  endpoint: string;
  pocPath: string;
  remediation: string;
  references?: string;
  timestamp: string;
  sessionId: string;
  target: string;
  vulnerabilityClass?: string;
}

export interface ReportGeneratorInput {
  /** Session root path */
  sessionRootPath: string;

  /** Session ID */
  sessionId: string;

  /** Main target */
  target: string;

  /** Session start time */
  startTime?: string;

  /** Session end time */
  endTime?: string;

  /** Custom report title */
  reportTitle?: string;

  /** Include detailed methodology section */
  includeMethodology?: boolean;
}

export interface ReportGeneratorResult {
  success: boolean;
  reportPath?: string;
  reportContent?: string;
  findingsCount: FindingsCount;
  error?: string;
}

export interface FindingsCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}
