export type UserRole = "analyst" | "lead" | "administrator";

export interface CurrentUser {
  id: string;
  name: string;
  initials: string;
  role: UserRole;
  organization: string;
}

/** Severity always carries an icon + label + numeric score + color — never color alone. */
export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type TrustState = "trusted" | "observed" | "untrusted" | "unknown";

export type ReputationState =
  | "known_malicious"
  | "known_benign"
  | "unknown"
  | "unavailable";

export type CampaignState = "emerging" | "active" | "expanding" | "monitoring";

export type RiskTrend = "increasing" | "stable" | "decreasing";

export type CaseStatus = "open" | "in_review" | "closed";

export type CaseDecision =
  | "confirmed_phishing"
  | "false_positive"
  | "needs_investigation"
  | "undecided";
