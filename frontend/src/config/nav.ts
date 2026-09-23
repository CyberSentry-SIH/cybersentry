import type { LucideIcon } from "lucide-react";
import {
  LayoutDashboard,
  ScanSearch,
  Mail,
  Radar,
  GitCompare,
  FolderKanban,
  FileText,
  ShieldCheck,
  Globe,
} from "lucide-react";

import type { UserRole } from "@/types";

export interface NavItem {
  label: string;
  href: string;
  icon: LucideIcon;
  /** Restrict visibility to specific roles. Omit for all roles. */
  roles?: UserRole[];
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const navGroups: NavGroup[] = [
  {
    label: "Main",
    items: [
      { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
      { label: "Analyze", href: "/analyze", icon: ScanSearch },
      { label: "Emails", href: "/emails", icon: Mail },
      { label: "Campaigns", href: "/campaigns", icon: Radar },
    ],
  },
  {
    label: "Investigation",
    items: [
      { label: "IP Locator", href: "/ip-locator", icon: Globe },
      { label: "Compare Variants", href: "/compare", icon: GitCompare },
      { label: "Cases", href: "/cases", icon: FolderKanban },
      { label: "Reports", href: "/reports", icon: FileText },
    ],
  },
  {
    label: "Administration",
    items: [
      {
        label: "Admin",
        href: "/admin",
        icon: ShieldCheck,
        roles: ["administrator"],
      },
    ],
  },
];
