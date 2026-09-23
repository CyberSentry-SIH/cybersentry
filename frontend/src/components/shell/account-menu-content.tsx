"use client";

import { useRouter } from "next/navigation";
import { LogOut, ScrollText, UserCog } from "lucide-react";

import type { CurrentUser } from "@/types";
import { useAuth } from "@/lib/auth-context";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";

export function AccountMenuContent({
  user,
  align = "end",
  side = "top",
}: {
  user: CurrentUser;
  align?: "start" | "end" | "center";
  side?: "top" | "bottom" | "left" | "right";
}) {
  const router = useRouter();
  const { logout } = useAuth();

  async function handleSignOut() {
    await logout();
    router.push("/login");
  }

  return (
    <DropdownMenuContent align={align} side={side} className="w-56">
      <DropdownMenuLabel>
        <div className="flex items-center gap-2">
          <span className="truncate">{user.name}</span>
          <Badge variant="accent" className="capitalize">
            {user.role}
          </Badge>
        </div>
        <p className="mt-0.5 truncate text-[11px] font-normal text-text-muted">
          {user.organization}
        </p>
      </DropdownMenuLabel>
      <DropdownMenuSeparator />
      <DropdownMenuItem>
        <UserCog className="h-3.5 w-3.5" />
        Profile & preferences
      </DropdownMenuItem>
      <DropdownMenuItem>
        <ScrollText className="h-3.5 w-3.5" />
        Audit activity
      </DropdownMenuItem>
      <DropdownMenuSeparator />
      <DropdownMenuItem onSelect={handleSignOut}>
        <LogOut className="h-3.5 w-3.5" />
        Sign out
      </DropdownMenuItem>
    </DropdownMenuContent>
  );
}
