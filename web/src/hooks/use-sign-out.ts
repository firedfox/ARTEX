"use client";

import { useRef, useState } from "react";

import { toast } from "sonner";

import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export function useSignOut() {
  const busy = useRef(false);
  const [signingOut, setSigningOut] = useState(false);

  function signOut() {
    if (busy.current) return;
    busy.current = true;
    setSigningOut(true);
    void api
      .logout()
      .then(() => {
        auth.clearToken();
        // Start a fresh request so both the static UI and Next's cookie gate see the cleared session.
        window.location.replace("/login");
      })
      .catch(() => {
        toast.error("Sign-out was not confirmed", {
          description:
            "Your sign-in details are still saved in this browser. Check your connection and retry to revoke the server session.",
          action: { label: "Retry", onClick: signOut },
          duration: 10_000,
        });
      })
      .finally(() => {
        busy.current = false;
        setSigningOut(false);
      });
  }

  return { signOut, signingOut };
}
