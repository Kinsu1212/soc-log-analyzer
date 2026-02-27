"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { getToken } from "@/lib/api";
import { me, logout } from "@/lib/auth";

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    async function go() {
      const token = getToken();
      if (!token) {
        router.replace("/login");
        return;
      }

      try {
        await me(); // validate token
        router.replace("/upload");
      } catch {
        logout(); // clear invalid token
        router.replace("/login");
      }
    }

    go();
  }, [router]);

  return (
    <div className="min-h-screen flex items-center justify-center text-sm text-gray-600">
      Redirecting...
    </div>
  );
}