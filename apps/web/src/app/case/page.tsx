"use client";
import { EvidenceInvestigation } from "@paylineage/ui";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

function Inner() {
  const id = useSearchParams().get("id");
  return <EvidenceInvestigation id={id} />;
}

export default function Page() {
  return (
    <Suspense>
      <Inner />
    </Suspense>
  );
}
