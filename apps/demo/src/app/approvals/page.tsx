"use client";
import { ApprovalCenter } from "@paylineage/ui";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

function Inner() {
  const id = useSearchParams().get("id");
  return <ApprovalCenter id={id} />;
}

export default function Page() {
  return (
    <Suspense>
      <Inner />
    </Suspense>
  );
}
