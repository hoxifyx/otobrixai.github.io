-- [REDACTED] Tier-2 Hardening Blueprints for DemoCompany v7.2.0
-- Patterns designed for immediate deployment to block BOLA and cross-tenant leakage.

-- 1. API Key Owner Isolation
-- Prevents any authenticated user from enumerating or using another user's API keys.
ALTER TABLE public.user_api_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY "api_keys_owner_only"
ON public.user_api_keys FOR ALL
TO authenticated
USING ("userId" = auth.uid())
WITH CHECK ("userId" = auth.uid());

-- 2. Credential Vault Isolation (Cross-Project Enforcement)
-- Ensures that credentials can only be accessed by members of the owning project.
ALTER TABLE public.credentials_entity ENABLE ROW LEVEL SECURITY;

CREATE POLICY "credentials_owner_only"
ON public.credentials_entity FOR ALL
TO authenticated
USING (
    "projectId" IN (
        SELECT id FROM public.project
        WHERE "ownedById" = auth.uid()
        OR id IN (
            SELECT "projectId" FROM public.shared_workflow
            WHERE "userId" = auth.uid()
        )
    )
)
WITH CHECK (
    "projectId" IN (
        SELECT id FROM public.project
        WHERE "ownedById" = auth.uid()
    )
);

-- 3. Verification Protocol
-- After applying these policies, perform the following validation:
--   a. Attempt to select from these tables as a Trial user. 
--   b. Expected Result: Zero rows returned for non-owned entities.
--   c. Proceed to rotate any keys exposed prior to March 24, 2026.