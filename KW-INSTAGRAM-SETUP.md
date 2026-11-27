# KW Instagram integration
Account: @ppskerthawisesa. This is read-only and separate from membership and finance.

Cloudflare Pages project kertha-wisesa: set encrypted production secret KW_INSTAGRAM_TOKEN to an Instagram Login access token for the professional account with instagram_business_basic permission. Do not commit tokens. Optional KW_INSTAGRAM_API_VERSION overrides v27.0 if needed. Redeploy after setting secrets. Use a long-lived token; renew before expiry using Meta's supported refresh flow. Automatic token renewal is not implemented.

GET /api/instagram validates the account and retrieves up to 12 posts. Successful responses use on-demand 15-minute edge cache; it is not a scheduled background job. The gallery refreshes while open. Carousel and videos show previews linking to original Instagram content. Without authorization, the gallery shows a profile link, not fabricated posts. Test /api/instagram returns status connected and correct username after setup.
