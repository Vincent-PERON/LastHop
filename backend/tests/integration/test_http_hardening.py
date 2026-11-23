import httpx


async def test_security_headers_on_all_responses(client: httpx.AsyncClient) -> None:
    for path in ("/healthz", "/api/v1/auth/me", "/nope"):
        h = (await client.get(path)).headers
        assert h["x-content-type-options"] == "nosniff" and h["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["strict-transport-security"].startswith("max-age=") and h["cache-control"] == "no-store"
        assert "x-request-id" in h


async def test_cors_only_allows_frontend_origin(client: httpx.AsyncClient) -> None:
    bad = await client.options(
        "/api/v1/auth/me", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"}
    )
    assert "access-control-allow-origin" not in bad.headers
    ok = await client.options(
        "/api/v1/auth/me", headers={"Origin": "https://lasthop.test", "Access-Control-Request-Method": "GET"}
    )
    assert ok.headers["access-control-allow-origin"] == "https://lasthop.test"


async def test_body_size_limit_and_generic_validation_errors(client: httpx.AsyncClient) -> None:
    r = await client.post("/api/v1/tokens", content=b"x" * 10_000, headers={"content-type": "application/json"})
    assert r.status_code == 413
    r = await client.get("/api/v1/audit", params={"limit": "SECRET-INPUT"})
    assert r.status_code in (401, 422) and "SECRET-INPUT" not in r.text


async def test_docs_not_public_and_openapi_requires_auth(client: httpx.AsyncClient, as_role) -> None:  # type: ignore[no-untyped-def]
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert (await client.get(p)).status_code == 404
    assert (await client.get("/api/v1/openapi.json")).status_code == 401
    await as_role("lasthop-viewers")
    assert (await client.get("/api/v1/openapi.json")).json()["info"]["title"] == "LastHop API"


async def test_health_endpoints(client: httpx.AsyncClient) -> None:
    assert (await client.get("/healthz")).json() == {"status": "ok"}
    assert (await client.get("/readyz")).json() == {"status": "ok"}
