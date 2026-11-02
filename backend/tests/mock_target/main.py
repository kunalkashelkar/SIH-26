from fastapi import FastAPI, Request, Header, HTTPException, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Optional, List
import json

app = FastAPI(title="Controlled Ground-Truth Target Application")

# ==============================================================================
# 1. Static HTML Pages & Links
# ==============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html>
        <head><title>CYPHER Benchmark Target - Home</title></head>
        <body>
            <h1>Ground Truth Target Application</h1>
            <nav>
                <a href="/about">About Us</a>
                <a href="/pricing">Pricing</a>
                <a href="/docs">Documentation</a>
                <a href="/login">User Login</a>
                <a href="/register">Create Account</a>
                <a href="/contact">Contact Support</a>
                <a href="/feedback">Feedback</a>
                <a href="/faq">FAQ</a>
                <a href="/terms">Terms</a>
                <a href="/privacy">Privacy</a>
                <a href="/dashboard_preview">Dashboard Preview</a>
                <a href="/spa">React SPA</a>
                <a href="/app-router">Next.js App Router</a>
                <a href="/vue-spa">Vue SPA</a>
                <a href="/angular-spa">Angular SPA</a>
            </nav>
            <script>
                // Embedded API clients
                const usersApi = "/api/v1/users";
                const metricsApi = "/api/v1/analytics/metrics";
            </script>
        </body>
    </html>
    """

@app.get("/about", response_class=HTMLResponse)
async def about():
    return """
    <html>
        <head><title>About CYPHER Benchmark</title></head>
        <body>
            <h2>About</h2>
            <p>Controlled testbed for measuring discovery recall and precision.</p>
            <a href="/contact?ref=about">Contact Support</a>
            <a href="/">Back to Home</a>
        </body>
    </html>
    """

@app.get("/pricing", response_class=HTMLResponse)
async def pricing():
    return """
    <html>
        <head><title>Pricing Plans</title></head>
        <body>
            <h2>Pricing Plans</h2>
            <p>Community and Enterprise tiers.</p>
            <a href="/register">Sign Up</a>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.get("/docs", response_class=HTMLResponse)
async def documentation():
    return """
    <html>
        <head><title>API Documentation</title></head>
        <body>
            <h2>Developer Docs</h2>
            <p>Access our <a href="/fake-openapi.json">OpenAPI Specification</a>.</p>
            <a href="/">Back</a>
        </body>
    </html>
    """

# ==============================================================================
# 2. Forms & Dynamic Submissions
# ==============================================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return """
    <html>
        <head><title>Login</title></head>
        <body>
            <h2>Sign In</h2>
            <form action="/login_submit" method="POST">
                <input type="text" name="username" placeholder="Username" required />
                <input type="password" name="password" placeholder="Password" required />
                <input type="submit" value="Sign In" />
            </form>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.post("/login_submit")
async def login_submit(request: Request):
    return {"status": "authenticated", "token": "session_tok_abc123"}

@app.get("/register", response_class=HTMLResponse)
async def register_page():
    return """
    <html>
        <head><title>Register</title></head>
        <body>
            <h2>New Account</h2>
            <form action="/register_submit" method="POST">
                <input type="text" name="username" required />
                <input type="email" name="email" required />
                <input type="password" name="password" required />
                <input type="submit" value="Create Account" />
            </form>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.post("/register_submit")
async def register_submit(request: Request):
    return {"status": "created", "user_id": 99}

@app.get("/contact", response_class=HTMLResponse)
async def contact(ref: str = ""):
    return """
    <html>
        <head><title>Contact Us</title></head>
        <body>
            <h2>Feedback</h2>
            <form action="/contact_submit" method="GET">
                <input type="text" name="message" placeholder="Message" required />
                <input type="submit" value="Send" />
            </form>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.get("/contact_submit", response_class=HTMLResponse)
async def contact_submit(message: str = ""):
    return f"""
    <html>
        <body>
            <h2>Message Received</h2>
            <div id="output">{message}</div>
        </body>
    </html>
    """

@app.get("/faq", response_class=HTMLResponse)
async def faq(category: str = "general"):
    return f"""
    <html>
        <head><title>FAQ - {category}</title></head>
        <body>
            <h2>Frequently Asked Questions</h2>
            <p>Category: {category}</p>
            <a href="/terms">Terms of Service</a>
            <a href="/privacy">Privacy Policy</a>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.get("/terms", response_class=HTMLResponse)
async def terms():
    return """
    <html>
        <head><title>Terms of Service</title></head>
        <body>
            <h2>Terms</h2>
            <p>Usage agreement and authorized testing scope.</p>
            <a href="/privacy">Privacy Policy</a>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.get("/privacy", response_class=HTMLResponse)
async def privacy():
    return """
    <html>
        <head><title>Privacy Policy</title></head>
        <body>
            <h2>Privacy</h2>
            <p>Information handling policies.</p>
            <a href="/faq">FAQ</a>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.get("/feedback", response_class=HTMLResponse)
async def feedback():
    return """
    <html>
        <head><title>User Feedback</title></head>
        <body>
            <h2>Feedback Form</h2>
            <form action="/feedback_submit" method="POST">
                <input type="number" name="rating" min="1" max="5" value="5" />
                <textarea name="comments"></textarea>
                <input type="submit" value="Submit Feedback" />
            </form>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.post("/feedback_submit")
async def feedback_submit(request: Request):
    return {"status": "success", "message": "Feedback recorded"}

@app.get("/dashboard_preview", response_class=HTMLResponse)
async def dashboard_preview(page: int = 1, limit: int = 10):
    return f"""
    <html>
        <head><title>Dashboard Preview</title></head>
        <body>
            <h2>Live Metrics Preview (Page {page})</h2>
            <a href="/dashboard_preview?page={page+1}&limit={limit}">Next Page</a>
            <a href="/">Home</a>
        </body>
    </html>
    """

# ==============================================================================
# 3. SPAs & Frontend Routers (React, Next.js, Vue, Angular)
# ==============================================================================

@app.get("/spa", response_class=HTMLResponse)
async def react_spa():
    return """<!DOCTYPE html>
    <html>
        <head>
            <title>React SPA App</title>
            <script src="/static/react_bundle.js"></script>
        </head>
        <body>
            <div id="root" data-reactroot=""></div>
            <button role="tab" onclick="document.getElementById('root').innerHTML='<p>Dashboard</p>'">Overview</button>
        </body>
    </html>"""

@app.get("/static/react_bundle.js")
async def react_bundle():
    js = """
    // React Router configuration
    const routes = [
        { path: "/dashboard", component: Dashboard },
        { path: "/settings/profile", component: Profile },
        { path: "/users/:userId", component: UserDetail }
    ];
    // Candidate APIs
    const API_ENDPOINT = "/api/v1/analytics/metrics";
    const AUTH_URL = "/api/v1/auth/refresh";
    """
    return HTMLResponse(content=js, media_type="application/javascript")

@app.get("/app-router", response_class=HTMLResponse)
async def nextjs_app_router():
    return """<!DOCTYPE html>
    <html>
        <head>
            <title>Next.js App Router</title>
            <script src="/static/nextjs_bundle.js"></script>
        </head>
        <body>
            <div id="__next">Next.js App</div>
        </body>
    </html>"""

@app.get("/static/nextjs_bundle.js")
async def nextjs_bundle():
    js = """
    // Next.js App Router flight manifests
    const appRouterManifest = {
        "/app/dashboard/page": ["/dashboard"],
        "/app/billing/invoices/page": ["/billing/invoices"]
    };
    fetch("/api/next/orders", { method: "POST", body: JSON.stringify({ item_id: 101 }) });
    """
    return HTMLResponse(content=js, media_type="application/javascript")

@app.get("/vue-spa", response_class=HTMLResponse)
async def vue_spa():
    return """<!DOCTYPE html>
    <html>
        <head>
            <title>Vue SPA</title>
            <script src="/static/vue_bundle.js"></script>
        </head>
        <body><div id="app">Vue App</div></body>
    </html>"""

@app.get("/static/vue_bundle.js")
async def vue_bundle():
    js = """
    const router = new VueRouter({
        routes: [
            { path: '/catalog', component: Catalog },
            { path: '/cart', component: Cart }
        ]
    });
    axios.get('/api/vue/products');
    """
    return HTMLResponse(content=js, media_type="application/javascript")

@app.get("/angular-spa", response_class=HTMLResponse)
async def angular_spa():
    return """<!DOCTYPE html>
    <html>
        <head>
            <title>Angular SPA</title>
            <script src="/static/angular_bundle.js"></script>
        </head>
        <body><app-root></app-root></body>
    </html>"""

@app.get("/static/angular_bundle.js")
async def angular_bundle():
    js = """
    const appRoutes = [
        { path: 'analytics', component: AnalyticsComponent },
        { path: 'reports', component: ReportsComponent }
    ];
    http.get('/api/angular/data');
    """
    return HTMLResponse(content=js, media_type="application/javascript")

# ==============================================================================
# 4. Backend REST APIs (FastAPI, Flask, Django, Express, NestJS)
# ==============================================================================

@app.get("/api/v1/users")
async def get_users():
    return [{"id": 1, "username": "admin"}, {"id": 2, "username": "analyst"}]

@app.get("/api/v1/users/{user_id}")
async def get_user_detail(user_id: int):
    return {"id": user_id, "username": f"user_{user_id}", "role": "member"}

@app.post("/api/v1/orders")
async def create_order(request: Request):
    return {"order_id": 5001, "status": "pending"}

@app.get("/api/flask/items")
async def flask_items(tag: Optional[str] = None):
    return [{"item_id": "fl_1", "tag": tag or "general"}]

@app.get("/api/flask/items/{item_id}")
async def flask_item_detail(item_id: str):
    return {"item_id": item_id, "name": "Flask Item"}

@app.get("/api/django/products/")
async def django_products(category: Optional[str] = None):
    return [{"product_id": 10, "category": category or "all"}]

@app.post("/api/express/checkout")
async def express_checkout(request: Request):
    return {"status": "paid", "amount": 199.99}

@app.get("/api/nest/billing/invoices")
async def nest_invoices(account_id: Optional[str] = None):
    return [{"invoice_id": "inv_01", "account_id": account_id or "default"}]

# ==============================================================================
# 5. GraphQL & WebSockets
# ==============================================================================

@app.post("/graphql")
async def graphql_endpoint(request: Request):
    body = await request.json()
    query = body.get("query", "")
    if "GetUserProfile" in query:
        return {"data": {"user": {"id": 1, "name": "Admin", "email": "admin@cypher.local"}}}
    return {"data": {"status": "ok"}}

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text(json.dumps({"type": "PING", "status": "ALIVE"}))
    await websocket.close()

# ==============================================================================
# 6. Authentication, RBAC, Pagination & Infinite Scroll
# ==============================================================================

@app.get("/api/v1/admin/audit")
async def admin_audit(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized - Admin Bearer Token Required")
    if "admin_super_secret" not in authorization:
        raise HTTPException(status_code=403, detail="Forbidden - Insufficient Permissions")
    return {"audit_logs": [{"event": "POLICY_UPDATE", "user": "root"}]}

@app.get("/api/v1/feed")
async def feed(page: int = 1, limit: int = 10, cursor: Optional[str] = None):
    return {
        "page": page,
        "limit": limit,
        "cursor": cursor,
        "items": [f"Post #{i}" for i in range((page - 1) * limit + 1, page * limit + 1)],
        "next_cursor": f"cursor_p{page + 1}"
    }

# ==============================================================================
# 7. Sitemaps, Robots, and OpenAPI Specification
# ==============================================================================

@app.get("/robots.txt", response_class=HTMLResponse)
async def robots_txt(request: Request):
    base = str(request.base_url).rstrip("/")
    return f"User-agent: *\nDisallow: /admin\nSitemap: {base}/sitemap.xml\n"

@app.get("/sitemap.xml", response_class=HTMLResponse)
async def sitemap_xml(request: Request):
    base = str(request.base_url).rstrip("/")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>{base}/</loc></url>
    <url><loc>{base}/about</loc></url>
    <url><loc>{base}/pricing</loc></url>
    <url><loc>{base}/docs</loc></url>
    <url><loc>{base}/login</loc></url>
    <url><loc>{base}/register</loc></url>
    <url><loc>{base}/contact</loc></url>
    <url><loc>{base}/feedback</loc></url>
    <url><loc>{base}/faq</loc></url>
    <url><loc>{base}/terms</loc></url>
    <url><loc>{base}/privacy</loc></url>
    <url><loc>{base}/dashboard_preview</loc></url>
    <url><loc>{base}/spa</loc></url>
    <url><loc>{base}/app-router</loc></url>
    <url><loc>{base}/vue-spa</loc></url>
    <url><loc>{base}/angular-spa</loc></url>
</urlset>"""

@app.get("/fake-openapi.json")
async def openapi_mock():
    return {
        "openapi": "3.0.2",
        "info": {"title": "Controlled Benchmark API", "version": "1.0.0"},
        "paths": {
            "/api/v2/products": {
                "get": {
                    "summary": "Get products catalog",
                    "parameters": [
                        {"name": "category_id", "in": "query", "schema": {"type": "integer"}},
                        {"name": "is_active", "in": "query", "schema": {"type": "boolean"}}
                    ]
                }
            },
            "/api/v2/orders/{order_id}": {
                "get": {
                    "summary": "Get order by ID",
                    "parameters": [
                        {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ]
                }
            }
        }
    }
