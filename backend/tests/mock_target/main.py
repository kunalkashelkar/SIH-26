from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI(title="Mock Vulnerable Target")

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
        <body>
            <h1>Welcome to the Mock Target</h1>
            <a href="/login">Login Here</a>
            <a href="/about">About Us</a>
            <script>
                // Hidden API endpoint
                const apiUrl = "/api/v1/users";
            </script>
        </body>
    </html>
    """

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return """
    <html>
        <body>
            <h2>Login</h2>
            <form action="/login_submit" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="submit" value="Login" />
            </form>
            <a href="/">Back to Home</a>
        </body>
    </html>
    """

@app.post("/login_submit")
async def login_submit(request: Request):
    return {"message": "Logged in!"}

@app.get("/about", response_class=HTMLResponse)
async def about():
    return """
    <html>
        <body>
            <h2>About</h2>
            <p>This is a vulnerable application mock.</p>
            <a href="/contact?ref=about">Contact Us</a>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.get("/contact", response_class=HTMLResponse)
async def contact(ref: str = ""):
    return """
    <html>
        <body>
            <h2>Contact</h2>
            <form action="/contact_submit" method="GET">
                <input type="text" name="message" />
                <input type="submit" value="Send" />
            </form>
            <a href="/">Back</a>
        </body>
    </html>
    """

@app.get("/contact_submit")
async def contact_submit(message: str = ""):
    return {"status": "Message sent"}

@app.get("/fake-openapi.json")
async def openapi_mock():
    return {
        "openapi": "3.0.2",
        "info": {"title": "Mock API", "version": "1.0.0"},
        "paths": {
            "/api/v2/products": {
                "get": {
                    "summary": "Get products",
                    "parameters": [
                        {"name": "category_id", "in": "query", "schema": {"type": "integer"}},
                        {"name": "is_active", "in": "query", "schema": {"type": "boolean"}}
                    ]
                }
            }
        }
    }

@app.get("/api/v1/users")
async def api_users():
    return [{"id": 1, "name": "admin"}, {"id": 2, "name": "user"}]
