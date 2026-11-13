"""GET/POST /v1/register/confirm: address confirmation for free API keys (TLREG)."""

import logging

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .. import registration
from ..email_notify import send_welcome_email

logger = logging.getLogger("trust_layer.routers.registration")

router = APIRouter()

# The page reads the token from the URL fragment (never sent to the server, so never in
# an access log) and POSTs it on a click: a mail scanner that prefetches the link
# only fetches this page and consumes nothing.
_CONFIRM_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Confirm your email - ArkForge</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0f;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#14141f;border:1px solid #2a2a3a;border-radius:12px;padding:2.5rem;max-width:420px;width:90%}
h1{font-size:1.4rem;margin-bottom:.5rem;color:#fff}
p{font-size:.9rem;color:#a0a0b0;margin-bottom:1.5rem;line-height:1.5}
button{width:100%;padding:.75rem;border:none;border-radius:8px;background:#4f8cff;color:#fff;font-size:1rem;font-weight:600;cursor:pointer}
button:disabled{background:#333;cursor:wait}
#msg{margin-top:1rem;font-size:.9rem}
</style>
</head>
<body>
<div class="card">
<h1>Confirm your email</h1>
<p>Press the button to confirm this address. Your free API key is then sent to it by email.</p>
<button id="go" type="button">Confirm my email</button>
<div id="msg"></div>
</div>
<script>
var m=/(?:^#|&)token=([A-Za-z0-9_-]+)/.exec(window.location.hash);
var token=m?m[1]:"";
if(token){history.replaceState(null,"",window.location.pathname);}
var btn=document.getElementById("go"),msg=document.getElementById("msg");
if(!token){btn.disabled=true;msg.textContent="This link is incomplete. Open the link from the email again.";}
btn.addEventListener("click",function(){
btn.disabled=true;
fetch("/v1/register/confirm",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:token})})
.then(function(r){
if(r.ok){msg.textContent="Confirmed. Your API key is on its way to your mailbox.";}
else if(r.status===400){msg.textContent="This link is invalid, already used, or expired. Request a new one.";}
else{msg.textContent="Confirmation is unavailable right now. Try again later.";btn.disabled=false;}
}).catch(function(){msg.textContent="Network error. Try again.";btn.disabled=false;});
});
</script>
</body>
</html>"""

_PAGE_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


def _error(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "status": status}},
        headers={"Cache-Control": "no-store"},
    )


@router.get("/v1/register/confirm")
async def confirm_page():
    """Static page: touches no state, whatever the query string carries."""
    return HTMLResponse(content=_CONFIRM_PAGE, headers=_PAGE_HEADERS)


@router.post("/v1/register/confirm")
async def confirm(request: Request, background: BackgroundTasks):
    from .. import app as app_mod  # lazy: app.py imports this router

    try:
        body = await request.json()
    except Exception:
        return _error("invalid_token", "This confirmation link is invalid or has expired.", 400)
    token = body.get("token") if isinstance(body, dict) else None
    ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")
    try:
        result = registration.confirm_registration(token, ip)
    except registration.RegistrationError as e:
        return _error(e.code, e.message, e.status)

    background.add_task(send_welcome_email, result["email"], result["key"])
    if result["created"]:
        meta = result["meta"]
        registration.log_funnel("register_completion", ip, result["email"], meta)
        registration.log_funnel("signup_attributed", ip, result["email"], meta, conversion=True)
        if ip not in app_mod._INTERNAL_IPS:
            app_mod.usage_metrics.record_free_signup()
    return JSONResponse(content={"status": "confirmed"}, headers={"Cache-Control": "no-store"})
