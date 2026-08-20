from datetime import datetime

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
    current_app,
)

from ..models import AppSetting

main_bp = Blueprint("main", __name__)


@main_bp.route("/api/public/status")
def public_status():
    maintenance = (
        AppSetting.get("maintenance_mode", "false").lower() == "true"
    )
    return jsonify(
        status={
            "portal_name": AppSetting.get(
                "portal_name", current_app.config["PORTAL_NAME"]
            ),
            "online": not maintenance,
            "maintenance_mode": maintenance,
            "server_time": datetime.now().isoformat(),
        }
    )


@main_bp.route("/")
def index():
    return render_template(
        "landing.html",
        portal_name=current_app.config["PORTAL_NAME"],
        allow_registration=current_app.config["ALLOW_REGISTRATION"],
        error=request.args.get("error", ""),
        verified=request.args.get("verified", ""),
        action=request.args.get("action", ""),
    )


@main_bp.route("/login")
def login():
    args = {}
    for key in ("error", "verified"):
        val = request.args.get(key, "")
        if val:
            args[key] = val
    return redirect(url_for("main.index", **args))


@main_bp.route("/register")
def register():
    args = {}
    error = request.args.get("error", "")
    if error:
        args["error"] = error
    if current_app.config["ALLOW_REGISTRATION"]:
        args["action"] = "register"
    return redirect(url_for("main.index", **args))


@main_bp.route("/dashboard")
def dashboard():
    return render_template(
        "dashboard.html", portal_name=current_app.config["PORTAL_NAME"]
    )


@main_bp.route("/community")
@main_bp.route("/community/dms")
def community():
    return render_template(
        "community.html", portal_name=current_app.config["PORTAL_NAME"]
    )
