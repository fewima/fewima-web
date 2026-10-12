
import logging
import threading

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.urls import NoReverseMatch, reverse
from django.utils.html import escape

log = logging.getLogger("hrms.mail")


# ---------- plumbing ----------
def _company():
    return getattr(settings, "COMPANY_NAME", "HRMS")


def _url(name, fallback):
    try:
        path = reverse(name)
    except NoReverseMatch:
        path = fallback
    return f"{getattr(settings, 'SITE_URL', '').rstrip('/')}{path}"


def _full_name(person):
    return f"{person.get('first_name', '')} {person.get('last_name', '')}".strip() or person.get("name", "") or "there"


def _html(heading, greeting, paragraphs, rows, button, footer):
    details = "".join(
        f"<tr><td style='padding:6px 16px 6px 0;color:#6b7280;font-size:14px'>{escape(k)}</td>"
        f"<td style='padding:6px 0;font-size:14px;font-weight:600;color:#111827'>{escape(v)}</td></tr>"
        for k, v in rows if v)
    body = "".join(f"<p style='margin:0 0 14px;line-height:1.55'>{escape(p)}</p>" for p in paragraphs)
    cta = ""
    if button:
        label, link = button
        cta = (f"<p style='margin:22px 0'><a href='{escape(link)}' style='background:#2563eb;color:#fff;"
               f"text-decoration:none;padding:11px 22px;border-radius:6px;font-weight:600;display:inline-block'>"
               f"{escape(label)}</a></p>")
    return (
        "<!doctype html><html><body style='margin:0;background:#f3f4f6;font-family:Segoe UI,Arial,sans-serif;color:#1f2937'>"
        "<table width='100%' cellpadding='0' cellspacing='0'><tr><td align='center' style='padding:28px 12px'>"
        "<table width='560' cellpadding='0' cellspacing='0' style='max-width:560px;background:#fff;border-radius:8px;overflow:hidden'>"
        f"<tr><td style='background:#1e3a8a;color:#fff;padding:18px 28px;font-size:18px;font-weight:600'>{escape(_company())}</td></tr>"
        "<tr><td style='padding:28px'>"
        f"<h1 style='margin:0 0 16px;font-size:20px;color:#111827'>{escape(heading)}</h1>"
        f"<p style='margin:0 0 14px'>{escape(greeting)}</p>{body}"
        + (f"<table cellpadding='0' cellspacing='0' style='margin:6px 0 4px'>{details}</table>" if details else "")
        + cta
        + f"<p style='margin:22px 0 0;font-size:12px;color:#6b7280;line-height:1.5'>{escape(footer)}</p>"
        "</td></tr></table></td></tr></table></body></html>")


def _text(heading, greeting, paragraphs, rows, button, footer):
    lines = [heading, "", greeting, ""] + [p + "\n" for p in paragraphs]
    lines += [f"{k}: {v}" for k, v in rows if v]
    if button:
        lines += ["", f"{button[0]}: {button[1]}"]
    lines += ["", footer, f"-- {_company()}"]
    return "\n".join(lines)


def _send(to, subject, heading, name, paragraphs, rows=(), button=None,
          footer="This is an automated message. Please do not reply to this e-mail."):
    if not to:
        return
    greeting = f"Hello {name},"
    subject = " ".join(str(subject).split())                    # no newlines (header injection)
    text = _text(heading, greeting, paragraphs, rows, button, footer)
    html = _html(heading, greeting, paragraphs, rows, button, footer)

    def run():
        try:
            msg = EmailMultiAlternatives(subject, text, getattr(settings, "DEFAULT_FROM_EMAIL", None), [to])
            msg.attach_alternative(html, "text/html")
            msg.send(fail_silently=False)
            log.info("e-mail sent: %r -> %s", subject, to)
        except Exception:
            log.exception("e-mail failed: %r -> %s", subject, to)

    threading.Thread(target=run, daemon=True).start()


# ---------- messages ----------
def account_created(email, name, role):
    """To the person whose login account was just created."""
    _send(email, f"Your {_company()} account is ready", "Your account has been created", name,
          ["Your account has been created successfully and you can now sign in with this e-mail address.",
           "If you did not create this account, please contact your HR administrator immediately."],
          rows=[("Account e-mail", email), ("Role", role.title())],
          button=("Sign in", _url("https://fewima.com/login", "/login/")))


def employee_welcome(emp, manager=None):
    """To a newly added employee: tells them to register using this e-mail address."""
    rows = [("Department", emp.get("department")), ("Position", emp.get("position")),
            ("Start date", emp.get("hire_date")),
            ("Your manager", _full_name(manager) if manager else "")]
    _send(emp.get("email"), f"Welcome to {_company()}", f"Welcome to {_company()}", _full_name(emp),
          ["Your employee record has been created by HR. To access the HR portal, create your account "
           "using this e-mail address and choose your own password.",
           "For your security, nobody at the company will ever ask you for your password."],
          rows=rows, button=("Create your account", _url("https://fewima.com/register", "/register/")))


def manager_new_member(manager, emp, department):
    """To a department manager when an employee joins (or moves into) their department."""
    _send(manager.get("email"), f"New team member in {department}", "A new employee has joined your team",
          _full_name(manager),
          [f"{_full_name(emp)} has been added to the {department} department, which you manage. "
           "You can now view their attendance and review their leave requests."],
          rows=[("Employee", _full_name(emp)), ("Position", emp.get("position")),
                ("Start date", emp.get("hire_date")), ("E-mail", emp.get("email"))],
          button=("Open the portal", _url("dashboard", "/dashboard/")))


def manager_assigned(manager, department, team_size):
    """To an employee when an administrator makes them manager of a department."""
    _send(manager.get("email"), f"You are now the manager of {department}",
          "You have been assigned as a department manager", _full_name(manager),
          [f"An administrator has assigned you as the manager of the {department} department.",
           "You can now view the department's employees and attendance, and approve or reject their leave requests."],
          rows=[("Department", department), ("Active team members", str(team_size))],
          button=("Open the portal", _url("dashboard", "/dashboard/")))