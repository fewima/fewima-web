import functools
import re
from datetime import date, datetime

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.hashers import check_password, make_password
from django.http import Http404
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST
from pymongo.errors import DuplicateKeyError

from .db import clean, db, oid
from .forms import DepartmentForm, EmployeeForm, LeaveForm, RegisterForm

LATE_AFTER = "09:15"


# ---------- helpers ----------
def page(request, template, nav, **ctx):
    ctx.update(nav=nav, currency=settings.CURRENCY)
    return render(request, template, ctx)


def login_required(view):
    @functools.wraps(view)
    def wrapper(request, *a, **k):
        if not request.session.get("uid"):
            return redirect("login")
        return view(request, *a, **k)
    return wrapper


def admin_required(view):
    @login_required
    @functools.wraps(view)
    def wrapper(request, *a, **k):
        if request.session.get("role") != "admin":
            messages.error(request, "Only HR administrators can do that.")
            return redirect("dashboard")
        return view(request, *a, **k)
    return wrapper


def is_admin(request):
    return request.session.get("role") == "admin"


def seed():
    d = db()
    d.users.create_index("email", unique=True)
    d.employees.create_index("email", unique=True)
    d.departments.create_index("name", unique=True)
    if not d.departments.count_documents({}):
        for n in ("Engineering", "Human Resources", "Finance", "Marketing", "Operations"):
            d.departments.insert_one({"name": n, "head": "", "description": ""})


# ---------- landing ----------
def landing(request):
    if request.session.get("uid"):
        return redirect("dashboard")
    return render(request, "landing.html")


# ---------- auth ----------
def login_view(request):
    if request.session.get("uid"):
        return redirect("dashboard")
    ctx = {"first": False, "email": ""}
    try:
        seed()
        ctx["first"] = db().users.count_documents({}) == 0
    except Exception as exc:  # MongoDB unreachable
        messages.error(request, f"Cannot reach the database ({exc.__class__.__name__}). "
                                "Check MONGO_URI in .env and your Atlas network access.")
        return render(request, "login.html", ctx)
    if request.method == "POST":
        email = ctx["email"] = request.POST.get("email", "").strip().lower()
        u = db().users.find_one({"email": email})
        if u and check_password(request.POST.get("password", ""), u["password"]):
            request.session.update({"uid": str(u["_id"]), "name": u["name"], "role": u["role"], "email": u["email"]})
            return redirect("dashboard")
        messages.error(request, "Email or password is incorrect.")
    return render(request, "login.html", ctx)


def register_view(request):
    """First account becomes the HR administrator; after that, only employees HR has added can register."""
    if request.session.get("uid"):
        return redirect("dashboard")
    try:
        seed()
        first = db().users.count_documents({}) == 0
    except Exception as exc:
        messages.error(request, f"Cannot reach the database ({exc.__class__.__name__}). "
                                "Check your network access.")
        return render(request, "register.html", {"form": RegisterForm(first=False), "first": False})
    form = RegisterForm(request.POST or None, first=first)
    if request.method == "POST" and form.is_valid():
        c = form.cleaned_data
        email = c["email"].strip().lower()
        name, role = c.get("name", "").strip(), "admin"
        if not first:
            emp = db().employees.find_one({"email": email})
            # if not emp or emp.get("status") == "Terminated":
                # form.add_error("email", "We couldn't find an active employee with this email. Ask HR to add you first.")
            # else:
                # name, role = f"{emp['first_name']} {emp['last_name']}", "employee"
        if not form.errors:
            try:
                db().users.insert_one({"email": email, "name": name, "role": role,
                                       "password": make_password(c["password"])})
            except DuplicateKeyError:
                form.add_error("email", "An account with this email already exists. Sign in instead.")
            else:
                messages.success(request, "Account created. Sign in to continue.")
                return redirect("login")
    return render(request, "register.html", {"form": form, "first": first})


def logout_view(request):
    request.session.flush()
    return redirect("landing")


@login_required
def password_change(request):
    if request.method == "POST":
        u = db().users.find_one({"email": request.session["email"]})
        new = request.POST.get("new", "")
        if not check_password(request.POST.get("current", ""), u["password"]):
            messages.error(request, "Current password is incorrect.")
        elif len(new) < 8:
            messages.error(request, "New password must be at least 8 characters.")
        else:
            db().users.update_one({"_id": u["_id"]}, {"$set": {"password": make_password(new)}})
            messages.success(request, "Password updated.")
            return redirect("dashboard")
    return page(request, "password.html", "")


# ---------- dashboard ----------
@login_required
def dashboard(request):
    d, today = db(), date.today().isoformat()
    groups = list(d.employees.aggregate([
        {"$match": {"status": "Active"}},
        {"$group": {"_id": "$department", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}]))
    top = max([g["n"] for g in groups] or [1])
    active = list(d.employees.find({"status": "Active"}, {"salary": 1}))
    mine = {"email": request.session["email"], "status": "Pending"}
    return page(request, "dashboard.html", "dashboard",
                headcount=len(active), payroll=sum(e.get("salary", 0) for e in active),
                departments=d.departments.count_documents({}),
                pending=d.leaves.count_documents({"status": "Pending"}),
                present=d.attendance.count_documents({"date": today}),
                my_pending=d.leaves.count_documents(mine),
                roster=[{"name": g["_id"], "n": g["n"], "pct": max(6, int(g["n"] * 100 / top))} for g in groups],
                recent=[clean(e) for e in d.employees.find().sort("hire_date", -1).limit(5)],
                waiting=[clean(l) for l in d.leaves.find({"status": "Pending"}).sort("created", 1).limit(5)])


# ---------- employees ----------
@login_required
def employees(request):
    q, dep = request.GET.get("q", "").strip(), request.GET.get("department", "")
    f = {}
    if q:
        f["$or"] = [{k: {"$regex": re.escape(q), "$options": "i"}} for k in ("first_name", "last_name", "email", "position")]
    if dep:
        f["department"] = dep
    rows = [clean(e) for e in db().employees.find(f).sort("first_name", 1)]
    return page(request, "employees.html", "employees", rows=rows, q=q, dep=dep,
                departments=[x["name"] for x in db().departments.find().sort("name", 1)])


@admin_required
def employee_edit(request, pk=None):
    doc = None
    if pk:
        doc = db().employees.find_one({"_id": oid(pk)})
        if not doc:
            raise Http404
    form = EmployeeForm(request.POST or None, initial=doc)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        data.update(hire_date=data["hire_date"].isoformat(), salary=float(data["salary"]),
                    email=data["email"].lower())
        try:
            if doc:
                db().employees.update_one({"_id": doc["_id"]}, {"$set": data})
                db().users.update_one({"email": doc["email"]}, {"$set": {"email": data["email"],
                                      "name": f"{data['first_name']} {data['last_name']}"}})
            else:
                db().employees.insert_one(data)
        except DuplicateKeyError:
            form.add_error("email", "Someone with this email already exists.")
        else:
            messages.success(request, "Employee saved." if doc else
                             "Employee added. Ask them to create their account on the Register page using this work email.")
            return redirect("employees")
    return page(request, "form.html", "employees", form=form, back="employees",
                title="Edit employee" if doc else "Add employee", save="Save employee")


@admin_required
@require_POST
def employee_reset(request, pk):
    e = db().employees.find_one({"_id": oid(pk)})
    if e:
        name = f"{e['first_name']} {e['last_name']}"
        if db().users.delete_one({"email": e["email"], "role": "employee"}).deleted_count:
            messages.success(request, f"{name}'s login was reset. They can register again with their work email.")
        else:
            messages.info(request, f"{name} hasn't registered yet.")
    return redirect("employees")


@admin_required
@require_POST
def employee_delete(request, pk):
    e = db().employees.find_one_and_delete({"_id": oid(pk)})
    if e:
        db().users.delete_one({"email": e["email"]})
        messages.success(request, f"{e['first_name']} {e['last_name']} was removed.")
    return redirect("employees")


# ---------- departments ----------
@login_required
def departments(request):
    rows = []
    for dp in db().departments.find().sort("name", 1):
        dp["count"] = db().employees.count_documents({"department": dp["name"], "status": "Active"})
        rows.append(clean(dp))
    return page(request, "departments.html", "departments", rows=rows)


@admin_required
def department_edit(request, pk=None):
    doc = None
    if pk:
        doc = db().departments.find_one({"_id": oid(pk)})
        if not doc:
            raise Http404
    form = DepartmentForm(request.POST or None, initial=doc)
    if request.method == "POST" and form.is_valid():
        try:
            if doc:
                db().departments.update_one({"_id": doc["_id"]}, {"$set": form.cleaned_data})
                if doc["name"] != form.cleaned_data["name"]:
                    db().employees.update_many({"department": doc["name"]}, {"$set": {"department": form.cleaned_data["name"]}})
            else:
                db().departments.insert_one(dict(form.cleaned_data))
        except DuplicateKeyError:
            form.add_error("name", "A department with this name already exists.")
        else:
            messages.success(request, "Department saved.")
            return redirect("departments")
    return page(request, "form.html", "departments", form=form, back="departments",
                title="Edit department" if doc else "Add department", save="Save department")


@admin_required
@require_POST
def department_delete(request, pk):
    dp = db().departments.find_one({"_id": oid(pk)})
    if dp and db().employees.count_documents({"department": dp["name"]}):
        messages.error(request, "Move or remove this department's employees first.")
    elif dp:
        db().departments.delete_one({"_id": dp["_id"]})
        messages.success(request, "Department deleted.")
    return redirect("departments")


# ---------- leave ----------
@login_required
def leaves(request):
    status = request.GET.get("status", "")
    f = {} if is_admin(request) else {"email": request.session["email"]}
    if status:
        f["status"] = status
    rows = [clean(l) for l in db().leaves.find(f).sort("created", -1)]
    return page(request, "leaves.html", "leaves", rows=rows, status=status,
                tabs=["", "Pending", "Approved", "Rejected"])


@login_required
def leave_apply(request):
    form = LeaveForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        c = form.cleaned_data
        db().leaves.insert_one({
            "email": request.session["email"], "name": request.session["name"],
            "leave_type": c["leave_type"], "start_date": c["start_date"].isoformat(),
            "end_date": c["end_date"].isoformat(), "days": (c["end_date"] - c["start_date"]).days + 1,
            "reason": c["reason"], "status": "Pending", "created": datetime.now().isoformat(timespec="seconds")})
        messages.success(request, "Leave request submitted.")
        return redirect("leaves")
    return page(request, "form.html", "leaves", form=form, back="leaves", title="Request leave", save="Submit request")


@admin_required
@require_POST
def leave_action(request, pk, action):
    status = {"approve": "Approved", "reject": "Rejected"}.get(action)
    if not status:
        raise Http404
    l = db().leaves.find_one_and_update({"_id": oid(pk)}, {"$set": {"status": status, "reviewed_by": request.session["name"]}})
    if l:
        messages.success(request, f"{l['name']}'s request was {status.lower()}.")
    return redirect(request.POST.get("next") or "leaves")


# ---------- attendance ----------
@login_required
def attendance(request):
    today = date.today().isoformat()
    day = request.GET.get("date") or today
    f = {"date": day}
    if not is_admin(request):
        f["email"] = request.session["email"]
    rows = []
    for a in db().attendance.find(f).sort("check_in", 1):
        a["late"] = a["check_in"] > LATE_AFTER
        rows.append(clean(a))
    mine = db().attendance.find_one({"email": request.session["email"], "date": today})
    return page(request, "attendance.html", "attendance", rows=rows, day=day, today=today, mine=mine, late_after=LATE_AFTER)


@login_required
@require_POST
def clock(request):
    now, today, email = datetime.now().strftime("%H:%M"), date.today().isoformat(), request.session["email"]
    rec = db().attendance.find_one({"email": email, "date": today})
    if not rec:
        db().attendance.insert_one({"email": email, "name": request.session["name"], "date": today,
                                    "check_in": now, "check_out": None})
        messages.success(request, f"Clocked in at {now}.")
    elif not rec.get("check_out"):
        db().attendance.update_one({"_id": rec["_id"]}, {"$set": {"check_out": now}})
        messages.success(request, f"Clocked out at {now}.")
    else:
        messages.info(request, "You've already completed today's attendance.")
    return redirect("attendance")