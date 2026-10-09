from django.urls import path
from . import views as v

urlpatterns = [
    path("", v.landing, name="landing"),
    path("dashboard/", v.dashboard, name="dashboard"),
    path("login/", v.login_view, name="login"),
    path("logout/", v.logout_view, name="logout"),
    path("password/", v.password_change, name="password"),
    path("employees/", v.employees, name="employees"),
    path("employees/new/", v.employee_edit, name="employee_add"),
    path("employees/<str:pk>/edit/", v.employee_edit, name="employee_edit"),
    path("employees/<str:pk>/delete/", v.employee_delete, name="employee_delete"),
    path("departments/", v.departments, name="departments"),
    path("departments/new/", v.department_edit, name="department_add"),
    path("departments/<str:pk>/edit/", v.department_edit, name="department_edit"),
    path("departments/<str:pk>/delete/", v.department_delete, name="department_delete"),
    path("leave/", v.leaves, name="leaves"),
    path("leave/new/", v.leave_apply, name="leave_apply"),
    path("leave/<str:pk>/<str:action>/", v.leave_action, name="leave_action"),
    path("attendance/", v.attendance, name="attendance"),
    path("attendance/clock/", v.clock, name="clock"),
]
