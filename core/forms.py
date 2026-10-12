from django import forms

from .db import db
from .policy import LEAVE_TYPES

DATE = lambda: forms.DateInput(attrs={"type": "date"})
TIME = lambda: forms.TimeInput(attrs={"type": "time"})

ROLE_CHOICES = [("EMPLOYEE", "Employee"), ("SUPERVISOR", "Supervisor"), ("MANAGER", "Manager"),
                ("ACCOUNTANT", "Accountant"), ("ADMINISTRATOR", "Administrator")]


class DepartmentForm(forms.Form):
    name = forms.CharField(max_length=80)
    manager_email = forms.ChoiceField(required=False, label="Department manager")  # choices set in the view
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), required=False)


class EmployeeForm(forms.Form):
    first_name = forms.CharField(max_length=60)
    last_name = forms.CharField(max_length=60)
    email = forms.EmailField(label="Work email")
    phone = forms.CharField(max_length=30, required=False)
    department = forms.ChoiceField()
    position = forms.CharField(max_length=80, label="Job title")
    salary = forms.DecimalField(min_value=0, decimal_places=2, label="Monthly salary")
    hire_date = forms.DateField(widget=DATE())
    status = forms.ChoiceField(choices=[(s, s) for s in ("Active", "On Leave", "Terminated")])
    role = forms.ChoiceField(choices=ROLE_CHOICES, initial="EMPLOYEE")
    supervisor_email = forms.ChoiceField(required=False, label="Supervisor")      # choices set in the view

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["department"].choices = [(d["name"], d["name"]) for d in db().departments.find().sort("name")]


class LeaveForm(forms.Form):
    leave_type = forms.ChoiceField(choices=[(k, f"{k} leave") for k in LEAVE_TYPES])
    start_date = forms.DateField(widget=DATE())
    end_date = forms.DateField(widget=DATE())
    reason = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 3}))

    def clean(self):
        data = super().clean()
        s, e = data.get("start_date"), data.get("end_date")
        if s and e and e < s:
            self.add_error("end_date", "End date must be on or after the start date.")
        return data


class ExemptionForm(forms.Form):
    date = forms.DateField(widget=DATE())
    kind = forms.ChoiceField(label="What did you miss?", choices=[
        ("in", "Forgot to clock in"), ("out", "Forgot to clock out"), ("both", "Forgot both")])
    check_in = forms.TimeField(required=False, widget=TIME(), label="Actual arrival time")
    check_out = forms.TimeField(required=False, widget=TIME(), label="Actual departure time")
    reason = forms.CharField(max_length=500, widget=forms.Textarea(attrs={"rows": 3}))


class PTAForm(forms.Form):
    month = forms.CharField(widget=forms.TextInput(attrs={"type": "month"}))
    amount = forms.DecimalField(min_value=1, max_digits=12, decimal_places=2)
    destination = forms.CharField(max_length=120)
    purpose = forms.CharField(max_length=500, widget=forms.Textarea(attrs={"rows": 3}))


class CandidateForm(forms.Form):
    first_name = forms.CharField(max_length=60)
    last_name = forms.CharField(max_length=60)
    email = forms.EmailField()
    phone = forms.CharField(max_length=30, required=False)
    position = forms.CharField(max_length=100)
    department = forms.ChoiceField()              # choices filled in the view
    expected_salary = forms.DecimalField(min_value=0, max_digits=14, decimal_places=2)


class InterviewForm(forms.Form):
    round = forms.ChoiceField(choices=[(r, r) for r in ("Screening", "Technical", "HR", "Final")])
    date = forms.DateField(widget=DATE())
    interviewer = forms.CharField(max_length=100)
    outcome = forms.ChoiceField(choices=[("Pass", "Pass"), ("Hold", "Hold"), ("Fail", "Fail")])
    score = forms.IntegerField(required=False, min_value=0, max_value=10, label="Score (0-10)")
    notes = forms.CharField(required=False, max_length=1000, widget=forms.Textarea(attrs={"rows": 3}))


class RegisterForm(forms.Form):
    name = forms.CharField(max_length=100, label="Full name")
    email = forms.EmailField(label="Work email", widget=forms.EmailInput(attrs={"autocomplete": "email"}))
    password = forms.CharField(min_length=8, widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
                               help_text="At least 8 characters.")
    confirm = forms.CharField(label="Confirm password", widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))

    def __init__(self, *args, first=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.first = first
        if not first:  # employees get their name from the record HR created
            del self.fields["name"]

    def clean(self):
        data = super().clean()
        if data.get("password") and data.get("confirm") and data["password"] != data["confirm"]:
            self.add_error("confirm", "Passwords don't match.")
        return data