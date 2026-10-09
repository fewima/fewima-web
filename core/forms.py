from django import forms
from .db import db

DATE = lambda: forms.DateInput(attrs={"type": "date"})


class DepartmentForm(forms.Form):
    name = forms.CharField(max_length=80)
    head = forms.CharField(max_length=80, required=False, label="Department head")
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["department"].choices = [(d["name"], d["name"]) for d in db().departments.find().sort("name")]


class LeaveForm(forms.Form):
    leave_type = forms.ChoiceField(choices=[(t, t) for t in ("Annual", "Sick", "Maternity/Paternity", "Unpaid", "Other")])
    start_date = forms.DateField(widget=DATE())
    end_date = forms.DateField(widget=DATE())
    reason = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), required=False)

    def clean(self):
        data = super().clean()
        s, e = data.get("start_date"), data.get("end_date")
        if s and e and e < s:
            self.add_error("end_date", "End date must be on or after the start date.")
        return data
