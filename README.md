# Rollcall HR (Django + MongoDB)

## Run (Windows)
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    copy .env.example .env      # then edit .env and set MONGO_URI
    python manage.py runserver
Open http://127.0.0.1:8000. First sign-in: **admin@hrms.local / admin123** (created automatically; change it under "Change password").

## Notes
- `/` is the public landing page; the app lives at `/dashboard/`.
- Admins manage employees, departments, leave and see payroll. Employees get a login when added (password `ChangeMe123`).
- Data collections: users, employees, departments, leaves, attendance. No migrations needed.
