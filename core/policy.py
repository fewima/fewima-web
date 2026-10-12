EXEMPTION_LIMIT = 5              # missed-clock exemptions per employee per month
EXEMPTION_WINDOW_DAYS = 14       # how far back an exemption can be requested
LEAVE_TYPES = {                  # name -> days per year (None = no cap). Adjust to your policy.
    "Annual": 20, "Sick": 10, "Casual": 5, "Maternity": 90,
    "Paternity": 10, "Compassionate": 5, "Study": 10, "Unpaid": None,
}
PENSION_RATE = 0.08
TAX_RATE = 0.0                   # placeholder: replace tax math in build_payslip() with your PAYE bands
WORKING_DAYS_PER_MONTH = 22