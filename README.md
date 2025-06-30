# Stashd - Personal Finance Tracker

**Stashd** is a simple, secure web application for tracking your income and expenses. It helps you understand your spendinghabits, manage your finacnes, and stay on top of your saving goals and budget.

---

## Demo
https://stashd.onrender.com/

## Features

✅ Register and log in securely
✅ Add income and expense entries
✅ Categorize transactions
✅ See a summary of your financial activity
✅ Edit or delete entries
✅ Supabase PostgreSQL integration for cloud storage
✅ Forgot and reset password functionality
✅ Responsive web interface

---

# Tech Stack

- **Backend**: Flask, SQLAlchemy, Supabase PostgreSQL
- **Frontend**: HTML, CSS, Jinja2
- **Auth**: Flask-Login, Flask-Bcrypt
- **Email**: Flask-Mail
- **Deployment**: Render 

---

## Setup Instrcutions

1. **Clone the repository**
```bash
git clone https://github.com/madstercoder7/Stashd.git
cd Stashd
```

2. **Create a virtual environment**
```bash
python -m venv venv
venv\Scripts\activate # Windows
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
SECRET_KEY=your_secret_key_here
SUPABASE_URL=your_supabase_project_url
SUPABASE_PASSWORD=your_supabase_db_password
SUPABASE_USER=postgres
SUPABASE_DB=postgres
MAIL_SERVER=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_app_password_here
MAIL_DEFAULT_SENDER=your_email@example.com
```

5. **Run databse migrations**
```bash
flask db init
flask db migrate -m "Intial migration"
flask db upgrade
```

6. **Run the development server**
```bash
flask run
```