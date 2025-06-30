# 💰 Stashd - Personal Expense and Savings Tracker

Stashd is a web application that helps you master your money, achieve your savings goals, and most importantly help keep your pockets "Stashd!" Track income and expenses, set financial goals, and visualize progress - all in a simple, dark-themed interface.

---

## 🚀 Features

✅ User registrationa and authentication (login, logout, register)
✅ Profile management with password change
✅ Add, edit, delete transactions
✅ Assign labels (tags) to transactions
✅ Filter transactions by date, type and description
✅ View recent transactions in a sortable table
✅ Export transactions to CSV
✅ Set personal saving goals
✅ Responseive dark-themed UI with Bootstrap 5
✅ Flash messages via Bootstrap Toasts for success/error feedback
✅ Uses Tom Select for multi-label inputs with existing label suggestions

---

## ⚙️ Technologies Used

- Python 3.x
- Flask (Jinja2 templates)
- SQlite (default) or switch to PostgreSQL
- SQLAlchemy
- Bootstrap 5
- Tom Select (tagging labels)
- Javascipt (custom scripts)
- HTML5/CSS3 (templating)

---

## 📦 Installation

1. **Clone the repository**
```bash
git clone https://github.com/madstercoder7/Stashd.git
cd Stashd
```

2. **Create a virtual environment and activate it**
```bash
python -m venv venv
venv\Scripts\activate
```

3. **Install dependencies**
```bash 
pip install -r requirements.txt
```

4. **Set up environment variables**
Create a .env file in the root directory with:
```bash
SECRET_KEY=your_secret_key_here
SUPABASE_URL=your_supabase_project_url
SUPABASE_PASSWORD=your_supabase_db_password
SUPABASE_USER=postgres
SUPABASE_DB=postgres
MAIL_SERVER=smtp.exxample.com
MAIL_PORT=587
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_app_password_here
MAIL_DEFAULT_SENDER=your_email@example.com
```

5. **Run database migrations**
```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

6. **Run the development server**
```bash
flask run
```

Please provide your valuable feedback