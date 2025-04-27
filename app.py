import logging
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth  # Import Authlib for OAuth
from collections import Counter
import os
import datetime
import pandas as pd
import io
import secrets  # Import for generating nonce
import openpyxl  # Import for Excel handling
import tempfile
import shutil
from functools import wraps
from flask_frozen import Freezer  # Исправлено на flask_frozen
import requests  # Import for sending Telegram messages

from models import db, User, Zayavka
from utils import generate_word_report, generate_pdf_report

# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Set logging level after app is created
app.logger.setLevel(logging.INFO)

db.init_app(app)
migrate = Migrate(app, db)

# Configure OAuth
import os
from dotenv import load_dotenv
load_dotenv()

oauth = OAuth(app)  # Инициализация OAuth

app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"


google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={
        'scope': 'openid email profile',
    }
)

freezer = Freezer(app)  # Initialize Freezer

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')  # Add your bot token to .env
TELEGRAM_ADMIN_CHAT_ID = os.getenv('TELEGRAM_ADMIN_CHAT_ID')  # Admin chat ID
TELEGRAM_EMPLOYEE_CHAT_ID_TEMPLATE = "employee_{user_id}"  # Template for employee chat IDs

def send_telegram_message(chat_id, message):
    """Send a message to a Telegram chat."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
    try:
        requests.post(url, json=payload)
    except Exception as e:
        app.logger.error(f"Failed to send Telegram message: {e}")

# Role-based access control decorator
def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') != role:
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

@app.route('/login/google')
def login_google():
    # Generate a nonce and store it in the session
    nonce = secrets.token_urlsafe(16)
    session['google_nonce'] = nonce
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    nonce = session.pop('google_nonce', None)
    if not nonce:
        return "Invalid nonce", 400

    user_info = google.parse_id_token(token, nonce=nonce)
    if user_info:
        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            username = user_info['name'].replace(" ", "_").lower()
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                username = f"{username}_{secrets.token_hex(4)}"

            user = User(
                username=username,
                email=user_info['email'],
                password=generate_password_hash('google_oauth_placeholder'),
                role="employee",  # Default role
                full_name=user_info['name']
            )
            db.session.add(user)
            db.session.commit()

        session['user_id'] = user.id
        session['role'] = user.role
        return redirect(url_for('employee') if user.role == 'employee' else url_for('admin'))
    return redirect(url_for('index'))

@app.route('/login/google/callback')
def google_callback():
    # Example logic for handling Google login
    user_info = get_google_user_info()  # Replace with your logic to fetch user info
    user = find_user_by_email(user_info['email'])  # Check if the user exists in the database

    if not user:
        # If the user doesn't exist, create a new user with incomplete profile
        user = create_user(email=user_info['email'], username=user_info['name'], role=None)

    # Check if the user's profile is incomplete
    if not user.password or not user.faculty or not user.position:
        return redirect(url_for('create_profile', user_id=user.id))

    # Log the user in and redirect to the dashboard
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/create_profile/<int:user_id>', methods=['GET', 'POST'])
def create_profile(user_id):
    user = find_user_by_id(user_id)  # Fetch the user from the database
    if request.method == 'POST':
        # Update the user's profile with the submitted data
        user.password = hash_password(request.form['password'])
        user.faculty = request.form['faculty']
        user.position = request.form['position']
        user.role = request.form['role']
        save_user(user)  # Save the updated user to the database
        return redirect(url_for('dashboard'))

    return render_template('create_profile.html', user=user)

@app.route('/select_role', methods=['GET', 'POST'])
def select_role():
    if request.method == 'POST':
        role = request.form.get('role')
        if role in ['employee', 'admin']:
            user = User.query.get(session['user_id'])
            user.role = role
            db.session.commit()
            if role == 'employee':
                return redirect(url_for('employee'))
            elif role == 'admin':
                return redirect(url_for('admin'))
        return "Invalid role selected", 400
    return render_template('select_role.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    plain_password = request.form['password']
    hashed_password = generate_password_hash(plain_password)
    role = request.form.get('role')
    full_name = request.form.get('full_name')
    faculty = request.form.get('faculty')
    position = request.form.get('position')

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return render_template('index.html', register_error="Пользователь с таким email уже существует.")

    photo = request.files.get('photo')
    photo_filename = None
    if photo and photo.filename != '':
        photo_filename = secure_filename(photo.filename)
        photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))

    user = User(
        username=username,
        email=email,
        password=hashed_password,
        role=role,
        full_name=full_name,
        faculty=faculty,
        position=position,
        photo=photo_filename
    )
    db.session.add(user)
    try:
        db.session.commit()
        session['user_id'] = user.id
        session['role'] = user.role
        return redirect(url_for('employee') if role == 'employee' else url_for('admin'))
    except Exception as e:
        app.logger.error(f"Error registering user: {e}")
        return render_template('index.html', register_error="Произошла ошибка при регистрации. Попробуйте снова.")

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['role'] = user.role
        if user.role == 'employee':
            return redirect(url_for('employee'))
        elif user.role == 'admin':
            return redirect(url_for('admin'))  # Redirect admin to the admin page
    # Render the login page with an error message
    return render_template('index.html', login_error="Неверный логин или пароль")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/employee')
@role_required('employee')
def employee():
    zayavki = Zayavka.query.filter_by(user_id=session['user_id']).order_by(Zayavka.created_at.desc()).all()
    return render_template('employee.html', zayavki=zayavki)

@app.route('/my-requests')
@role_required('employee')
def my_requests():
    zayavki = Zayavka.query.filter_by(user_id=session['user_id']).order_by(Zayavka.created_at.desc()).all()
    return render_template('my_requests.html', zayavki=zayavki)

@app.route('/send', methods=['POST'])
@role_required('employee')
def send():
    file = request.files.get('file')
    filename = None
    if file and file.filename != '':
        filename = secrets.token_hex(8) + '_' + secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    urgent = bool(request.form.get('urgent'))  # Check if the "Срочно" checkbox is selected

    z = Zayavka(
        type=request.form['type'],
        description=request.form['description'],
        user_id=session['user_id'],
        file=filename,
        urgent=urgent  # Save the urgent status
    )
    db.session.add(z)
    db.session.commit()

    # Notify admin about the new request
    user = User.query.get(session['user_id'])  # Fetch the user's full name
    admin_message = f"📥 Новая заявка:\n<b>Тип:</b> {z.type}\n<b>Описание:</b> {z.description}\n<b>Сотрудник:</b> {user.full_name}"
    send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, admin_message)

    return redirect(url_for('employee'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/history')
@role_required('admin')
def history():
    zayavki = Zayavka.query.filter_by(status='сделано').order_by(Zayavka.created_at.desc()).all()
    return render_template('history.html', zayavki=zayavki)

@app.route('/admin')
@role_required('admin')
def admin():
    type_filter = request.args.get('type', '').strip().lower()
    status_filter = request.args.get('status', '').strip().lower()
    query_filter = request.args.get('query', '').strip().lower()

    query = Zayavka.query.join(User, Zayavka.user_id == User.id)

    # Exclude "Сделано" by default
    if not status_filter or status_filter != 'сделано':
        query = query.filter(Zayavka.status != 'сделано')

    # Apply filters based on type, status, and query
    if type_filter:
        query = query.filter(Zayavka.type.ilike(f"%{type_filter}%"))
    if status_filter:
        query = query.filter(Zayavka.status.ilike(f"%{status_filter}%"))
    if query_filter:
        query = query.filter(
            (Zayavka.description.ilike(f"%{query_filter}%")) |
            (User.username.ilike(f"%{query_filter}%")) |
            (User.full_name.ilike(f"%{query_filter}%"))
        )

    zayavki = query.order_by(Zayavka.created_at.desc()).all()
    return render_template('admin.html', zayavki=zayavki)

@app.route('/admin/requests')
@role_required('admin')
def admin_requests():
    zayavki = Zayavka.query.order_by(Zayavka.created_at.desc()).all()
    return render_template('admin_requests.html', zayavki=zayavki)

@app.route('/admin/calendar')
def admin_calendar():
    zayavki = [
        {
            'type': 'Картридж Canon 737',
            'description': 'Заявка на замену картриджа',
            'created_at': datetime(2023, 10, 1),
            'status': 'сделано'
        },
        {
            'type': 'Монитор Samsung 24',
            'description': 'Заявка на замену монитора',
            'created_at': datetime(2023, 10, 5),
            'status': 'ожидает'
        }
    ]
    return render_template('admin_calendar.html', zayavki=zayavki)

@app.route('/calendar')
@role_required('admin')
def calendar():
    zayavki = Zayavka.query.order_by(Zayavka.created_at.desc()).all()
    return render_template('admin_calendar.html', zayavki=zayavki)

@app.route('/update_status', methods=['POST'])
@role_required('admin')
def update_status():
    z = Zayavka.query.get(request.form['id'])
    new_status = request.form['action'].lower()  # Normalize status to lowercase
    z.set_status(new_status)  # Use the set_status method to enforce lowercase
    db.session.commit()

    # Notify employee about the status change
    if new_status == 'сделано':
        employee_chat_id = TELEGRAM_EMPLOYEE_CHAT_ID_TEMPLATE.format(user_id=z.user_id)
        employee_message = f"✅ Ваша заявка <b>{z.type}</b> выполнена. Вы можете её забрать."
        send_telegram_message(employee_chat_id, employee_message)

    return redirect(url_for('admin'))

def save_to_excel(zayavka, filename):
    original_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as temp_file:
        temp_filepath = temp_file.name

    try:
        # Open or create the workbook
        if os.path.exists(original_filepath):
            try:
                workbook = openpyxl.load_workbook(original_filepath)
            except Exception as e:
                app.logger.error(f"Error loading Excel file: {e}")
                return "Ошибка: Файл Excel повреждён или недействителен."
        else:
            workbook = openpyxl.Workbook()
            sheet = workbook.active
            sheet.title = "Заявки"
            # Add headers
            sheet.append(["Тип заявки", "Описание", "Дата", "Статус", "Файл", "Кто оставил заявку", "Факультет"])

        # Open the active sheet
        sheet = workbook.active

        # Append the new row
        sheet.append([
            zayavka.type,
            zayavka.description,
            zayavka.created_at.strftime('%d.%m.%Y %H:%M'),
            zayavka.status,
            zayavka.file if zayavka.file else "Нет файла",
            zayavka.user.username,
            zayavka.user.faculty
        ])

        # Save the workbook to the temporary file
        workbook.save(temp_filepath)
        workbook.close()  # Ensure the workbook is closed before replacing the original file

        # Replace the original file with the temporary file
        shutil.move(temp_filepath, original_filepath)
        app.logger.info(f"Excel file updated: {original_filepath}")

    except Exception as e:
        app.logger.error(f"Error saving to Excel file {filename}: {e}")
        # Clean up the temporary file in case of an error
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise

@app.route('/generate_report', methods=['POST'])
@role_required('admin')
def generate_report():
    import calendar

    month_raw = request.form.get('month', 'all')
    query = Zayavka.query.join(User, Zayavka.user_id == User.id)
    now = datetime.datetime.now()

    # Словарь русских названий месяцев
    month_names_ru = {
        1: "Январь", 2: "Февраль", 3: "Март", 4: "Апрель",
        5: "Май", 6: "Июнь", 7: "Июль", 8: "Август",
        9: "Сентябрь", 10: "Октябрь", 11: "Ноябрь", 12: "Декабрь"
    }

    if month_raw != 'all':
        month = int(month_raw)
        start = datetime.date(now.year, month, 1)
        end_month = month % 12 + 1
        end_year = now.year + (month == 12)
        end = datetime.date(end_year, end_month, 1)
        query = query.filter(Zayavka.created_at >= start, Zayavka.created_at < end)
    else:
        month = 'all'

    # Подготовка данных
    data = [{
        'Сотрудник': z.user.username,
        'Тип': z.type,
        'Описание': z.description,
        'Статус': z.status,
        'Дата': z.created_at.strftime('%Y-%m-%d %H:%M')
    } for z in query.all()]

    df = pd.DataFrame(data)
    output = io.BytesIO()

    # Название файла
    if month == 'all':
        filename = f"Заявки_{now.year}.xlsx"
    else:
        month_name = month_names_ru.get(month, f"Месяц_{month}")
        filename = f"Заявки_{month_name}_{now.year}.xlsx"

    # Создание Excel
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Отчёт')

    output.seek(0)
    return send_file(output, download_name=filename, as_attachment=True)


@app.route('/export_requests')
@role_required('admin')
def export_requests():
    zayavki = Zayavka.query.all()
    data = [{
        'ID': z.id,
        'Тип': z.type,
        'Описание': z.description,
        'Дата': z.created_at.strftime('%Y-%m-%d %H:%M'),
        'Пользователь': z.user.full_name if z.user else 'Неизвестно',
        'Статус': z.status
    } for z in zayavki]

    df = pd.DataFrame(data)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
        df.to_excel(tmp.name, index=False)
        return send_file(tmp.name, as_attachment=True, download_name='Заявки.xlsx')

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            app.logger.warning(f"User with ID {user_id} not found.")
            return {"error": f"User with ID {user_id} not found."}, 404
        db.session.delete(user)
        db.session.commit()
        app.logger.info(f"User with ID {user_id} has been deleted.")
        return {"message": f"User with ID {user_id} has been deleted."}, 200
    except Exception as e:
        # Log the error for debugging
        app.logger.error(f"Error deleting user with ID {user_id}: {e}")
        return {"error": "An internal server error occurred."}, 500

@app.route('/users')
@role_required('admin')
def users():
    users = User.query.order_by(User.username).all()  # Fetch all users
    return render_template('admin_users.html', users=users)

@app.route('/delete_request/<int:request_id>', methods=['POST'])
@role_required('employee')
def delete_request(request_id):
    z = Zayavka.query.get(request_id)
    if z and z.user_id == session['user_id'] and z.status != 'сделано':
        db.session.delete(z)
        db.session.commit()
    return redirect(url_for('my_requests'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Update user details
        user.full_name = request.form.get('full_name')
        user.faculty = request.form.get('faculty')
        user.position = request.form.get('position')
        # Handle profile photo upload
        photo = request.files.get('photo')
        if photo and photo.filename != '':
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            user.photo = photo_filename  # Update the photo field in the database
        db.session.commit()
        return redirect(url_for('profile'))
    # Render different templates based on the user's role
    return render_template('profile_admin.html', user=user) if user.role == 'admin' else render_template('profile_employee.html', user=user)

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Update user details
        user.full_name = request.form.get('full_name')
        user.faculty = request.form.get('faculty')
        user.position = request.form.get('position')
        # Handle profile photo upload
        photo = request.files.get('photo')
        if photo and photo.filename != '':
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            user.photo = photo_filename  # Save the photo filename in the database
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('edit_profile.html', user=user)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Logic to send a password reset email or token
            reset_token = secrets.token_urlsafe(16)  # Generate a secure token
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            # Log the reset link for debugging (replace with email sending logic)
            app.logger.info(f"Password reset link for {email}: {reset_link}")
            return render_template('forgot_password.html', success_message="Инструкции по восстановлению пароля отправлены на вашу почту.")
        else:
            return render_template('forgot_password.html', error_message="Пользователь с таким email не найден.")
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if new_password != confirm_password:
            return render_template('reset_password.html', error_message="Пароли не совпадают.", token=token)
        # Logic to validate the token and reset the password
        # For simplicity, assume the token is valid and reset the password
        user = User.query.filter_by(email="example@example.com").first()  # Replace with token validation logic
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            return redirect(url_for('index'))
        return render_template('reset_password.html', error_message="Неверный или истёкший токен.", token=token)
    return render_template('reset_password.html', token=token)

@app.route('/submit_feedback/<int:request_id>', methods=['POST'])
def submit_feedback(request_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    z = Zayavka.query.get(request_id)
    if z and z.user_id == session['user_id'] and z.status in ['сделано', 'отклонено']:
        z.comment = request.form.get('comment')
        z.rating = int(request.form.get('rating'))
        z.confirmed_by_user = True
        db.session.commit()
    return redirect(url_for('my_requests'))

@app.route('/reports')
@role_required('admin')  # или убери, если пока не используешь авторизацию
def reports():
    return render_template('reports.html')

from flask import jsonify

@app.route('/api/calendar_events')
def calendar_events():
    zayavki = Zayavka.query.all()
    events = []

    for z in zayavki:
        if z.created_at:
            events.append({
                "title": f"{z.type} ({z.status})",
                "start": z.created_at.strftime('%Y-%m-%d'),
                "color": get_status_color(z.status)
            })

    return jsonify(events)


def get_status_color(status):
    status = (status or '').lower()
    return {
        'сделано': 'green',
        'отклонено': 'red',
        'ожидает': 'orange',
        'неизвестно': 'gray',
        
    }.get(status, 'lightblue')

from flask import Flask, render_template, request
from flask_babel import Babel, _

# Настройки локализации
app.config['BABEL_DEFAULT_LOCALE'] = 'ru'  # Язык по умолчанию
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'  # Путь к переводам

# Подключаем Babel к приложению
babel = Babel(app)

# Функция для определения языка пользователя
def get_locale():
    # Пытаемся взять язык из параметра URL ?lang=ru/en и т.д.
    return request.args.get('lang', 'ru')

# Регистрируем функцию выбора языка в Babel
babel.locale_selector_func = get_locale



# Запускаем приложение
if __name__ == "__main__":
    app.run(debug=True)




#if __name__ == '__main__':
  #  from flask_migrate import Migrate
   # migrate = Migrate(app, db)
    
    #with app.app_context():
    #    db.create_all()
    
    # Uncomment the following line to freeze the app
    # freezer.freeze()  # Generate static files

    # ⚠️ НЕ запускай app.run() на Render — это делает gunicorn
    # app.run(debug=True)  ← ЭТО УДАЛЯЕМ

