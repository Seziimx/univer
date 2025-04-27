import logging
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from collections import Counter
import os
import datetime
import pandas as pd
import io
import secrets
import openpyxl
import tempfile
import shutil
from functools import wraps
from flask_frozen import Freezer
import requests
import pytz

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

freezer = Freezer(app)

import os
import requests
from flask import Flask, request, session, redirect, url_for
from functools import wraps
from models import db, Zayavka  # Предположим, что у вас есть модель Zayavka

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_ADMIN_CHAT_ID = os.getenv('TELEGRAM_ADMIN_CHAT_ID')
TELEGRAM_ADMIN_CHAT_ID_2 = os.getenv('TELEGRAM_ADMIN_CHAT_ID_2')
TELEGRAM_ADMIN_CHAT_ID_3 = os.getenv('TELEGRAM_ADMIN_CHAT_ID_3')

app.config['SECRET_KEY'] = 'your_secret_key'  # Настроить секретный ключ для сессий

app.logger.info(f"Loaded admin chat IDs: {TELEGRAM_ADMIN_CHAT_ID }, {TELEGRAM_ADMIN_CHAT_ID_2}, {TELEGRAM_ADMIN_CHAT_ID_3}")

def send_telegram_message(chat_id, message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
    try:
        response = requests.post(url, json=payload)
        if response.status_code != 200:
            app.logger.error(f"Failed to send Telegram message: {response.text}")
        else:
            app.logger.info(f"Telegram message sent to chat ID {chat_id}")
    except Exception as e:
        app.logger.error(f"Error sending Telegram message: {e}")

def send_to_all_admins(message):
    app.logger.info(f"Sending message to all admins: {message}")
    for admin_id in TELEGRAM_ADMIN_CHAT_ID + TELEGRAM_ADMIN_CHAT_ID_2 + TELEGRAM_ADMIN_CHAT_ID_3:
        if admin_id:
            app.logger.info(f"Sending message to admin with chat ID: {admin_id}")
            send_telegram_message(admin_id, message)
        else:
            app.logger.warning("Admin chat ID is None or invalid.")

@app.route('/telegram/start', methods=['POST'])
def telegram_start():
    """Handler for the start route, sending a welcome message to admins."""
    data = request.get_json()
    user_id = data.get('user_id')
    role = data.get('role', 'admin')  # Assume role is 'admin' for now

    if role == 'admin':
        welcome_message = (
            "Добро пожаловать, администратор! 👨‍💻\n"
            "Вы можете:\n"
            "1️⃣ Просмотреть все заявки.\n"
            "2️⃣ Сформировать отчёты.\n"
            "Выберите действие, используя кнопки ниже."
        )
        buttons = [["Просмотр заявок", "Отчёты"]]
    else:
        welcome_message = "Добро пожаловать! Пожалуйста, уточните вашу роль."
        buttons = [["Связаться с поддержкой"]]  # Default fallback button (could be removed if not needed)

    send_telegram_message_with_buttons(user_id, welcome_message, buttons)
    return {"message": "Welcome message with buttons sent."}, 200

@app.route('/telegram/notify_admins', methods=['POST'])
def notify_admins():
    """Send a notification to all admins."""
    data = request.get_json()
    message = data.get('message')

    if message:
        send_to_all_admins(message)
        return {"message": "Notification sent to admins."}, 200
    else:
        return {"message": "No message provided."}, 400

def send_telegram_message_with_buttons(chat_id, message, buttons):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "reply_markup": {
            "keyboard": buttons,
            "resize_keyboard": True,
            "one_time_keyboard": True
        }
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code != 200:
            app.logger.error(f"Failed to send Telegram message with buttons: {response.text}")
        else:
            app.logger.info(f"Telegram message with buttons sent to chat ID {chat_id}")
    except Exception as e:
        app.logger.error(f"Error sending Telegram message with buttons: {e}")

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
                role="employee",
                full_name=user_info['name']
            )
            db.session.add(user)
            db.session.commit()

        session['user_id'] = user.id
        session['role'] = user.role
        return redirect(url_for('employee') if user.role == 'employee' else url_for('admin'))
    return redirect(url_for('index'))

@app.route('/create_profile/<int:user_id>', methods=['GET', 'POST'])
def create_profile(user_id):
    user = User.query.get(user_id)
    if request.method == 'POST':
        user.password = generate_password_hash(request.form['password'])
        user.faculty = request.form['faculty']
        user.position = request.form['position']
        user.role = request.form['role']
        db.session.commit()
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

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if new_password != confirm_password:
            return render_template('reset_password.html', error_message="Пароли не совпадают.", token=token)
        user = User.query.filter_by(email="example@example.com").first()
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
            return redirect(url_for('admin'))
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

    urgent = bool(request.form.get('urgent'))
    z = Zayavka(
        type=request.form['type'],
        description=request.form['description'],
        user_id=session['user_id'],
        file=filename,
        urgent=urgent
    )
    db.session.add(z)
    db.session.commit()

    user = User.query.get(session['user_id'])
    kz_timezone = pytz.timezone('Asia/Almaty')
    utc_time = z.created_at.replace(tzinfo=pytz.utc)
    local_time = utc_time.astimezone(kz_timezone)
    timestamp = local_time.strftime('%d.%m.%Y %H:%M')
    admin_message = (
        f"📥 <b>Новая заявка</b>\n"
        f"<b>Тип:</b> {z.type}\n"
        f"<b>Описание:</b> {z.description}\n"
        f"<b>Сотрудник:</b> {user.full_name}\n"
        f"<b>Время:</b> {timestamp} (по времени Казахстана)"
    )
    send_to_all_admins(admin_message)

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

    if not status_filter or status_filter != 'сделано':
        query = query.filter(Zayavka.status != 'сделано')

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
            'created_at': datetime.datetime(2023, 10, 1),
            'status': 'сделано'
        },
        {
            'type': 'Монитор Samsung 24',
            'description': 'Заявка на замену монитора',
            'created_at': datetime.datetime(2023, 10, 5),
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
    new_status = request.form['action'].lower()
    z.set_status(new_status)
    db.session.commit()

    if new_status == 'сделано':
        employee_message = f"✅ Ваша заявка <b>{z.type}</b> выполнена. Вы можете её забрать."
        employee_chat_id = TELEGRAM_EMPLOYEE_CHAT_ID_TEMPLATE.format(user_id=z.user_id)
        send_telegram_message(employee_chat_id, employee_message)
    else:
        app.logger.warning(f"Telegram chat ID not found for user {z.user_id}")

    return redirect(url_for('admin'))

def save_to_excel(zayavka, filename):
    original_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as temp_file:
        temp_filepath = temp_file.name

    try:
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
            sheet.append(["Тип заявки", "Описание", "Дата", "Статус", "Файл", "Кто оставил заявку", "Факультет"])

        sheet = workbook.active
        sheet.append([
            zayavka.type,
            zayavka.description,
            zayavka.created_at.strftime('%d.%m.%Y %H:%M'),
            zayavka.status,
            zayavka.file if zayavka.file else "Нет файла",
            zayavka.user.username,
            zayavka.user.faculty
        ])

        workbook.save(temp_filepath)
        workbook.close()
        shutil.move(temp_filepath, original_filepath)
        app.logger.info(f"Excel file updated: {original_filepath}")
    except Exception as e:
        app.logger.error(f"Error saving to Excel file {filename}: {e}")
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

    data = [{
        'Сотрудник': z.user.username,
        'Тип': z.type,
        'Описание': z.description,
        'Статус': z.status,
        'Дата': z.created_at.strftime('%Y-%m-%d %H:%M')
    } for z in query.all()]

    df = pd.DataFrame(data)
    output = io.BytesIO()

    if month == 'all':
        filename = f"Заявки_{now.year}.xlsx"
    else:
        month_name = month_names_ru.get(month, f"Месяц_{month}")
        filename = f"Заявки_{month_name}_{now.year}.xlsx"

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
        app.logger.error(f"Error deleting user with ID {user_id}: {e}")
        return {"error": "An internal server error occurred."}, 500

@app.route('/users')
@role_required('admin')
def users():
    users = User.query.order_by(User.username).all()
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
        user.full_name = request.form.get('full_name')
        user.faculty = request.form.get('faculty')
        user.position = request.form.get('position')
        photo = request.files.get('photo')
        if photo and photo.filename != '':
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            user.photo = photo_filename
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('profile_admin.html', user=user) if user.role == 'admin' else render_template('profile_employee.html', user=user)

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('index'))
    if request.method == 'POST':
        user.full_name = request.form.get('full_name')
        user.faculty = request.form.get('faculty')
        user.position = request.form.get('position')
        photo = request.files.get('photo')
        if photo and photo.filename != '':
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            user.photo = photo_filename
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('edit_profile.html', user=user)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            reset_token = secrets.token_urlsafe(16)
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            app.logger.info(f"Password reset link for {email}: {reset_link}")
            return render_template('forgot_password.html', success_message="Инструкции по восстановлению пароля отправлены на вашу почту.")
        else:
            return render_template('forgot_password.html', error_message="Пользователь с таким email не найден.")
    return render_template('forgot_password.html')

@app.route('/reports')
@role_required('admin')
def reports():
    return render_template('reports.html')

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
        'ожидает': 'orange',
        'отклонено': 'red',
        'неизвестно': 'gray',
    }.get(status, 'lightblue')

if __name__ == "__main__":
    app.run(debug=True)

