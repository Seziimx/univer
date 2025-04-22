from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from collections import Counter
import os
import datetime
import pandas as pd
import io

from models import db, User, Zayavka
from utils import generate_word_report, generate_pdf_report

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
migrate = Migrate(app, db)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = generate_password_hash(request.form['password'])
    role = request.form.get('role')  # Ensure role is selected
    if role not in ['employee', 'admin']:
        return 'Invalid role selected', 400
    user = User(username=username, email=email, password=password, role=role)
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('index'))

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
    return 'Неверный логин или пароль'

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/employee')
def employee():
    if session.get('role') != 'employee':
        return redirect(url_for('index'))
    zayavki = Zayavka.query.filter_by(user_id=session['user_id']).order_by(Zayavka.created_at.desc()).all()
    return render_template('employee.html', zayavki=zayavki)

@app.route('/send', methods=['POST'])
def send():
    if session.get('role') != 'employee':
        return redirect(url_for('index'))

    file = request.files.get('file')
    filename = None
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    z = Zayavka(
        type=request.form['type'],
        description=request.form['description'],
        user_id=session['user_id'],
        file=filename
    )
    db.session.add(z)
    db.session.commit()
    return redirect(url_for('employee'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin')
def admin():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))

    zayavki = Zayavka.query.order_by(Zayavka.created_at.desc()).all()  # Ensure all requests are retrieved
    return render_template('admin.html', zayavki=zayavki)

@app.route('/update_status', methods=['POST'])
def update_status():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    z = Zayavka.query.get(request.form['id'])
    if not z:
        return 'Заявка не найдена', 404

    new_status = request.form['action'].lower()
    if new_status not in ['сделано', 'отказано']:
        return 'Недопустимый статус', 400

    z.set_status(new_status)
    db.session.commit()

    # Notify the employee
    employee = User.query.get(z.user_id)
    notification = f"Ваша заявка '{z.description}' была обновлена: {z.status}"
    # Store notification logic here (e.g., save to database or send email)

    return redirect(url_for('admin'))

@app.route('/api/update_status', methods=['POST'])
def api_update_status():
    if session.get('role') != 'admin':
        return {'error': 'Unauthorized'}, 403

    data = request.get_json()
    zayavka_id = data.get('id')
    new_status = data.get('status')

    zayavka = Zayavka.query.get(zayavka_id)
    if not zayavka:
        return {'error': 'Request not found'}, 404

    zayavka.status = new_status
    db.session.commit()

    return {'success': True, 'status': new_status}

@app.route('/reports')
def reports():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    return render_template('reports.html')

@app.route('/download_report', methods=['POST'])
def download_report():
    if session.get('role') != 'admin': return redirect(url_for('index'))
    month = request.form['month']
    query = Zayavka.query.join(User, Zayavka.user_id == User.id)
    if month != 'all':
        month = int(month)
        start = datetime.date(datetime.datetime.now().year, month, 1)
        end = datetime.date(datetime.datetime.now().year + (month == 12), (month % 12) + 1, 1)
        query = query.filter(Zayavka.created_at >= start, Zayavka.created_at < end)

    data = [{
        'Сотрудник': z.user.username,
        'Тип': z.type,
        'Описание': z.description,
        'Статус': z.status
    } for z in query.all()]

    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Отчёт')
    output.seek(0)
    return send_file(output, download_name='report.xlsx', as_attachment=True)

@app.route('/download_word_report', methods=['POST'])
def download_word_report():
    if session.get('role') != 'admin': return redirect(url_for('index'))
    month = request.form['month']
    query = Zayavka.query.join(User, Zayavka.user_id == User.id)
    if month != 'all':
        start = datetime.date(datetime.datetime.now().year, int(month), 1)
        end = datetime.date(datetime.datetime.now().year + (int(month) == 12), (int(month) % 12) + 1, 1)
        query = query.filter(Zayavka.created_at >= start, Zayavka.created_at < end)
    report = generate_word_report(query.all())
    return send_file(report, download_name='report.docx', as_attachment=True)

@app.route('/download_pdf_report', methods=['POST'])
def download_pdf_report():
    if session.get('role') != 'admin': return redirect(url_for('index'))
    month = request.form['month']
    query = Zayavka.query.join(User, Zayavka.user_id == User.id)
    if month != 'all':
        start = datetime.date(datetime.datetime.now().year, int(month), 1)
        end = datetime.date(datetime.datetime.now().year + (int(month) == 12), (int(month) % 12) + 1, 1)
        query = query.filter(Zayavka.created_at >= start, Zayavka.created_at < end)
    report = generate_pdf_report(query.all())
    return send_file(report, download_name='report.pdf', as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        from flask_migrate import Migrate
        migrate = Migrate(app, db)  # Initialize migration
        db.create_all()  # Create all database tables
    app.run(debug=True)