import openpyxl
import datetime

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

    # Handle profile photo upload
    photo = request.files.get('photo')
    photo_filename = None
    if photo and photo.filename != '':
        photo_filename = secure_filename(photo.filename)
        photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))

    # Create a new user and save it to the database
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
    db.session.commit()

    return redirect(url_for('index'))

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
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
            user.photo = photo_filename

        db.session.commit()
        return redirect(url_for('profile'))

    # Render different templates based on the user's role
    if user.role == 'admin':
        return render_template('profile_admin.html', user=user)
    elif user.role == 'employee':
        return render_template('profile_employee.html', user=user)

    return redirect(url_for('index'))

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
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))
            user.photo = photo_filename

        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)

@app.route('/my-requests')
def my_requests():
    if session.get('role') != 'employee':
        return redirect(url_for('index'))
    zayavki = Zayavka.query.filter_by(user_id=session['user_id']).order_by(Zayavka.created_at.desc()).all()
    return render_template('my_requests.html', zayavki=zayavki)

@app.route('/delete_request/<int:request_id>', methods=['POST'])
def delete_request(request_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    z = Zayavka.query.get(request_id)
    if z and z.user_id == session['user_id'] and z.status in ['ожидает', 'отклонено']:
        db.session.delete(z)
        db.session.commit()
    return redirect(url_for('my_requests'))

@app.route('/submit_feedback/<int:request_id>', methods=['POST'])
def submit_feedback(request_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    z = Zayavka.query.get(request_id)
    if z and z.user_id == session['user_id'] and z.status in ['сделано', 'отклонено']:
        z.comment = request.form.get('comment')
        z.confirmed_by_user = True
        db.session.commit()
    return redirect(url_for('my_requests'))

@app.route('/my-history')
def my_history():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    zayavki = Zayavka.query.filter_by(user_id=session['user_id']).filter(
        (Zayavka.status == 'архив') | (Zayavka.confirmed_by_user == True)
    ).order_by(Zayavka.created_at.desc()).all()
    return render_template('my_history.html', zayavki=zayavki)

@app.route('/admin')
def admin():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))

    type_filter = request.args.get('type')
    status_filter = request.args.get('status')
    query = Zayavka.query.join(User, Zayavka.user_id == User.id)

    # Apply filters based on type and status
    if type_filter:
        query = query.filter(Zayavka.type == type_filter)
    if status_filter:
        query = query.filter(Zayavka.status == status_filter)

    zayavki = query.order_by(Zayavka.created_at.desc()).all()
    type_data = Counter(z.type for z in zayavki)
    status_data = Counter(z.status for z in zayavki)

    return render_template('admin.html', zayavki=zayavki,
                           type_data=type_data,
                           status_data=status_data)

@app.route('/update_status', methods=['POST'])
def update_status():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    z = Zayavka.query.get(request.form['id'])
    new_status = request.form['action'].lower()  # Normalize status to lowercase
    z.set_status(new_status)  # Use the set_status method to enforce standardized values
    db.session.commit()

    # Save to the appropriate Excel file
    excel_file = ''
    if new_status == 'сделано':
        excel_file = 'завершённые_заявки.xlsx'
    elif new_status == 'отклонено':
        excel_file = 'отклонённые_заявки.xlsx'

    if excel_file:
        save_to_excel(z, excel_file)

    return redirect(url_for('admin'))

def save_to_excel(zayavka, filename):
    # Generate a unique filename by appending the current date and time
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_filename = f"{filename.split('.')[0]}_{timestamp}.xlsx"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    # Create a new workbook
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Заявки"

    # Add headers
    sheet.append(["Тип заявки", "Описание", "Дата", "Статус", "Файл", "Кто оставил заявку", "Факультет"])

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

    # Save the workbook
    workbook.save(filepath)
    app.logger.info(f"Excel file saved: {filepath}")

@app.route('/employee')
def employee():
    if session.get('role') != 'employee':
        return redirect(url_for('index'))
    try:
        zayavki = Zayavka.query.filter_by(user_id=session['user_id']).order_by(Zayavka.created_at.desc()).all()
        app.logger.info(f"Loaded {len(zayavki)} requests for user {session['user_id']}")
        return render_template('employee.html', zayavki=zayavki)
    except Exception as e:
        app.logger.error(f"Error loading employee page: {e}")
        return "An error occurred while loading the employee page.", 500

@app.route('/history')
def history():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    zayavki = Zayavka.query.filter_by(status='сделано').order_by(Zayavka.created_at.desc()).all()
    return render_template('history.html', zayavki=zayavki)
