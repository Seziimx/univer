from werkzeug.utils import secure_filename
import os

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Update user details
        current_user.full_name = request.form.get('full_name')
        current_user.faculty = request.form.get('faculty')
        current_user.position = request.form.get('position')

        # Handle profile photo upload
        photo = request.files.get('photo')
        if photo and photo.filename != '':
            filename = secure_filename(photo.filename)
            if not filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                return 'Недопустимый формат файла', 400
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(photo_path)
            current_user.photo = filename

        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)
