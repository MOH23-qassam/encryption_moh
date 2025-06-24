import os
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from crypto_core import encrypt_data, decrypt_data, encrypt_text, decrypt_text
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'very_secret_key'

USERNAME = 'كتائب القسام'
with open('password.txt', 'r', encoding='utf-8') as f:
    stored_password = f.read().strip()

FILE_DIR = 'static/files'
os.makedirs(FILE_DIR, exist_ok=True)

# حذف الملفات الأقدم من 7 أيام
EXPIRATION_SECONDS = 7 * 24 * 60 * 60
now = time.time()
for fname in os.listdir(FILE_DIR):
    path = os.path.join(FILE_DIR, fname)
    if os.path.isfile(path) and now - os.path.getmtime(path) > EXPIRATION_SECONDS:
        os.remove(path)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == USERNAME and request.form['password'] == stored_password:
            session['logged_in'] = True
            return redirect('/home')
        else:
            flash('بيانات الدخول غير صحيحة')
    return render_template('login.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    global stored_password
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    result = None
    file_url = None
    output_text = None

    if request.method == 'POST':
        action = request.form['action']

        if action == 'change_password':
            old = request.form.get('old_password')
            new = request.form.get('new_password')
            if old == stored_password and new:
                stored_password = new
                with open('password.txt', 'w', encoding='utf-8') as f:
                    f.write(new)
                result = "✅ تم تغيير كلمة المرور بنجاح"
            else:
                result = "❌ كلمة المرور الحالية غير صحيحة"

        elif action in ('encrypt_direct', 'encrypt_show', 'decrypt'):
            password = request.form.get('password')
            file = request.files.get('file')
            if file and password:
                file_bytes = file.read()
                try:
                    if action.startswith('encrypt'):
                        ext = os.path.splitext(file.filename)[1]
                        processed = encrypt_data(file_bytes, password, extension=ext)
                        filename = secure_filename(file.filename) + '.enc'
                    else:
                        processed, ext = decrypt_data(file_bytes, password)
                        filename = secure_filename(file.filename).replace('.enc', '')
                        if not filename.endswith(ext):
                            filename += ext

                    if action == 'encrypt_direct':
                        return send_file(BytesIO(processed), download_name=filename, as_attachment=True)
                    else:
                        path = os.path.join(FILE_DIR, filename)
                        with open(path, 'wb') as f:
                            f.write(processed)
                        file_url = '/' + path.replace('\\', '/')
                        result = f"✅ تم إنشاء الملف: {filename}"

                except Exception as e:
                    result = f"❌ خطأ: {str(e)}"
            else:
                result = "❌ يرجى رفع ملف وإدخال كلمة المرور"

        elif action in ('encrypt_text', 'decrypt_text'):
            text = request.form.get('text')
            password = request.form.get('password_text')
            try:
                if action == 'encrypt_text':
                    output_text = encrypt_text(text, password)
                else:
                    output_text = decrypt_text(text, password)
            except Exception as e:
                output_text = f"❌ خطأ: {str(e)}"

    return render_template('home.html', result=result, file_url=file_url, output_text=output_text)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)





