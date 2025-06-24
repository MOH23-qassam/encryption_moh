import os
import time
import hmac
import hashlib
import shutil
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from crypto_core import encrypt_data, decrypt_data, encrypt_text, decrypt_text

app = Flask(__name__)
app.secret_key = 'very_secret_key'

USERNAME = 'كتائب القسام'
with open('password.txt', 'r', encoding='utf-8') as f:
    stored_password = f.read().strip()

# مجلد الملفات
FILE_DIR = 'static/files'
os.makedirs(FILE_DIR, exist_ok=True)

# حذف تلقائي للملفات الأقدم من 7 أيام
EXPIRATION_SECONDS = 7 * 24 * 60 * 60
now = time.time()
for fname in os.listdir(FILE_DIR):
    path = os.path.join(FILE_DIR, fname)
    if os.path.isfile(path) and now - os.path.getmtime(path) > EXPIRATION_SECONDS:
        os.remove(path)

# 🔐 التوقيع الرقمي لرابط التحميل لمرة واحدة
SECRET_KEY = b"my_download_secret"
used_signatures = set()

def generate_signature(filename: str) -> str:
    return hmac.new(SECRET_KEY, filename.encode(), hashlib.sha256).hexdigest()

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
    output_text = None
    file_url = None

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

        elif action in ['encrypt', 'encrypt_direct', 'encrypt_show', 'decrypt']:
            password = request.form['password']
            file = request.files['file']
            if file and password:
                file_bytes = file.read()
                try:
                    if action.startswith('encrypt'):
                        processed = encrypt_data(file_bytes, password, extension=os.path.splitext(file.filename)[1])
                        filename = secure_filename(file.filename) + '.enc'
                    else:
                        processed, ext = decrypt_data(file_bytes, password)
                        filename = secure_filename(file.filename).replace('.enc', '') + ext

                    file_path = os.path.join(FILE_DIR, filename)
                    with open(file_path, 'wb') as f:
                        f.write(processed)

                    if action == 'encrypt_show':
                        sig = generate_signature(filename)
                        file_url = f"/download?file={filename}&sig={sig}"
                    else:
                        return send_file(file_path, as_attachment=True)

                    result = f"✅ تم إنشاء الملف: {filename}"
                except Exception as e:
                    result = f"❌ حدث خطأ: {str(e)}"
            else:
                result = "❗ يرجى رفع ملف وإدخال كلمة المرور"

        elif action == 'encrypt_text':
            text = request.form['text']
            password = request.form['password_text']
            try:
                output_text = encrypt_text(text, password)
            except Exception as e:
                result = f"❌ خطأ في التشفير: {str(e)}"

        elif action == 'decrypt_text':
            text = request.form['text']
            password = request.form['password_text']
            try:
                output_text = decrypt_text(text, password)
            except Exception as e:
                result = f"❌ خطأ في فك التشفير: {str(e)}"

    return render_template('home.html', result=result, file_url=file_url, output_text=output_text)

@app.route('/download')
def download_once():
    filename = request.args.get("file")
    sig = request.args.get("sig")

    if not filename or not sig:
        return "❌ رابط غير صالح", 400

    expected_sig = generate_signature(filename)
    if not hmac.compare_digest(sig, expected_sig):
        return "❌ توقيع غير صالح", 403

    if sig in used_signatures:
        return "🔁 هذا الرابط تم استخدامه مسبقًا", 403

    used_signatures.add(sig)

    file_path = os.path.join(FILE_DIR, filename)
    if not os.path.isfile(file_path):
        return "❌ الملف غير موجود", 404

    return send_file(file_path, as_attachment=True)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))



if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)





