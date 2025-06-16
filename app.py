from flask import Flask, jsonify,request, session, redirect, url_for, send_from_directory, render_template, send_file, flash
import os
import json
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from dotenv import load_dotenv
from flask_session import Session

app = Flask(__name__)
CORS(app)
load_dotenv()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
print("DEBUG: SECRET_KEY =", app.config['SECRET_KEY'])  # Debug-Ausgabe
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Verhindert Zugriff per JavaScript
app.config['SESSION_COOKIE_SECURE'] = False   # Nur über HTTPS senden
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken']
app.config['SESSION_TYPE'] = 'filesystem'  # Session auf der Festplatte speichern
app.config['SESSION_PERMANENT'] = False    # Session bleibt auch ohne Neustart erhalten
app.config['SESSION_USE_SIGNER'] = True    # Signiert die Session für mehr Sicherheit
app.config['SESSION_KEY_PREFIX'] = 'csrf_' # Präfix für die Session-Keys (optional)
Session(app)
SHARE_FOLDER = '---'
ALLOWED_EXTENSIONS = {'txt', 'jpg', 'png', 'pdf'}
TOKEN_PATH = '......./tokens.json' # changed
TOKEN_MAP = {}
LOG_FILE_PATH = '/var/log/nginx/access.log'
HUE_BRIDGE_IP = "192.168.2.103"
# Flask-Limiter für Rate Limiting (max. 5 Versuche pro Minute)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

# Dictionary für fehlgeschlagene Logins pro IP
failed_logins = {}
csrf = CSRFProtect(app)

class LoginForm(FlaskForm):
    username = StringField('Benutzername', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Passwort', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    ip = get_remote_address()
    now = time.time()

    # Wenn IP in der Sperrliste ist
    if ip in failed_logins and failed_logins[ip]['count'] >= 5:
        last_attempt = failed_logins[ip]['last_attempt']
        if now - last_attempt < 300:  # 5 Minuten Sperre
            return "Zu viele fehlgeschlagene Versuche. Versuche es in 5 Minuten erneut.", 403
        else:
            failed_logins[ip]['count'] = 0  # Reset nach 5 Minuten



    form = LoginForm()
    print("DEBUG: CSRF-Token in Session:", session.get('_csrf_token'))
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in users and check_password_hash(users[username], password):
            session['admin'] = True
            flash('Login erfolgreich!', 'success')
            failed_logins.pop(ip, None)
            return redirect(url_for('dashboard'))
        else:
                # Fehlgeschlagen -> IP speichern
            if ip not in failed_logins:
                failed_logins[ip] = {'count': 1, 'last_attempt': now}
            else:
                failed_logins[ip]['count'] += 1
                failed_logins[ip]['last_attempt'] = now
            flash('Ungültige Anmeldeinformationen', 'danger')
    return render_template('login.html', form=form)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(func):
    def wrapper(*args, **kwargs):
        if 'admin' not in session:
            print("Bitte melde dich zuerst an!", "warning")
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def send_hue_command(light_id, payload):
    """Send commands to Hue Bridge API"""
    url = f"http://{HUE_BRIDGE_IP}/api/{API_KEY}/lights/{light_id}/state"
    response = requests.put(url, json=payload)
    return response.json()

def get_light_status():
    """Fetch all light statuses from Hue Bridge"""
    url = f"http://{HUE_BRIDGE_IP}/api/{API_KEY}/lights"
    response = requests.get(url)
    return response.json()

@app.route("/toggle_light", methods=["POST"])
def toggle_light():
    data = request.json
    light_id = data.get("light_id")
    state = data.get("state")  # true = on, false = off
    response = send_hue_command(light_id, {"on": state})
    return jsonify(response)

@app.route("/brightness", methods=["POST"])
def set_brightness():
    data = request.json
    light_id = data.get("light_id")
    brightness = data.get("brightness")  # Range 0-254
    response = send_hue_command(light_id, {"bri": brightness})
    return jsonify(response)

@app.route("/lights", methods=["GET"])
def lights():
    """Returns the status of all lights"""
    response = get_light_status()
    return jsonify(response)

def get_tokens():
    """Load tokens from the JSON file into TOKEN_MAP."""
    global TOKEN_MAP
    try:
        with open(TOKEN_PATH, 'r') as file:
            TOKEN_MAP = json.load(file)
        print("JSON-Datei erfolgreich geladen.")
    except FileNotFoundError:
        print(f"Die Datei {TOKEN_PATH} wurde nicht gefunden. TOKEN_MAP bleibt leer.")
        TOKEN_MAP = {}
    except json.JSONDecodeError as e:
        print(f"Fehler beim Dekodieren der JSON-Datei: {e}")
        TOKEN_MAP = {}

def save_tokens(new_tokens):
    """Append new tokens to the existing TOKEN_MAP and save to the file."""
    global TOKEN_MAP

    # Load existing tokens
    get_tokens()

    # Update TOKEN_MAP with new tokens
    TOKEN_MAP.update(new_tokens)

    # Save the updated TOKEN_MAP to the file
    try:
        with open(TOKEN_PATH, 'w') as file:
            json.dump(TOKEN_MAP, file, indent=4)
        print("TOKEN_MAP erfolgreich gespeichert.")
    except Exception as e:
        print(f"Fehler beim Speichern der TOKEN_MAP: {e}")

get_tokens()  # Load the tokens into TOKEN_MAP

@app.route('/login2', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Beschränkung: Max. 5 Versuche pro Minute
def login2():
    ip = get_remote_address()
    now = time.time()

    # Wenn IP in der Sperrliste ist
    if ip in failed_logins and failed_logins[ip]['count'] >= 5:
        last_attempt = failed_logins[ip]['last_attempt']
        if now - last_attempt < 300:  # 5 Minuten Sperre
            return "Zu viele fehlgeschlagene Versuche. Versuche es in 5 Minuten erneut.", 403
        else:
            failed_logins[ip]['count'] = 0  # Reset nach 5 Minuten

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Login-Versuch: Benutzername: {username}, Passwort: {password}")

        # Login validieren
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD: # HASH alternative in login1, unsicher
            print("Erfolgreich eingeloggt!")
            session['admin'] = True
            failed_logins.pop(ip, None)
            return redirect(url_for('dashboard'))
        if ip not in failed_logins:
            failed_logins[ip] = {'count': 1, 'last_attempt': now}
        else:
            failed_logins[ip]['count'] += 1
            failed_logins[ip]['last_attempt'] = now

        return "Login fehlgeschlagen!", 403

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('admin', None)
    # Clear session cookie
    session.clear()
    return redirect(url_for('login'))

import mimetypes

@app.route('/datawarehouse', defaults={'path': ''})
@app.route('/datawarehouse/<path:path>')
@login_required
def datawarehouse(path):
    if not session.get('admin'):
        return redirect(url_for('login'))

    abs_path = os.path.join(SHARE_FOLDER, path)
    app.logger.debug(f"Accessing path: {abs_path}")

    if not os.path.exists(abs_path):
        app.logger.error(f"Path not found: {abs_path}")
        return "Path not found", 404

    if os.path.isfile(abs_path):
        try:
            # Bestimme den MIME-Typ
            mimetype = mimetypes.guess_type(abs_path)[0]

            if mimetype == 'application/pdf':
                # PDF anzeigen
                return send_from_directory(SHARE_FOLDER, path, as_attachment=False, mimetype=mimetype)
            else:
                # Andere Dateien herunterladen
                return send_from_directory(SHARE_FOLDER, path, as_attachment=True)
        except Exception as e:
            app.logger.error(f"Error sending file: {e}")
            return f"Error sending file: {e}", 500

    try:
        # Verzeichnisinhalt laden
        files = []
        for f in os.listdir(abs_path):
            full_path = os.path.join(abs_path, f)
            is_file = os.path.isfile(full_path)
            files.append({"name": f, "is_file": is_file})
            app.logger.debug(f"Found item: {f}, is_file: {is_file}")
    except PermissionError as e:
        app.logger.error(f"Permission denied: {e}")
        return f"Permission denied: {e}", 403
    except Exception as e:
        app.logger.error(f"Error loading directory: {e}")
        return f"Error loading directory: {e}", 500

    return render_template('explorer.html', files=files, current_path=path)


# 📌 Datei-Upload in das gewählte Verzeichnis
@app.route('/upload/<path:path>', methods=['GET', 'POST'])
@login_required
def upload_file(path):
    full_path = os.path.join(SHARE_FOLDER, path)
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("Keine Datei hochgeladen!", "danger")
            return redirect(url_for('upload_file', path=path))
        
        file = request.files['file']
        if file.filename == '':
            flash("Keine Datei ausgewählt!", "danger")
            return redirect(url_for('upload_file', path=path))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(full_path, filename))
            flash(f"Datei '{filename}' erfolgreich hochgeladen!", "success")
            return redirect(url_for('datawarehouse', path=path))
    
    return render_template('upload.html', path=path)

@app.route('/')
def index():
    return render_template('index.html', message="")
@app.route('/about')
def about():
	return render_template('about.html', message="")
@app.route('/pomodoro')
def pomodoro():
	return render_template('pomodoro.html', message="")

@app.route('/hue')
@login_required
def hue():
	return render_template('hue.html', message="")

@app.route('/dashboard')
@login_required
def dashboard():
    print("dashboard redirect")
    if not session.get('admin'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', message="Welcome to the Dashboard!")

@app.route('/generate_token/<path:file_path>', methods=['GET'])
@login_required
def generate_token(file_path):
    if not session.get('admin'):
        return redirect(url_for('login'))
    
    abs_path = os.path.join(SHARE_FOLDER, file_path)

    if not os.path.exists(abs_path):
        return "File not found", 404

    if not os.path.isfile(abs_path):
        return "Cannot generate token for directories", 400

    # Token generieren und speichern
    token = secrets.token_urlsafe(32)
    tokens = {}
    tokens[token] = abs_path
    save_tokens(tokens)  # Speichere die aktualisierte Map

    public_url = url_for('access_with_token', token=token, _external=True)
    return render_template('token_created.html', public_url=public_url)

@app.route('/access/<token>', methods=['GET'])
def access_with_token(token):
    get_tokens() #updates token map from token map file
    if token not in TOKEN_MAP:
        return f"Invalid or expired token: token map: {TOKEN_MAP}", 403

    abs_path = TOKEN_MAP[token]
    if not os.path.exists(abs_path):
        return "File not found", 404

    return send_file(abs_path, as_attachment=False)

@app.route('/logs', methods=['GET'])
@login_required
def logs():
    """
    Log viewer page with AJAX-based dynamic updates.
    Only accessible to logged-in users.
    """
    if not session.get('admin'):
        return redirect(url_for('login'))

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Serve log data for AJAX requests
        try:
            with open(LOG_FILE_PATH, 'r') as file:
                lines = file.readlines()
            return jsonify({'logs': lines[-100:]})  # Return the last 100 lines
        except FileNotFoundError:
            return jsonify({'error': f"Log file {LOG_FILE_PATH} not found"}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Render the log viewer page for normal requests
    return render_template('log_viewer.html')

from Controller import Controller  # für items
controller = Controller()

import requests

def print_label_remote(name, id_str, webid):
    url = "http://192.168.2.110:5000/print-label"
    payload = {
        "name": name,
        "id_str": id_str,
        "webid": webid
    }
    
    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()  # Löst Fehler aus, wenn z. B. 500 zurückkommt
        print(f"✅ Label erfolgreich angefordert für '{name}' (ID: {id_str})")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Fehler beim Drucken des Labels: {e}")
        return {"status": "error", "message": str(e)}

@app.route('/items', methods=['GET', 'POST'])
@login_required
def manage_items():
    if request.method == 'POST':
        name = request.form['name']
        room = request.form['room']
        position = request.form['position']
        content = request.form['content']
        item = controller.create_new_item(name, room, position, content)
        print_label_remote(name,item.id, item.webtag)
        return redirect(url_for('manage_items'))

    query = request.args.get("query", "")
    if query:
        items = [item for item in controller.get_all_items() if query.lower() in item.name.lower() or query.lower() in item.id.lower()]
    else:
        items = controller.get_all_items()
    return render_template('items.html', items=items, query=query)

@app.route('/items/delete/<item_id>')
@login_required
def delete_item(item_id):
    controller.delete_item(item_id)
    return redirect(url_for('manage_items'))

from datetime import datetime

@app.route('/items/<item_id>')
@login_required
def item_detail(item_id):
    item = controller.find_item(item_id)
    if not item:
        return "Item not found", 404

    previous_accessed = item.last_accessed

    item.last_accessed = datetime.now()
    controller.db.update_item(item)

    return render_template('item_detail.html', item=item, previous_accessed=previous_accessed)

@app.route('/items/print/<item_id>')
@login_required
def print_item(item_id):
    item = controller.find_item(item_id)
    print_label_remote(item.name,item_id,item.webtag)
    return redirect(url_for('manage_items'))


@app.route('/view/<webtag>')
def view_item_public(webtag):
    item = controller.find_item_by_webtag(webtag)
    if not item:
        return "Item not found or access denied", 404
    return render_template("item_detail.html", item=item, previous_accessed=item.last_accessed)

@app.route('/maps')
@login_required
def maps():
    return render_template('maps.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)