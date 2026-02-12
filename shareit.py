import os
import socket
import pyqrcode
import json
import shutil
from datetime import datetime
from flask import Flask, render_template_string, request, send_from_directory, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from pyngrok import ngrok
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. SETUP ---
app = Flask(__name__)
# IMPORTANT: On Koyeb, this secret key should ideally be an Environment Variable
app.secret_key = os.environ.get("SECRET_KEY", "shivam_social_vault_2026") 
CORS(app)

BASE_DIR = os.getcwd()
VAULT_ROOT = os.path.join(BASE_DIR, 'vault_storage')
PUBLIC_ROOT = os.path.join(VAULT_ROOT, '_public_hub')
DB_FILE = os.path.join(BASE_DIR, 'vault_db.json')

for p in [VAULT_ROOT, PUBLIC_ROOT]:
    if not os.path.exists(p): os.makedirs(p)

if not os.path.exists(DB_FILE):
    with open(DB_FILE, 'w') as f: json.dump({"users": {}, "public_meta": {}}, f)

# --- 2. AUTHENTICATION ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id): self.id = id

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    return User(user_id) if user_id in db['users'] else None

def get_db():
    try:
        with open(DB_FILE, 'r') as f: return json.load(f)
    except: return {"users": {}, "public_meta": {}}

def save_db(data):
    with open(DB_FILE, 'w') as f: json.dump(data, f)

# --- 3. UI DESIGN (UI_HTML remains same as your original) ---
UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <title>Social Cloud Hub</title>
    <style>
        body { background: #0b0f1a; color: #f1f5f9; font-family: 'Inter', sans-serif; }
        .glass { background: rgba(23, 32, 53, 0.8); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); }
        .active-tab { border-left: 4px solid #3b82f6; background: rgba(59, 130, 246, 0.1); color: #3b82f6; }
        .like-btn:hover { transform: scale(1.1); transition: 0.2s; }
    </style>
</head>
<body class="min-h-screen">
    {% if current_user.is_authenticated %}
    <nav class="p-4 glass sticky top-0 z-50 border-b border-white/5">
        <div class="max-w-7xl mx-auto flex justify-between items-center">
            <h1 class="text-xl font-black text-blue-500 tracking-tighter italic">SOCIAL<span class="text-white">HUB</span></h1>
            <div class="flex items-center gap-4">
                <span class="text-[10px] font-black uppercase bg-blue-500/10 px-3 py-1 rounded-full text-blue-400">{{ current_user.id }}</span>
                <a href="/logout" class="text-[10px] font-black text-red-500 uppercase">Logout</a>
            </div>
        </div>
    </nav>
    <main class="max-w-7xl mx-auto p-4 lg:p-8 grid grid-cols-1 lg:grid-cols-4 gap-8">
        <div class="space-y-4">
            <div class="glass p-6 rounded-3xl">
                <form action="/upload" method="POST" enctype="multipart/form-data" id="upForm">
                    <input type="hidden" name="target" value="{{ 'public' if is_public else 'private' }}">
                    <label class="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed border-slate-700 rounded-2xl cursor-pointer hover:border-blue-500 transition-all bg-slate-900/50 group">
                        <i class="fas fa-upload text-slate-500 group-hover:text-blue-500 mb-2"></i>
                        <span class="text-[10px] font-black text-slate-500 uppercase">Upload to {{ 'Hub' if is_public else 'Vault' }}</span>
                        <input type="file" name="file" class="hidden" onchange="document.getElementById('upForm').submit()" />
                    </label>
                </form>
            </div>
            <div class="glass p-4 rounded-3xl space-y-1">
                <a href="/" class="flex items-center p-3 rounded-xl transition text-sm font-bold {{ 'active-tab' if not is_trash and not is_public else '' }}"><i class="fas fa-lock mr-3"></i> Private Vault</a>
                <a href="/hub" class="flex items-center p-3 rounded-xl transition text-sm font-bold {{ 'active-tab' if is_public else '' }}"><i class="fas fa-fire-alt mr-3"></i> Public Hub</a>
                <a href="/trash" class="flex items-center p-3 rounded-xl transition text-sm font-bold {{ 'active-tab' if is_trash else '' }}"><i class="fas fa-trash-alt mr-3"></i> Trash</a>
            </div>
        </div>
        <div class="lg:col-span-3 glass rounded-[2.5rem] overflow-hidden">
            <div class="p-6 border-b border-white/5 bg-white/5 flex justify-between items-center">
                <h2 class="text-xs font-black uppercase tracking-[0.2em] text-slate-400">
                    {{ 'Community Public Hub (Sorted by Likes)' if is_public else 'Personal Private Vault' }}
                </h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                    <thead class="bg-black/20 text-[10px] uppercase font-black text-slate-500 tracking-widest">
                        <tr>
                            <th class="p-5">Filename</th>
                            <th class="p-5">{% if is_public %}Likes{% else %}Type{% endif %}</th>
                            <th class="p-5 text-right">Control</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-white/5">
                        {% for f in files %}
                        <tr class="hover:bg-white/5 transition">
                            <td class="p-5">
                                <p class="font-medium truncate max-w-[200px]">{{ f }}</p>
                                {% if is_public %}
                                <p class="text-[9px] text-slate-500 uppercase font-bold">Shared by {{ meta[f]['sender'] if f in meta else 'Admin' }}</p>
                                {% endif %}
                            </td>
                            <td class="p-5">
                                {% if is_public %}
                                <div class="flex items-center gap-2">
                                    <a href="/like/{{ f }}" class="like-btn text-rose-500">
                                        <i class="{{ 'fas' if current_user.id in meta[f].get('liked_by', []) else 'far' }} fa-heart"></i>
                                    </a>
                                    <span class="text-xs font-black">{{ meta[f].get('likes', 0) }}</span>
                                </div>
                                {% else %}
                                <span class="text-[10px] text-slate-500 font-bold uppercase">Private</span>
                                {% endif %}
                            </td>
                            <td class="p-5 text-right flex justify-end gap-2">
                                <a href="/download/{{ f }}?src={{ 'public' if is_public else 'private' }}" class="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-800 hover:bg-blue-600"><i class="fas fa-download text-xs"></i></a>
                                {% if not is_public and not is_trash %}
                                <a href="/make_public/{{ f }}" class="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-800 hover:bg-emerald-600" title="Share to Public Hub"><i class="fas fa-share-nodes text-xs"></i></a>
                                <a href="/delete/{{ f }}" class="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-800 hover:bg-red-600"><i class="fas fa-trash text-xs"></i></a>
                                {% endif %}
                                {% if is_trash %}
                                <a href="/restore/{{ f }}" class="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-800 hover:bg-green-600"><i class="fas fa-undo text-xs"></i></a>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% if not files %}<div class="p-20 text-center opacity-20 font-black text-xs uppercase">No Content Available</div>{% endif %}
        </div>
    </main>
    {% else %}
    <div class="flex items-center justify-center min-h-screen p-6">
        <div class="glass p-12 rounded-[3.5rem] w-full max-w-sm shadow-2xl border border-white/5">
            <h2 class="text-3xl font-black text-center mb-8 tracking-tighter">SOCIAL<span class="text-blue-500">HUB</span></h2>
            <form method="POST" action="/login" class="space-y-4 mb-8">
                <input type="text" name="u" placeholder="Username" required class="w-full bg-slate-900 border border-slate-800 p-4 rounded-2xl outline-none focus:border-blue-500">
                <input type="password" name="p" placeholder="Password" required class="w-full bg-slate-900 border border-slate-800 p-4 rounded-2xl outline-none focus:border-blue-500">
                <button type="submit" class="w-full bg-blue-600 py-4 rounded-2xl font-black uppercase tracking-widest shadow-xl shadow-blue-900/40">Open Vault</button>
            </form>
            <div class="pt-6 border-t border-white/5 text-center">
                <p class="text-[10px] font-black text-slate-500 uppercase mb-4 tracking-widest">New here? Join us</p>
                <form method="POST" action="/register" class="space-y-4">
                    <input type="text" name="u" placeholder="New Username" required class="w-full bg-slate-900 border border-slate-800 p-3 rounded-xl outline-none focus:border-emerald-500 text-xs">
                    <input type="password" name="p" placeholder="New Password" required class="w-full bg-slate-900 border border-slate-800 p-3 rounded-xl outline-none focus:border-emerald-500 text-xs">
                    <button type="submit" class="w-full bg-emerald-600/10 text-emerald-500 border border-emerald-500/20 py-3 rounded-xl font-black text-[10px] uppercase">Sign Up</button>
                </form>
            </div>
        </div>
    </div>
    {% endif %}
</body>
</html>
"""

# --- 4. SYSTEM LOGIC ---
def get_user_folders(user_id):
    u_root = os.path.join(VAULT_ROOT, user_id)
    u_trash = os.path.join(u_root, '.trash')
    for p in [u_root, u_trash]:
        if not os.path.exists(p): os.makedirs(p)
    return u_root, u_trash

@app.route('/register', methods=['POST'])
def register():
    u, p = request.form['u'].lower().strip(), request.form['p']
    db = get_db()
    if u in db['users'] or not u: return "Invalid or existing username"
    db['users'][u] = generate_password_hash(p)
    save_db(db)
    get_user_folders(u)
    login_user(User(u))
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form['u'].lower().strip(), request.form['p']
        db = get_db()
        if u in db['users'] and check_password_hash(db['users'][u], p):
            login_user(User(u))
            return redirect(url_for('index'))
    return render_template_string(UI_HTML)

@app.route('/')
@login_required
def index():
    u_root, _ = get_user_folders(current_user.id)
    files = [f for f in os.listdir(u_root) if os.path.isfile(os.path.join(u_root, f))]
    return render_template_string(UI_HTML, files=files, is_trash=False, is_public=False)

@app.route('/hub')
@login_required
def hub():
    db = get_db()
    files = os.listdir(PUBLIC_ROOT)
    files.sort(key=lambda f: db['public_meta'].get(f, {}).get('likes', 0), reverse=True)
    return render_template_string(UI_HTML, files=files, meta=db['public_meta'], is_trash=False, is_public=True)

@app.route('/like/<path:filename>')
@login_required
def like_file(filename):
    db = get_db()
    if filename in db['public_meta']:
        meta = db['public_meta'][filename]
        liked_by = meta.get('liked_by', [])
        if current_user.id in liked_by:
            liked_by.remove(current_user.id)
            meta['likes'] = max(0, meta.get('likes', 1) - 1)
        else:
            liked_by.append(current_user.id)
            meta['likes'] = meta.get('likes', 0) + 1
        meta['liked_by'] = liked_by
        save_db(db)
    return redirect('/hub')

@app.route('/trash')
@login_required
def trash():
    _, u_trash = get_user_folders(current_user.id)
    files = os.listdir(u_trash)
    return render_template_string(UI_HTML, files=files, is_trash=True, is_public=False)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    f = request.files.get('file')
    target = request.form.get('target')
    if f:
        if target == 'public':
            f.save(os.path.join(PUBLIC_ROOT, f.filename))
            db = get_db()
            db['public_meta'][f.filename] = {"sender": current_user.id, "likes": 0, "liked_by": []}
            save_db(db)
            return redirect('/hub')
        else:
            u_root, _ = get_user_folders(current_user.id)
            f.save(os.path.join(u_root, f.filename))
    return redirect('/')

@app.route('/make_public/<path:filename>')
@login_required
def make_public(filename):
    u_root, _ = get_user_folders(current_user.id)
    src, dest = os.path.join(u_root, filename), os.path.join(PUBLIC_ROOT, filename)
    if os.path.exists(src):
        shutil.copy(src, dest)
        db = get_db()
        db['public_meta'][filename] = {"sender": current_user.id, "likes": 0, "liked_by": []}
        save_db(db)
    return redirect('/hub')

@app.route('/delete/<path:filename>')
@login_required
def delete_file(filename):
    u_root, u_trash = get_user_folders(current_user.id)
    src, dest = os.path.join(u_root, filename), os.path.join(u_trash, filename)
    if os.path.exists(src): shutil.move(src, dest)
    return redirect('/')

@app.route('/restore/<path:filename>')
@login_required
def restore_file(filename):
    u_root, u_trash = get_user_folders(current_user.id)
    src, dest = os.path.join(u_trash, filename), os.path.join(u_root, filename)
    if os.path.exists(src): shutil.move(src, dest)
    return redirect('/trash')

@app.route('/download/<path:filename>')
@login_required
def download(filename):
    src_type = request.args.get('src')
    if src_type == 'public': folder = PUBLIC_ROOT
    elif '/trash' in request.referrer: _, folder = get_user_folders(current_user.id)
    else: folder, _ = get_user_folders(current_user.id)
    return send_from_directory(folder, filename)

@app.route('/logout')
def logout():
    logout_user(); return redirect(url_for('login'))

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('10.255.255.255', 1)); IP = s.getsockname()[0]
    except: IP = '127.0.0.1'
    finally: s.close()
    return IP

# --- 5. ENGINE START (UPDATED FOR KOYEB) ---
def start_engine(token=""):
    # Detect if we are on Koyeb by looking for the PORT environment variable
    # If not found, it defaults to 8080
    port = int(os.environ.get("PORT", 8080))
    is_cloud = os.environ.get("PORT") is not None

    if not is_cloud:
        # LOCAL MODE (Your Laptop)
        local_url = f"http://{get_ip()}:5000"
        qr = pyqrcode.create(local_url, error='L', version=None)
        print("\n" + "❤️"*20)
        print(f" 🏠 LOCAL: {local_url}")
        print(qr.terminal(quiet_zone=1)) 
        if token:
            try:
                ngrok.set_auth_token(token)
                public_url = ngrok.connect(5000).public_url
                print(f" 🌍 GLOBAL SOCIAL HUB: {public_url}")
            except Exception as e: print(f" [!] Ngrok Error: {e}")
        print("❤️"*20 + "\n")
        # Run on 5000 locally
        app.run(host='0.0.0.0', port=5000, debug=False)
    else:
        # CLOUD MODE (Koyeb)
        print(f"\n🚀 CLOUD MODE ACTIVE: Listening on Port {port}\n")
        # Run on the port provided by Koyeb (8080)
        app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    MY_TOKEN = "39YXDnpRc0YeJOito0vhQrFSOCX_28ootyWn9kSpNiVKCSZ6Z"
    start_engine(token=MY_TOKEN)