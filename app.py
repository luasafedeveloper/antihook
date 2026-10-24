from datetime import datetime, timedelta
import base64, hashlib, hmac, json, os, random, string, time
from flask import Flask, jsonify, request, session, render_template
from flask_sqlalchemy import SQLAlchemy
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# ==========================================
# 🗄️ 데이터베이스 모델 (DB 테이블 구조)
# ==========================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_master = db.Column(db.Boolean, default=False)

class InviteCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False)

class Script(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    lua_code = db.Column(db.Text, nullable=False)

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.String(120), unique=True, nullable=False)
    script_name = db.Column(db.String(120), nullable=False)
    hwid = db.Column(db.String(120), default='UNBOUND')
    ip = db.Column(db.String(50), default='미등록')
    expires_at = db.Column(db.DateTime, nullable=True)

    def is_valid(self):
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

with app.app_context():
    db.create_all()

# ==========================================
# 🌐 1. 화면 라우팅 (HTML 페이지 연결)
# ==========================================
@app.route('/')
def home():
    return render_template('user/index.html')

@app.route('/admin')
def admin_page():
    return render_template('admin/index.html')

@app.route('/master-secret-portal')
def master_page():
    return render_template('master/index.html')

# ==========================================
# 🚨 2. 마스터(Master) 및 인증 API
# ==========================================
@app.route('/api/secret/login', methods=['POST'])
def secret_login():
    data = request.get_json() or {}
    if data.get('username') == app.config['MASTER_ID'] and data.get('password') == app.config['MASTER_PW']:
        session['is_master'] = True
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': '마스터 비밀번호가 틀렸습니다.'}), 401

@app.route('/api/master/invite', methods=['POST'])
def gen_invite():
    if not session.get('is_master'): return jsonify({'success': False}), 403
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
    db.session.add(InviteCode(code=code))
    db.session.commit()
    return jsonify({'success': True, 'code': code})

# ==========================================
# 🚨 3. 관리자(Admin) API
# ==========================================
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    invite = InviteCode.query.filter_by(code=data.get('invite_code'), used=False).first()
    if not invite: return jsonify({'success': False, 'message': '유효하지 않은 코드입니다.'}), 400
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({'success': False, 'message': '이미 존재하는 아이디입니다.'}), 400

    db.session.add(User(username=data.get('username'), password=data.get('password')))
    invite.used = True
    db.session.commit()
    return jsonify({'success': True, 'message': '회원가입 완료!'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    user = User.query.filter_by(username=data.get('username'), password=data.get('password')).first()
    if user:
        session['user_id'] = user.id
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': '아이디/비밀번호 오류'}), 401

@app.route('/api/admin/script', methods=['POST'])
def upload_script():
    if not session.get('user_id'): return jsonify({}), 403
    data = request.get_json() or {}
    script = Script.query.filter_by(owner_id=session['user_id'], name=data.get('name')).first()
    if script: script.lua_code = data.get('lua_code')
    else: db.session.add(Script(owner_id=session['user_id'], name=data.get('name'), lua_code=data.get('lua_code')))
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/admin/key', methods=['POST'])
def gen_key():
    if not session.get('user_id'): return jsonify({}), 403
    data = request.get_json() or {}
    dur = data.get('duration')
    expires = None if dur == 'life' else datetime.utcnow() + timedelta(days=int(dur))
    key_str = f"AH-{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"
    
    db.session.add(Key(owner_id=session['user_id'], key=key_str, script_name=data.get('script_name'), expires_at=expires))
    db.session.commit()
    return jsonify({'success': True, 'key': key_str})

@app.route('/api/admin/keys', methods=['GET'])
def get_keys():
    if not session.get('user_id'): return jsonify([]), 403
    keys = Key.query.filter_by(owner_id=session['user_id']).all()
    return jsonify([{'id': k.id, 'key': k.key, 'script_name': k.script_name, 'ip': k.ip, 'hwid': k.hwid} for k in keys])

@app.route('/api/admin/reset', methods=['POST'])
def reset_key():
    if not session.get('user_id'): return jsonify({}), 403
    data = request.get_json() or {}
    k = Key.query.filter_by(id=data.get('id'), owner_id=session['user_id']).first()
    if k:
        k.hwid = 'UNBOUND'
        k.ip = '미등록'
        db.session.commit()
    return jsonify({'success': True})

# ==========================================
# 🚨 4. 유저(User) API
# ==========================================
@app.route('/api/user/loader', methods=['POST'])
def user_loader():
    data = request.get_json() or {}
    k = Key.query.filter_by(key=data.get('key')).first()
    if not k or not k.is_valid(): return jsonify({'success': False, 'message': '유효하지 않거나 만료된 키입니다.'})
    
    loader_code = f"""-- AntiHook Loader
local key = "{k.key}"
local hwid = tostring(game:GetService("RbxAnalyticsService"):GetClientId())
print("AntiHook 인증 성공! 스크립트를 로드합니다.")"""
    return jsonify({'success': True, 'loader': loader_code})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
