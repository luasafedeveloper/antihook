from flask import Flask, render_template, request, session, jsonify
# ... (중략: 이전에 드린 DB 모델과 보안 함수들은 그대로 유지) ...

app = Flask(__name__)
# ...

# 🚨 화면 라우팅 연결
@app.route('/')
def home():
    return render_template('user/index.html')

@app.route('/admin')
def admin_page():
    return render_template('admin/index.html')

@app.route('/master-secret-portal')
def master_page():
    return render_template('master/index.html')

# ... (이하 API 라우트 및 서버 실행부는 이전 코드와 동일) ...
