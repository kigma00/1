# Flask 및 기타 필요한 라이브러리들 가져옴
from flask import Flask, send_file, send_from_directory, render_template, request, jsonify, redirect, url_for, flash, session
import os
import subprocess
from glob import glob
import zipfile
from zipfile import ZipFile
import tempfile
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
from datetime import datetime
import threading
import time
import uuid  # uuid 모듈을 가져옴
from flask import Flask, render_template, request, redirect, url_for
import requests
import base64

# Flask 애플리케이션을 초기화
app = Flask(__name__)
app.secret_key = 'secret_key'  # 세션을 보호하기 위한 비밀 키 설정

# 세션을 검증하는 함수
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:  # 세션에 사용자 정보가 없으면
            flash('로그인이 필요합니다.')  # 로그인 필요 메시지를 표시하고
            return redirect(url_for('login'))  # 로그인 페이지로 리디렉션
        return f(*args, **kwargs)
    return decorated_function

# 데이터베이스를 초기화하는 함수
def init_db():
    conn = sqlite3.connect('database.db')  # 데이터베이스에 연결
    cursor = conn.cursor()  # 커서를 생성
    
    # 사용자 테이블을 생성
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    
    # scan_logs 테이블을 생성
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id TEXT PRIMARY KEY,
            date TEXT,
            start_time TEXT,
            end_time TEXT,
            repo_name TEXT,
            csv_path TEXT,
            status TEXT
        )
    ''')

    conn.commit()  # 변경사항 커밋

    # 관리자 계정이 있는지 확인
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    admin = cursor.fetchone()
    
    # 관리자 계정이 없으면 생성
    if not admin:
        hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')  # 비밀번호 해시
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', hashed_password))
        conn.commit()  # 관리자 계정을 생성하고 커밋

    conn.close()  # 데이터베이스 연결 닫음
init_db()  # 데이터베이스 초기화 실행

# 회원가입 페이지와 회원가입 요청을 처리
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':  # POST 요청을 받으면
        username = request.form['username']  # 사용자 이름을 폼에서 가져옴
        password = request.form['password']  # 비밀번호를 폼에서 가져옴
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')  # 비밀번호를 해시

        conn = sqlite3.connect('database.db')  # 데이터베이스에 연결
        cursor = conn.cursor()  # 커서를 생성
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()  # 새로운 사용자를 추가하고 커밋
        except sqlite3.IntegrityError:
            error = '이미 존재하는 사용자 이름입니다. 다른 이름을 사용해주세요.'  # 사용자 이름이 중복되면 에러 메시지를 설정
            return render_template('register.html', error=error)
        finally:
            conn.close()  # 데이터베이스 연결 닫음

        flash('회원가입이 성공적으로 완료되었습니다. 로그인 해주세요.')  # 성공 메시지를 플래시
        return redirect(url_for('login'))  # 로그인 페이지로 리디렉션
    return render_template('register.html')  # 회원가입 페이지를 렌더링

# 로그인 페이지와 로그인 요청을 처리
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # POST 요청을 받으면
        username = request.form['username']  # 사용자 이름을 폼에서 가져옴
        password = request.form['password']  # 비밀번호를 폼에서 가져옴

        conn = sqlite3.connect('database.db')  # 데이터베이스에 연결
        cursor = conn.cursor()  # 커서 생성
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))  # 사용자 이름으로 사용자를 검색
        user = cursor.fetchone()  # 사용자 정보를 가져옴
        conn.close()  # 데이터베이스 연결을 닫음

        if user and check_password_hash(user[2], password):  # 사용자가 존재하고 비밀번호가 일치하면
            session['username'] = user[1]  # 세션에 사용자 이름을 저장
            if user[1] == 'admin':
                return redirect(url_for('admin_dashboard'))  # 관리자는 관리자 대시보드로 리디렉션
            flash('성공적으로 로그인되었습니다!')  # 성공 메시지를 플래시
            return render_template('index.html')  # 메인 페이지를 렌더링
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다. 다시 시도해주세요.')  # 실패 메시지를 플래시
            return redirect(url_for('login'))  # 로그인 페이지로 리디렉션
    return render_template('login.html')  # GET 요청이면 로그인 페이지를 렌더링

# 관리자 대시보드 페이지
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if 'username' in session and session['username'] == 'admin':  # 세션에 관리자 정보가 있으면
        conn = sqlite3.connect('database.db')  # 데이터베이스에 연결
        cursor = conn.cursor()  # 커서를 생성
        cursor.execute('SELECT username, password FROM users')  # 모든 사용자 정보를 가져옴
        users = cursor.fetchall()  # 사용자 정보를 가져옴
        conn.close()  # 데이터베이스 연결을 닫음
        return render_template('admin_dashboard.html', users=users)  # 관리자 대시보드를 렌더링 함
    else:
        return redirect(url_for('login'))  # 관리자가 아니면 로그인 페이지로 리디렉션

# 사용자를 삭제하는 엔드포인트
@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if 'username' in session and session['username'] == 'admin':  # 세션에 관리자 정보가 있으면
        username = request.form['username']  # 삭제할 사용자 이름을 폼에서 가져옴
        
        if username == 'admin':
            flash('관리자 계정은 삭제할 수 없습니다.', 'danger')  # 관리자는 삭제할 수 없다는 메시지를 플래시
            return redirect(url_for('admin_dashboard'))  # 관리자 대시보드로 리디렉션
        
        conn = sqlite3.connect('database.db')  # 데이터베이스에 연결
        cursor = conn.cursor()  # 커서를 생성
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))  # 사용자를 삭제
        conn.commit()  # 변경사항을 커밋
        conn.close()  # 데이터베이스 연결을 닫음
        
        flash('사용자가 성공적으로 삭제되었습니다.', 'success')  # 성공 메시지를 플래시
        return redirect(url_for('admin_dashboard'))  # 관리자 대시보드로 리디렉션
    else:
        return redirect(url_for('login'))  # 관리자가 아니면 로그인 페이지로 리디렉션

# 로그아웃 엔드포인트
@app.route('/logout')
def logout():
    session.pop('username', None)  # 세션에서 사용자 이름을 제거
    flash('성공적으로 로그아웃되었습니다.')  # 성공 메시지를 플래시
    return redirect(url_for('login'))  # 로그인 페이지로 리디렉션

# 맨 처음 초기 라우팅
@app.route('/')
def index():
    return render_template('login.html')  # 로그인 페이지를 렌더링 함

# 저장소 URL을 처리하는 엔드포인트
@app.route('/process_url', methods=['POST'])
@login_required
def process_url():
    repository_url = request.form['repository_url']  # 폼에서 저장소 URL을 가져 옴
    language = request.form['language']  # 폼에서 언어를 가져옴
    unique_id = str(uuid.uuid4())  # 고유 ID 생성
    current_time = datetime.now()
    start_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    repo_name = repository_url.split('/')[-1]  # 저장소 이름 추출
    csv_path = f'/home/codevuln/target-repo/{repo_name}/scan_result/semgrep.csv'  # CSV 결과 경로 설정

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # 스캔 로그를 데이터베이스에 저장
    cursor.execute('''
        INSERT INTO scan_logs (id, date, start_time, repo_name, csv_path, status)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (unique_id, current_time.strftime('%Y-%m-%d'), start_time, repo_name, csv_path, 'inprogress'))
    conn.commit()
    conn.close()

    command = ['./scripts/query-setting.sh', repository_url, language]  # 실행할 명령어 설정
    
    # 스캔 작업을 비동기로 처리하는 함수
    def run_scan(command, unique_id, csv_path):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            print(f"Running command: {command}")  # 디버그 출력
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            print(f"Command output: {result.stdout}")  # 명령어 출력
            if os.path.exists(csv_path):
                print(f"CSV path exists: {csv_path}")  # 디버그 출력
                cursor.execute('UPDATE scan_logs SET status = ? WHERE id = ?', ('done', unique_id))
            else:
                print(f"CSV path does not exist: {csv_path}")  # 디버그 출력
        except subprocess.CalledProcessError as e:
            print(f"CalledProcessError: {e}")  # 오류가 발생하면 출력
            cursor.execute('UPDATE scan_logs SET status = ? WHERE id = ?', ('failed', unique_id))
        except Exception as e:
            print(f"Exception: {e}")  # 일반 예외 출력
            cursor.execute('UPDATE scan_logs SET status = ? WHERE id = ?', ('failed', unique_id))
        finally:
            end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('UPDATE scan_logs SET end_time = ? WHERE id = ?', (end_time, unique_id))
            conn.commit()  # 변경사항 저장
            conn.close()

    # 스캔 작업을 별도의 스레드에서 실행
    scan_thread = threading.Thread(target=run_scan, args=(command, unique_id, csv_path))
    scan_thread.start()

    return render_template('run_query.html', scan_id=unique_id)  # scan_id를 템플릿으로 전달

# 주기적으로 상태를 확인하는 엔드포인트
@app.route('/check_process/<scan_id>', methods=['GET'])
@login_required
def check_process(scan_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT status FROM scan_logs WHERE id = ?', (scan_id,))
    status = cursor.fetchone()
    conn.close()

    if status and status[0] == 'done':
        return jsonify({"status": "done", "redirect": url_for('ok')})  # 완료 상태를 반환
    elif status and status[0] == 'failed':
        return jsonify({"status": "failed"})  # 실패 상태를 반환
    else:
        return jsonify({"status": "inprogress"}), 204  # 진행 중 상태를 반환

# 설정 페이지를 처리
@app.route('/setting')
@login_required
def settings():
    return render_template('setting.html')  # 설정 페이지를 렌더링

# 쿼리 실행을 시작하는 엔드포인트
@app.route('/run_query')
@login_required
def run_query():
    return render_template('run_query.html')  # 쿼리 실행 페이지를 렌더링

# 파일들을 압축하는 유틸리티 함수
def create_zip(files, directory):
    zip_filename = os.path.join(tempfile.gettempdir(), os.path.basename(directory) + '.zip')  # 임시 디렉토리에 압축 파일 경로를 설정
    with zipfile.ZipFile(zip_filename, 'w') as zipf:  # 압축 파일을 열음
        for file in files:
            zipf.write(file, arcname=os.path.basename(file))  # 파일을 압축 파일에 추가
    return zip_filename  # 압축 파일 경로를 반환

@app.route('/download/scan_result/<scan_id>')
@login_required
def download_scan_result(scan_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT repo_name FROM scan_logs WHERE id = ?', (scan_id,))
    result = cursor.fetchone()
    conn.close()

    if result is None:
        flash('Invalid scan ID.', 'danger')
        return redirect(url_for('index'))
    
    repo_name = result[0]
    print(f"Repo Name: {repo_name}")  # 디버깅을 위해 repo_name 출력

    target_directory = f'/home/codevuln/target-repo/{repo_name}/scan_result'  # 스캔 결과 디렉토리 경로를 설정
    zip_filename = f'/tmp/{repo_name}_result.zip'  # 임시 디렉토리에 압축 파일 이름을 설정

    # 디버깅 출력
    print(f"Target Directory: {target_directory}")
    print(f"Zip Filename: {zip_filename}")

    # 타겟 디렉토리의 파일 목록 출력 (디버깅)
    if os.path.exists(target_directory):
        print(f"Directory exists: {target_directory}")
    else:
        print(f"Directory does not exist: {target_directory}")

    for foldername, subfolders, filenames in os.walk(target_directory):
        print(f"Found directory: {foldername}")
        for filename in filenames:
            print(f"File: {filename}")

    try:
        with ZipFile(zip_filename, 'w') as zipf:  # 압축 파일을 염
            for foldername, subfolders, filenames in os.walk(target_directory):  # 디렉토리를 순회
                for filename in filenames:
                    file_path = os.path.join(foldername, filename)  # 파일 경로를 설정
                    arcname = os.path.relpath(file_path, target_directory)  # 압축 파일 내부 경로 설정
                    zipf.write(file_path, arcname)  # 파일을 압축 파일에 추가

        print(f"Zip file created: {zip_filename}")
        return send_file(zip_filename, as_attachment=True)  # 압축 파일을 클라이언트에게 전송
    except Exception as e:
        print(f"Error creating zip file: {e}")
        flash('Error creating zip file.', 'danger')
        return redirect(url_for('index'))

# 작업 완료 후 보여주는 페이지
@app.route('/ok')
@login_required
def ok():
    return render_template('ok.html')  # 완료 페이지를 렌더링

@app.route('/submit', methods=['POST'])
def submit_form():
    GoCD_pipeline = request.form['GoCD_pipeline']
    GoCD_giturl = request.form['GoCD_giturl']
    test_shell_script = request.form['test_shell_script']
    GoCD_group = request.form['GoCD_group']
    Github_owner = request.form['Github_owner']
    Github_repo = request.form['Github_repo']
    Github_token = request.form['Github_token']
    
    # 제공된 코드 문자열
    code_string = f"""
import requests
import base64
import json
import urllib3

http = urllib3.PoolManager()

def send_slack_message():
    slack_webhook_url = "https://hooks.slack.com/services/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"

    # 메시지 내용 설정
    message_content = "GoCD 파이프라인 생성"

    # 슬랙 메시지 생성
    slack_message = {{
        "text": message_content
    }}

    # 슬랙으로 메시지 전송
    try:
        encoded_message = json.dumps(slack_message).encode('utf-8')
        response = http.request('POST', slack_webhook_url, body=encoded_message, headers={{'Content-Type': 'application/json'}})
        print(f"Response status: {{response.status}}")
        print(f"Response data: {{response.data.decode('utf-8')}}")
    except Exception as e:
        print(f"Error sending message to Slack: {{e}}")
        return {{
            'statusCode': 500,
            'body': f"Error sending message to Slack: {{e}}"
        }}

    return {{
        'statusCode': response.status,
        'body': response.data.decode('utf-8')
    }}

def update_github_config():
    # GoCD 설정 입력받기
    GoCD_pipeline = "{GoCD_pipeline}"  # GoCD 파이프라인 이름
    GoCD_giturl = "{GoCD_giturl}"  # Git 저장소 URL
    test_shell_script = "{test_shell_script}"  # 파이프라인에서 실행할 셸 스크립트
    GoCD_group = "{GoCD_group}"  # GoCD 그룹 이름

    # GitHub 저장소 업데이트 설정 입력받기
    Github_owner = "{Github_owner}"  # GitHub 소유자 (사용자명 또는 조직명)
    Github_repo = "{Github_repo}"  # GitHub 저장소 이름
    Github_token = "{Github_token}"  # GitHub 개인 액세스 토큰
    Github_path = f"{{GoCD_pipeline}}.gocd.yaml"  # GitHub 저장소에 저장할 YAML 파일 경로

    # YAML 파일 생성
    template = f'''
    format_version: 10
    pipelines:
      {{GoCD_pipeline}}:
        group: {{GoCD_group}}
        label_template: ${{{COUNT}}}
        lock_behavior: none
        display_order: -1
        materials:
          git:
              git: {{GoCD_giturl}}
              shallow_clone: false
              auto_update: true
              branch: main
        stages:
        - {{GoCD_pipeline}}_stage:
            fetch_materials: true
            keep_artifacts: false
            clean_workspace: false
            approval:
              type: success
              allow_only_on_success: false
            jobs:
              {{GoCD_pipeline}}_job:
                timeout: 0
                tasks:
                - exec:
                    command: {{test_shell_script}}
                    run_if: passed
    '''

    # GitHub API에 업데이트 요청
    url = f'https://api.github.com/repos/{{Github_owner}}/{{Github_repo}}/contents/temp/{{Github_path}}'

    # 요청 헤더 설정
    headers = {{
        'Authorization': f'token {{Github_token}}',  # 인증 토큰
        'Content-Type': 'application/yaml',  # 콘텐츠 유형
        'Accept': 'application/vnd.github.v3+json'  # GitHub API 버전
    }}

    # 파일 상태 조회
    response_get = requests.get(url, headers=headers)

    # 파일이 존재하는 경우 SHA 값을 추출
    if response_get.status_code == 200:
        sha = response_get.json()['sha']
    else:
        sha = None

    # 파일 내용을 base64로 인코딩
    content_encoded = base64.b64encode(template.encode('utf-8')).decode('utf-8')

    # GitHub API 요청 데이터 (SHA 값을 포함하여 업데이트하는 경우)
    data = {{
        "message": f"Update {{Github_path}}",  # 커밋 메시지
        'content': content_encoded  # 인코딩된 파일 내용
    }}

    if sha:
        data['sha'] = sha  # 기존 파일의 SHA 값 추가

    # 파일 생성 또는 수정 요청
    response = requests.put(url, headers=headers, json=data)

    # 응답 출력
    if response.status_code in [200, 201]:
        print("File created or updated successfully.")  # 파일 생성 또는 업데이트 성공
    else:
        print(f"Error: {{response.status_code}} - {{response.text}}")  # 오류 발생 시 메시지 출력

if __name__ == "__main__":
    update_github_config()  # GitHub 설정 업데이트
    result = send_slack_message()  # Slack 메시지 전송
    print(result)
    """

    # GitHub에 파일 업로드
    github_url = f'https://api.github.com/repos/{Github_owner}/{Github_repo}/contents/app.py'
    headers = {
        'Authorization': f'token {Github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    # 파일 상태 조회
    response_get = requests.get(github_url, headers=headers)
    if response_get.status_code == 200:
        sha = response_get.json()['sha']
    else:
        sha = None

    # 파일 내용을 base64로 인코딩
    content_encoded = base64.b64encode(code_string.encode('utf-8')).decode('utf-8')

    data = {
        "message": "Add app.py with provided code",
        'content': content_encoded
    }

    if sha:
        data['sha'] = sha

    response = requests.put(github_url, headers=headers, json=data)
    if response.status_code in [200, 201]:
        return "File created or updated successfully."
    else:
        return f"Error: {response.status_code} - {response.text}"

@app.route('/gocd')
def gocd():
    return render_template('gocd.html')  # 설정 페이지를 렌더링

# 애플리케이션을 0.0.0.0:80에서 실행
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)  # 애플리케이션을 0.0.0.0:80에서 실행
