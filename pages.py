import streamlit as st
import sqlite3
import bcrypt
import pages
import secrets
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
import re
from localization import Localization

# 초기화
if 'localization' not in st.session_state:
    st.session_state.localization = Localization(lang ='ko')  # 기본 언어는 한국어로 설정됨
# 현재 언어 설정 초기화
if 'current_language' not in st.session_state:
    st.session_state.current_language = 'ko'  # 기본값으로 한국어 설정

localization = st.session_state.localization

# 데이터베이스 연결 함수
def create_connection():
    conn = sqlite3.connect('zip.db')
    conn.row_factory = sqlite3.Row  # 결과를 딕셔너리 형식으로 반환
    return conn


# UserVO (사용자 정보 클래스)
class UserVO:
    def __init__(self, user_id='', user_password='', user_email='', user_seq=None, user_is_online=False):
        self.user_id = user_id
        self.user_password = user_password
        self.user_email = user_email
        self.user_seq = user_seq
        self.user_is_online = user_is_online


# UserDAO (데이터베이스 연동 클래스)
class UserDAO:
    # 아이디 중복 체크
    def check_user_id_exists(self, user_id):
        connection = create_connection()
        try:
            cursor = connection.cursor()
            query = "SELECT * FROM user WHERE user_id = ?"
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()
            return result is not None
        except sqlite3.Error as e:
            st.error(f"DB 오류: {e}")
        finally:
            connection.close()

    # user_id로 사용자 정보를 가져온다
    def search_user(self, user_id):
        connection = create_connection()
        try:
            cursor = connection.cursor()
            query = "SELECT * FROM user WHERE user_id = ?"
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()
            return result
        except sqlite3.Error as e:
            st.error(f"DB 오류: {e}")
        finally:
            connection.close()

    # 비밀번호 해싱 및 사용자 추가
    def insert_user(self, user):
        connection = create_connection()

        # 비밀번호 해싱 (bcrypt 사용)
        hashed_password = bcrypt.hashpw(user.user_password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor = connection.cursor()
            query = "INSERT INTO user (user_id, user_password, user_email, user_is_online) VALUES (?, ?, ?, 0)"
            cursor.execute(query, (user.user_id, hashed_password, user.user_email))
            connection.commit()
        except sqlite3.IntegrityError as e:  # UNIQUE 제약 조건으로 발생하는 오류 처리
            if "user_email" in str(e):
                st.error(localization.get_text("email_in_use_error"))
            elif "user_id" in str(e):
                st.error(localization.get_text("id_in_use_error"))
            else:
                st.error(localization.get_text("signup_unknown_error"))
            return  # 예외 발생 시 함수 종료
        except sqlite3.Error as e:
            st.error(localization.get_text("db_error").format(error=e))
            return  # 예외 발생 시 함수 종료
        finally:
            connection.close()

        # 회원가입 성공 메시지 (오류가 없을 경우에만 실행)
        st.success(localization.get_text("signup_success"))


    # 해시알고리즘을 이용하여 비밀번호 일치 확인
    def check_password(self, hashed_password, plain_password):
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

    def update_user_online(self, user_id, is_online):
        connection = create_connection()
        try:
            cursor = connection.cursor()
            query = "UPDATE user SET user_is_online = 1 WHERE user_is_online=? user_id = ?"
            cursor.execute(query, (user_id, is_online))
            connection.commit()
        except sqlite3.Error as e:
            st.error(localization.get_text("db_error").format(error=e))
        finally:
            connection.close()


# 회원가입 처리 클래스
class SignUp:
    def __init__(self, user_id, user_password, user_email):
        self.user = UserVO(user_id=user_id, user_password=user_password, user_email=user_email)

    def sign_up_event(self):
        dao = UserDAO()
        dao.insert_user(self.user)

    def check_length(self):
        if len(self.user.user_password) < 8:
            st.error(localization.get_text("password_min_length_error"))
            return False
        return True

    def check_user(self):
        dao = UserDAO()
        if dao.check_user_id_exists(self.user.user_id):
            st.error(localization.get_text("id_in_use_error"))
            return False
        return True

    def validate_email(self, email):
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            st.error(localization.get_text("invalid_email_error"))
            return False
        return True


# 로그인 처리 클래스
class SignIn:
    def __init__(self, user_id, user_password):
        self.user_id = user_id
        self.user_password = user_password
        self.user_is_online = 0

    def sign_in_event(self):
        dao = UserDAO()
        result = dao.search_user(self.user_id)

        if result:
            # 저장된 해시된 비밀번호 가져오기
            stored_hashed_password = result['user_password']  # result는 딕셔너리 형태
            if dao.check_password(stored_hashed_password, self.user_password):  # bcrypt로 비밀번호 비교
                st.session_state["user_id"] = self.user_id  # 로그인 성공 시 세션에 user_id 저장
                self.user_is_online = 1
                pages.change_page('after_login')
                return True
            else:
                st.error(localization.get_text("wrong_password_error"))
        else:
            st.error(localization.get_text("id_not_found_error"))
        return False

    def log_out_event(self):
        # This can be triggered by a logout button
        if st.button(localization.get_text("logout_button"), key="logout_button"):
            dao = UserDAO()
            dao.update_user_online(st.session_state["user_id"], 0)  # Set is_online to 0 in D
            st.session_state.user_id = ''  # Clear the session variable
            st.session_state.user_password = ''
            st.warning(localization.get_text("logout_success"))
            pages.change_page('Home')


class UserManager:
    def __init__(self,smtp_email, smtp_password):

        self.smtp_email = smtp_email
        self.smtp_password = smtp_password

    def create_connection(self):
        conn = sqlite3.connect('zip.db')
        conn.row_factory = sqlite3.Row  # 결과를 딕셔너리 형식으로 반환
        return conn

    def is_email_registered(self, email):

        connection = self.create_connection()
        if not connection:
            return None

        try:
            cursor = connection.cursor()
            query = "SELECT * FROM user WHERE user_email = ?"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            return result
        except sqlite3.Error as e:
            st.error(f"DB 오류: {e}")
            return None
        finally:
            connection.close()

    def generate_token(self, length=16):

        characters = string.ascii_letters + string.digits
        return ''.join(secrets.choice(characters) for _ in range(length))

    def send_recovery_email(self, email):

        token = self.generate_token()  # 토큰 생성
        subject = "Password Recovery Token"
        body = (
            f"안녕하세요,\n\n"
            f"비밀번호 복구 요청이 접수되었습니다. 아래의 복구 토큰을 사용하세요:\n\n"
            f"{token}\n\n"
            f"이 요청을 본인이 하지 않은 경우, 이 이메일을 무시해 주세요."
        )

        # MIME 메시지 생성
        msg = MIMEMultipart()
        msg['From'] = Header(self.smtp_email, 'utf-8')  # 발신자 이메일
        msg['To'] = Header(email, 'utf-8')  # 수신자 이메일
        msg['Subject'] = Header(subject, 'utf-8')  # 제목 UTF-8 인코딩
        msg.attach(MIMEText(body, 'plain', 'utf-8'))  # 본문 UTF-8 인코딩

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as connection:
                connection.starttls()  # 암호화 시작
                connection.login(user=self.smtp_email, password=self.smtp_password)  # 로그인
                connection.sendmail(from_addr=self.smtp_email, to_addrs=email, msg=msg.as_string())  # 이메일 전송
            print(f"Recovery email sent to {email}.")
        except smtplib.SMTPException as e:
            print(f"Failed to send email: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def generate_token(self):

        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))
