#friend.py 이상원 11.27 업로드 2차

#여기서부터-----------------------------------------------------------------------------
import sqlite3
import streamlit as st

# 데이터베이스 연결 함수
def create_connection():
    conn = sqlite3.connect('zip.db')
    conn.row_factory = sqlite3.Row  # 딕셔너리 형태로 반환
    return conn

# 내 친구 리스트 표시
def show_friend_list(user_id):
    conn = create_connection()
    try:
        cursor = conn.cursor()
        # 친구 목록 가져오기
        query = "SELECT friend_user_id FROM friend WHERE user_id = ?"
        cursor.execute(query, (user_id,))
        friends = cursor.fetchall()
        if friends:
            st.title("내 친구 리스트")
            for friend in friends:
                st.write(f"- {friend['friend_user_id']}")
        else:
            st.write("친구가 없습니다.")
    except sqlite3.Error as e:
        st.error(f"DB 오류: {e}")
    finally:
        conn.close()

# 친구 추가
def add_friend(user_id, friend_id):
    if user_id == friend_id:
        st.error("자신을 친구로 추가할 수 없습니다.")
        return
    conn = create_connection()
    try:
        cursor = conn.cursor()
        # 상대방 존재 확인
        query = "SELECT user_id FROM user WHERE user_id = ?"
        cursor.execute(query, (friend_id,))
        user_exists = cursor.fetchone()
        if not user_exists:
            st.error("없는 ID입니다.")
            return

        # 이미 친구인지 확인
        query = "SELECT * FROM friend WHERE user_id = ? AND friend_user_id = ?"
        cursor.execute(query, (user_id, friend_id))
        already_friends = cursor.fetchone()
        if already_friends:
            st.error("이미 친구입니다.")
            return

        # 친구 요청 중복 확인
        query = "SELECT * FROM myFriendrequest WHERE user_id = ? AND requested_user_id = ?"
        cursor.execute(query, (user_id, friend_id))
        already_requested = cursor.fetchone()
        if already_requested:
            st.error("이미 친구 요청을 보냈습니다.")
            return

        # 친구 요청 등록
        cursor.execute("INSERT INTO myFriendrequest (user_id, requested_user_id) VALUES (?, ?)", (user_id, friend_id))
        cursor.execute("INSERT INTO otherRequest (user_id, requester_user_id) VALUES (?, ?)", (friend_id, user_id))
        conn.commit()
        st.success(f"{friend_id}님에게 친구 요청을 보냈습니다.")
    except sqlite3.Error as e:
        st.error(f"DB 오류: {e}")
    finally:
        conn.close()

# 친구 요청 수락
def accept_friend_request(user_id, requester_id):
    conn = create_connection()
    try:
        cursor = conn.cursor()
        # 친구 요청 확인
        query = "SELECT * FROM otherRequest WHERE user_id = ? AND requester_user_id = ?"
        cursor.execute(query, (user_id, requester_id))
        request_exists = cursor.fetchone()
        if not request_exists:
            st.error("해당 요청이 존재하지 않습니다.")
            return

        # 친구 관계 추가
        cursor.execute("INSERT INTO friend (user_id, friend_user_id) VALUES (?, ?)", (user_id, requester_id))
        cursor.execute("INSERT INTO friend (user_id, friend_user_id) VALUES (?, ?)", (requester_id, user_id))

        # 요청 삭제
        cursor.execute("DELETE FROM otherRequest WHERE user_id = ? AND requester_user_id = ?", (user_id, requester_id))
        conn.commit()
        st.success(f"{requester_id}님과 친구가 되었습니다.")
    except sqlite3.Error as e:
        st.error(f"DB 오류: {e}")
    finally:
        conn.close()

# 차단
def block_friend(user_id, friend_id):
    if user_id == friend_id:
        st.error("자신을 차단할 수 없습니다.")
        return
    
    conn = create_connection()
    try:
        cursor = conn.cursor()
        
        # user 테이블에서 해당 ID 존재 여부 확인
        query = "SELECT user_id FROM user WHERE user_id = ?"
        cursor.execute(query, (friend_id,))
        user_exists = cursor.fetchone()
        
        if not user_exists:
            st.error("없는 ID입니다.")  # 해당 ID가 user 테이블에 없을 경우
            return
        
        # 이미 차단했는지 확인
        query = "SELECT * FROM block WHERE user_id = ? AND blocked_user_id = ?"
        cursor.execute(query, (user_id, friend_id))
        already_blocked = cursor.fetchone()
        
        if already_blocked:
            st.error("이미 차단된 사용자입니다.")
            return

        # 친구 목록에서 삭제 (차단된 경우 친구에서 제거)
        cursor.execute("DELETE FROM friend WHERE user_id = ? AND friend_user_id = ?", (user_id, friend_id))

        # 차단 테이블에 추가
        cursor.execute("INSERT INTO block (user_id, blocked_user_id) VALUES (?, ?)", (user_id, friend_id))
        conn.commit()
        
        st.success(f"{friend_id}님을 차단하였습니다.")
    except sqlite3.Error as e:
        st.error(f"DB 오류: {e}")
    finally:
        conn.close()

# 차단 리스트 출력
def show_blocked_list(user_id):
    conn = create_connection()
    try:
        cursor = conn.cursor()
        query = "SELECT blocked_user_id FROM block WHERE user_id = ?"
        cursor.execute(query, (user_id,))
        blocked_users = cursor.fetchall()
        if blocked_users:
            st.title("차단 목록")
            for blocked in blocked_users:
                st.write(f"- {blocked['blocked_user_id']}")
        else:
            st.write("차단된 사용자가 없습니다.")
    except sqlite3.Error as e:
        st.error(f"DB 오류: {e}")
    finally:
        conn.close()

# 차단 해제
def unblock_friend(user_id, friend_id):
    conn = create_connection()
    try:
        cursor = conn.cursor()
        # 차단된 사용자인지 확인
        query = "SELECT * FROM block WHERE user_id = ? AND blocked_user_id = ?"
        cursor.execute(query, (user_id, friend_id))
        blocked = cursor.fetchone()
        if not blocked:
            st.error("차단된 사용자가 아닙니다.")
            return

        # 차단 해제
        cursor.execute("DELETE FROM block WHERE user_id = ? AND blocked_user_id = ?", (user_id, friend_id))
        conn.commit()
        st.success(f"{friend_id}님을 차단 해제하였습니다.")
    except sqlite3.Error as e:
        st.error(f"DB 오류: {e}")
    finally:
        conn.close()

# 친구 삭제
def delete_friend(user_id, friend_id):
    conn = create_connection()
    try:
        cursor = conn.cursor()
        # 친구인지 확인
        query = "SELECT * FROM friend WHERE user_id = ? AND friend_user_id = ?"
        cursor.execute(query, (user_id, friend_id))
        is_friend = cursor.fetchone()
        if not is_friend:
            st.error("해당 유저는 내 친구 리스트에 없는 유저입니다.")
            return

        # 친구 삭제
        cursor.execute("DELETE FROM friend WHERE user_id = ? AND friend_user_id = ?", (user_id, friend_id))
        conn.commit()
        st.success(f"{friend_id}님을 친구 목록에서 삭제하였습니다.")
    except sqlite3.Error as e:
        st.error(f"DB 오류: {e}")
    finally:
        conn.close()

#여기까지-----------------------------------------------------------------------------