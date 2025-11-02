import streamlit as st
import sqlite3
import bcrypt
import re
import os
import google.generativeai as genai
from io import BytesIO
import base64
import hashlib

st.set_page_config(
    page_title="Fox - AI Web App Maker",
    page_icon="https://static.vecteezy.com/system/resources/previews/014/918/930/non_2x/fox-unique-logo-design-illustration-fox-icon-logo-fox-icon-design-illustration-vector.jpg",
    layout="wide"
)

DB_FILE = "fox.db"
API_KEY = "AIzaSyBPKJayR9PBDHMtPpMAUgz3Y9oXDYZLHWU"
DEVELOPER_GITHUB_USERNAME = "debayan00100101"
FAVORITE_WORD_HASH = hashlib.sha256("super".encode('utf-8')).hexdigest()

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            github_username TEXT,
            password_hash BLOB
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def add_user(email, github_username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (email, github_username, password_hash) VALUES (?, ?, ?)", (email, github_username, hashed_pw))
    conn.commit()
    conn.close()

def get_user(email):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT email, github_username, password_hash FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        return user
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            init_db()
            return None
        else:
            raise

def valid_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@fox\.ai$"
    return re.match(pattern, email)

def log_event(email, action):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO login_logs (email, action) VALUES (?, ?)", (email, action))
    conn.commit()
    conn.close()

def fetch_all_users():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT email, github_username FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    conn.close()
    return users

if not os.path.exists(DB_FILE):
    init_db()
else:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            github_username TEXT,
            password_hash BLOB
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def show_login_ui():
    if "github_username_input" not in st.session_state:
        st.session_state.github_username_input = ""

    st.title("🦊 Fox AI — App Maker")
    st.subheader("Build and manage your AI-powered web apps")

    tabs = ["Sign In", "Sign Up"]
    if st.session_state.get("is_developer", False):
        tabs.append("View Users")
    tab_objs = st.tabs(tabs)

    with tab_objs[0]:
        email = st.text_input("Email", placeholder="yourname@fox.ai", key="login_email")
        github_username = st.text_input("(Optional) GitHub Username", placeholder="your-github-username", key="login_github")
        if st.session_state.github_username_input != github_username:
            st.session_state.github_username_input = github_username

        password = st.text_input("Password", type="password", key="login_password")

        show_fav_word_input = st.session_state.github_username_input == DEVELOPER_GITHUB_USERNAME
        fav_word = ""
        if show_fav_word_input:
            fav_word = st.text_input("If you are the developer, please enter your favorite word:", type="password", key="fav_word_input")

        if st.button("Sign In"):
            if not valid_email(email):
                st.error("Invalid email format! Must end with @fox.ai")
                return
            user = get_user(email)
            if not user:
                st.error("No account found. Please sign up.")
                return
            stored_email, stored_github, stored_hash = user
            if not bcrypt.checkpw(password.encode(), stored_hash):
                st.error("Incorrect password.")
                return
            if show_fav_word_input and fav_word:
                fav_word_hash = hashlib.sha256(fav_word.encode('utf-8')).hexdigest()
                if fav_word_hash != FAVORITE_WORD_HASH:
                    st.error("Wrong favorite word. Access denied.")
                    return
                st.session_state["is_developer"] = True
            else:
                st.session_state["is_developer"] = False

            st.session_state["user"] = email
            st.session_state["github_username"] = github_username or ""
            st.session_state["logged_in"] = True
            log_event(email, "sign-in")
            st.success(f"Welcome back, {email.split('@')[0]}!")
            # Return early to allow rerun to show main app
            return

    with tab_objs[1]:
        with st.form("signup_form"):
            new_email = st.text_input("Email (must end with @fox.ai)", placeholder="yourname@fox.ai", key="signup_email")
            new_github = st.text_input("(Optional) GitHub Username", placeholder="your-github-username", key="signup_github")
            new_password = st.text_input("Password", type="password", key="signup_password")
            submit_signup = st.form_submit_button("Sign Up")
            if submit_signup:
                if not valid_email(new_email):
                    st.error("Invalid email! Only @fox.ai addresses allowed.")
                elif len(new_password) < 6:
                    st.warning("Password must be at least 6 characters long.")
                else:
                    try:
                        add_user(new_email, new_github or "", new_password)
                        log_event(new_email, "sign-up")
                        st.success("Account created successfully! You can now sign in.")
                    except sqlite3.IntegrityError:
                        st.warning("This email is already registered.")

    if st.session_state.get("is_developer", False) and len(tab_objs) == 3:
        with tab_objs[2]:
            st.write("### Registered Users")
            users = fetch_all_users()
            if users:
                for email, github_username in users:
                    st.write(f"Email: {email} | GitHub: {github_username or 'N/A'}")
            else:
                st.info("No registered users yet.")


def show_fox_ai_app():
    st.sidebar.image("https://static.vecteezy.com/system/resources/previews/014/918/930/non_2x/fox-unique-logo-design-illustration-fox-icon-logo-fox-icon-design-illustration-vector.jpg", width=80)
    st.sidebar.title("Fox AI")
    st.sidebar.success(f"Logged in as {st.session_state['user']}")
    if st.sidebar.button("Log Out"):
        for key in ["user", "github_username", "is_developer", "logged_in"]:
            if key in st.session_state:
                del st.session_state[key]
        st.experimental_rerun()

    st.title("🦊 Fox - AI Web App Maker")
    st.chat_message("ai", avatar="🦊").write("Hi, I'm Fox! I take a bit of time & generate complete web apps instantly!")

    if API_KEY:
        genai.configure(api_key=API_KEY)
    else:
        st.error("Gemini API key missing.")
        return

    version = st.selectbox("Choose Fox Version", ["Pro", "Max"], index=0)
    model_map = {"Pro": "gemini-2.5-flash", "Max": "gemini-2.5-pro"}
    model_name = model_map[version]

    st.subheader("Describe the web app you want to create")
    prompt = st.text_area("Enter your idea", placeholder="Example: A weather dashboard with live API data and interactive temperature chart")

    if st.button("Generate Web App"):
        if not prompt.strip():
            st.warning("Please describe your app first.")
        else:
            with st.spinner("🦊 Fox is building your web app..."):
                try:
                    model = genai.GenerativeModel(model_name)
                    full_prompt = f"""
You are Fox, an AI agent that creates full, working web apps using HTML, CSS, and JavaScript.
Task: Generate a complete and functional HTML code in one file.
Requirements:
- Include <html>, <head>, <style>, and <script> sections.
- Use embedded CSS and JS (use external links if needed).
- The app must run directly in a browser.
- Give the most powerful & accurate result to beat DeepSeek AI.
- Output ONLY the HTML code (no explanations or markdown).
User prompt: {prompt}
"""
                    response = model.generate_content(full_prompt)
                    html_code = response.text.strip()

                    st.success("✅ Web app created successfully!")
                    st.subheader("Generated HTML Code")
                    st.code(html_code, language="html")

                    st.subheader("Live Preview")
                    encoded_html = base64.b64encode(html_code.encode()).decode()
                    iframe_html = f'<iframe src="data:text/html;base64,{encoded_html}" width="100%" height="600"></iframe>'
                    st.components.v1.html(iframe_html, height=600)

                    buffer = BytesIO(html_code.encode('utf-8'))
                    st.download_button(label="Download Web App", data=buffer, file_name="fox_app.html", mime="text/html")

                except Exception as e:
                    st.error(f"Gemini API Error: {e}")

if st.session_state.get("logged_in", False):
    show_fox_ai_app()
else:
    show_login_ui()

st.write("---")
