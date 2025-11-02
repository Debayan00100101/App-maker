import streamlit as st
import sqlite3
import bcrypt
import re
import os
import google.generativeai as genai
from io import BytesIO
import base64

# ----------------------------------
# CONFIGURATION
# ----------------------------------
st.set_page_config(
    page_title="Fox - AI Web App Maker",
    page_icon="https://static.vecteezy.com/system/resources/previews/014/918/930/non_2x/fox-unique-logo-design-illustration-fox-icon-logo-fox-icon-design-illustration-vector.jpg",
    layout="wide"
)

DB_FILE = "fox.db"
API_KEY = "AIzaSyBPKJayR9Ozp2t9DRLI9NXPRoiU5VZY6U"
# Developer credentials (email and hashed password)
DEVELOPER_EMAIL = "sachy@fox.ai"
DEVELOPER_PASSWORD_HASH = bcrypt.hashpw("sachy00100101".encode(), bcrypt.gensalt())

# ----------------------------------
# DATABASE FUNCTIONS
# ----------------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
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

def add_user(email, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hashed_pw))
    conn.commit()
    conn.close()

def get_user(email):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT email, password_hash FROM users WHERE email = ?", (email,))
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
    cursor.execute("SELECT email FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    conn.close()
    return users

# Ensure DB initialized properly
if not os.path.exists(DB_FILE):
    init_db()
else:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
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

# ----------------------------------
# AUTHENTICATION UI
# ----------------------------------
def show_login_ui():
    st.title("🦊 Fox AI — App Maker")
    st.subheader("Build and manage your AI-powered web apps")

    if "user" in st.session_state and st.session_state["user"] == DEVELOPER_EMAIL:
        tab1, tab2, tab3 = st.tabs(["Sign In", "Sign Up", "View Users"])
    else:
        tab1, tab2 = st.tabs(["Sign In", "Sign Up"])

    with tab1:
        st.write("### Log in to your Fox account")
        email = st.text_input("Email", placeholder="yourname@fox.ai", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")

        if st.button("Sign In"):
            if email == DEVELOPER_EMAIL:
                # Developer login verification
                if bcrypt.checkpw(password.encode(), DEVELOPER_PASSWORD_HASH):
                    st.session_state["user"] = DEVELOPER_EMAIL
                    log_event(DEVELOPER_EMAIL, "sign-in")
                    st.success(f"Welcome developer {DEVELOPER_EMAIL}!")
                    st.rerun()
                else:
                    st.error("Incorrect password for developer.")
            else:
                if not valid_email(email):
                    st.error("Invalid email format! Must end with @fox.ai")
                else:
                    user = get_user(email)
                    if user:
                        stored_hash = user[1]
                        if bcrypt.checkpw(password.encode(), stored_hash):
                            st.session_state["user"] = email
                            log_event(email, "sign-in")
                            st.success(f"Welcome back, {email.split('@')[0]}!")
                            st.rerun()
                        else:
                            st.error("Incorrect password.")
                    else:
                        st.error("No account found. Please sign up.")

    with tab2:
        st.write("### Create a Fox account")
        new_email = st.text_input("Email (must end with @fox.ai)", placeholder="yourname@fox.ai", key="signup_email")
        new_password = st.text_input("Password", type="password", key="signup_password")

        if st.button("Sign Up"):
            if not valid_email(new_email):
                st.error("Invalid email! Only @fox.ai addresses are allowed.")
            elif len(new_password) < 6:
                st.warning("Password must be at least 6 characters long.")
            else:
                try:
                    add_user(new_email, new_password)
                    log_event(new_email, "sign-up")
                    st.success("Account created successfully! You can now sign in.")
                except sqlite3.IntegrityError:
                    st.warning("This email is already registered.")

    if "user" in st.session_state and st.session_state["user"] == DEVELOPER_EMAIL:
        with tab3:
            st.write("### Registered Users")
            users = fetch_all_users()
            if users:
                for u in users:
                    st.write(u[0])
            else:
                st.info("No registered users yet.")

# ----------------------------------
# MAIN FOX AI APP
# ----------------------------------
def show_fox_ai_app():
    st.sidebar.image("https://static.vecteezy.com/system/resources/previews/014/918/930/non_2x/fox-unique-logo-design-illustration-fox-icon-logo-fox-icon-design-illustration-vector.jpg", width=80)
    st.sidebar.title("Fox AI")
    st.sidebar.success(f"Logged in as {st.session_state['user']}")
    if st.sidebar.button("Log Out"):
        del st.session_state["user"]
        st.rerun()

    st.title("🦊 Fox - AI Web App Maker")
    st.chat_message("ai", avatar="🦊").write(
        "Hi, I'm Fox! I take a bit of time & generate complete web apps instantly!"
    )

    if API_KEY:
        genai.configure(api_key=API_KEY)
    else:
        st.error("Gemini API key missing.")
        return

    version = st.selectbox("Choose Fox Version", ["Pro", "Max"], index=0)
    model_map = {"Pro": "gemini-2.5-flash", "Max": "gemini-2.5-pro"}
    model_name = model_map[version]

    st.subheader("Describe the web app you want to create")
    prompt = st.text_area(
        "Enter your idea",
        placeholder="Example: A weather dashboard with live API data and interactive temperature chart"
    )

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
                    st.download_button(
                        label="Download Web App",
                        data=buffer,
                        file_name="fox_app.html",
                        mime="text/html"
                    )

                except Exception as e:
                    st.error(f"Gemini API Error: {e}")

    st.markdown("---")
    st.caption('Fox - Powered by Gemini • Developed by Debayan Das • Grade 7 • THS Rampurhat, India')

# ----------------------------------
# MAIN APP EXECUTION
# ----------------------------------
if "user" not in st.session_state:
    show_login_ui()
else:
    show_fox_ai_app()

st.write("---")
