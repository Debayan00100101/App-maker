import streamlit as st
import google.generativeai as genai
from io import BytesIO
import base64

# -------------------------------
# App Setup
# -------------------------------
st.set_page_config(page_title="Fox - AI Web App Maker", layout="wide")

st.title("🦊 Fox - AI Web App Maker")
st.chat_message("ai",avatar="🦊").write("Hi, I'm fox I take a bit time & Generate and preview complete web apps instantly!")

# -------------------------------
# Gemini API Setup
# -------------------------------
api_key = st.text_input("Enter your Gemini API Key", type="password")
if api_key:
    genai.configure(api_key=api_key)

# -------------------------------
# Version Selector
# -------------------------------
version = st.selectbox("Choose Fox Version", ["Pro", "Max"], index=0)

model_map = {
    "Pro": "gemini-2.5-flash",
    "Max": "gemini-2.5-pro"
}

model_name = model_map[version]

# -------------------------------
# App Creation Prompt
# -------------------------------
st.subheader("Describe the web app you want to create")
prompt = st.text_area(
    "Enter your idea",
    placeholder="Example: A weather dashboard with live API data and interactive temperature chart"
)

if st.button("Generate Web App"):
    if not api_key:
        st.error("Please enter your Gemini API Key first.")
    elif not prompt.strip():
        st.warning("Please describe your app first.")
    else:
        with st.spinner("🦊 Fox is building your web app..."):
            model = genai.GenerativeModel(model_name)
            full_prompt = f"""
You are Fox, an AI agent that creates full, working web apps using HTML, CSS, and JavaScript.

Task: Generate a complete and functional HTML code in one file.
Requirements:
- Include <html>, <head>, <style>, and <script> sections.
- Use embedded CSS and JS (no external links).
- The app must run directly in a browser.
- Output ONLY the HTML code (no explanations or markdown).

User prompt: {prompt}
"""
            response = model.generate_content(full_prompt)
            html_code = response.text.strip()

            # Display generated code
            st.success("✅ Web app created successfully!")
            st.subheader("Generated HTML Code")
            st.code(html_code, language="html")

            # -------------------------------
            # Live Preview (iframe)
            # -------------------------------
            st.subheader("Live Preview")
            encoded_html = base64.b64encode(html_code.encode()).decode()
            iframe_html = f'<iframe src="data:text/html;base64,{encoded_html}" width="100%" height="600"></iframe>'
            st.components.v1.html(iframe_html, height=600)

            # -------------------------------
            # Download Option
            # -------------------------------
            buffer = BytesIO(html_code.encode('utf-8'))
            st.download_button(
                label="💾 Download Web App",
                data=buffer,
                file_name="fox_app.html",
                mime="text/html"
            )

# -------------------------------
# Footer
# -------------------------------
st.markdown("---")
st.caption("Fox - AI Web App Maker • Powered by Gemini • Developed by Debayan")

