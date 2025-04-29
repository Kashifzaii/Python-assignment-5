# --- Secure Data Encryption System (Superhero Upgraded) ---

import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
import base64

# Path to save encrypted data
DATA_FILE = "stored_data.json"

# ------------------- Utility Functions -------------------

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    else:
        return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    try:
        key = generate_key_from_passkey(passkey)
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_text.encode()).decode()
        return decrypted
    except Exception:
        return None

def generate_data_id():
    import uuid
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

# ------------------- Session Init -------------------
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"

stored_data = load_data()

# ------------------- Streamlit UI -------------------

st.set_page_config(page_title="🔒 Secure Data Encryption System", layout="centered")
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Failed attempts lockout
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("🔒 Too many failed attempts! Reauthorization required.")

# ------------------- Pages -------------------

if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome Home")
    st.write("Securely **encrypt and retrieve** your sensitive data.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data", use_container_width=True):
            st.session_state.current_page = "Store Data"
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            st.session_state.current_page = "Retrieve Data"

    st.info(f"🔐 Stored entries: {len(stored_data)}")

elif st.session_state.current_page == "Store Data":
    st.subheader("📂 Store Secure Data")
    
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Set a Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match!")
            else:
                with st.spinner("Encrypting and Saving..."):
                    data_id = generate_data_id()
                    hashed_passkey = hash_passkey(passkey)
                    encrypted_text = encrypt_data(user_data, passkey)

                    stored_data[data_id] = {
                        "encrypted_text": encrypted_text,
                        "passkey": hashed_passkey
                    }
                    save_data(stored_data)

                st.success("✅ Data encrypted and saved successfully!")
                st.code(data_id, language="text")
                st.caption("⚡ Save this Data ID to retrieve your data later!")

elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔍 Retrieve Secure Data")

    attempts_left = 3 - st.session_state.failed_attempts
    st.info(f"Attempts left: {attempts_left}")

    data_id = st.text_input("Enter your Data ID:")
    passkey = st.text_input("Enter your Passkey:", type="password")

    if st.button("Decrypt Data"):
        if data_id and passkey:
            if data_id in stored_data:
                stored_entry = stored_data[data_id]
                if stored_entry["passkey"] == hash_passkey(passkey):
                    decrypted_text = decrypt_data(stored_entry["encrypted_text"], passkey)
                    if decrypted_text:
                        st.success("✅ Decryption successful!")
                        st.code(decrypted_text, language="text")
                        reset_failed_attempts()
                    else:
                        st.error("❌ Decryption failed!")
                else:
                    st.session_state.failed_attempts += 1
                    st.session_state.last_attempt_time = time.time()
                    st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
            else:
                st.error("❌ Data ID not found!")
        else:
            st.error("⚠️ Please enter both Data ID and Passkey.")

elif st.session_state.current_page == "Login":
    st.subheader("🔑 Reauthorization Required")

    if time.time() - st.session_state.last_attempt_time < 10 and st.session_state.failed_attempts >= 3:
        remaining_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"🕒 Wait {remaining_time} seconds before trying again.")
    else:
        login_pass = st.text_input("Enter Admin Password:", type="password")
        if st.button("Login"):
            # Ideally, load from Streamlit Secrets
            MASTER_PASSWORD = "admin123"
            if login_pass == MASTER_PASSWORD:
                reset_failed_attempts()
                st.success("✅ Login successful!")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("❌ Incorrect password!")

# Footer
st.markdown("---")
st.caption("🔒 Built for Secure Data Storage | Streamlit Hero Version")
