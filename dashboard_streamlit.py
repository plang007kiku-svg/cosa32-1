import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
from datetime import datetime
import hmac

# ========== PASSWORD PROTECTION ==========
def check_password():
    """Returns True if user enters correct password"""
    def password_entered():
        try:
            password_correct = hmac.compare_digest(st.session_state["password"], st.secrets.get("password", "cosa3201"))
        except KeyError:
            password_correct = hmac.compare_digest(st.session_state["password"], "cosa3201")
        
        if password_correct:
            st.session_state["password_correct"] = True
            del st.session_state["password"]
        else:
            st.session_state["password_correct"] = False

    if st.session_state.get("password_correct", False):
        return True

    st.text_input("🔐 Please enter password", type="password", on_change=password_entered, key="password")
    if "password_correct" in st.session_state and not st.session_state["password_correct"]:
        st.error("❌ Password is incorrect")
    return False

# Call this function before everything else
if not check_password():
    st.stop()
# ==========================================

st.set_page_config(page_title="COSA OMEGA ASI v15", layout="wide")
st.title("🛡️ COSA OMEGA ASI v15 – Threat Intelligence Dashboard")
st.caption(f"อัปเดตล่าสุด: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# โหลดข้อมูลจาก DB (หรือ CSV ถ้าจะไม่ให้外人เห็น path)
@st.cache_data
def load_data():
    try:
        conn = sqlite3.connect('cosa_mesh_v15.db')
        df = pd.read_sql_query("SELECT timestamp, ip, country, score, action FROM mesh_events ORDER BY id DESC LIMIT 1000", conn)
        conn.close()
        return df
    except:
        # fallback สำหรับ deploy ครั้งแรก (mock data)
        return pd.DataFrame({
            "timestamp": pd.date_range(start='2026-04-01', periods=10, freq='D'),
            "ip": ["192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.5", "198.51.100.45", 
                   "192.0.2.30", "203.0.113.75", "198.51.100.100", "192.168.1.200", "10.0.0.100"],
            "country": ["Russia", "China", "North Korea", "Iran", "Syria", "Russia", "China", "North Korea", "Russia", "China"],
            "score": [95, 87, 92, 88, 85, 93, 89, 91, 94, 86],
            "action": ["BLOCKED", "MONITORED", "BLOCKED", "MONITORED", "BLOCKED", 
                      "BLOCKED", "MONITORED", "BLOCKED", "BLOCKED", "MONITORED"]
        })

df = load_data()

# สถิติรวม
col1, col2, col3 = st.columns(3)
col1.metric("🌐 Malicious IPs", len(df['ip'].unique()))
col2.metric("🎯 Total Events", len(df))
col3.metric("🚫 Blocked", len(df[df['action'] == 'BLOCKED']))

st.markdown("---")

# กราฟประเทศ
st.subheader("📍 Top Attacker Countries")
country_counts = df['country'].value_counts().reset_index()
country_counts.columns = ['country', 'count']
fig = px.bar(country_counts.head(10), x='country', y='count', color='country', title="Threat Sources by Country")
st.plotly_chart(fig, use_container_width=True)

# กราฟ Score Distribution
st.subheader("📊 Threat Score Distribution")
score_fig = px.histogram(df, x='score', nbins=20, color_discrete_sequence=['#FF6B6B'], title="Threat Score Analysis")
st.plotly_chart(score_fig, use_container_width=True)

# ตาราง (ไม่แสดง IP แบบเต็ม พรางบ้าง)
st.subheader("📋 Recent Events (Anonymized)")
df_display = df.copy()
df_display['ip'] = df_display['ip'].apply(lambda x: x[:5] + '***' if len(x) > 5 else x)
df_display['timestamp'] = pd.to_datetime(df_display['timestamp'])
st.dataframe(df_display[['timestamp', 'ip', 'country', 'score', 'action']], use_container_width=True)

# Sidebar Filters
st.sidebar.subheader("🔍 Filters")
selected_country = st.sidebar.multiselect("Filter by Country", df['country'].unique())
if selected_country:
    df_filtered = df[df['country'].isin(selected_country)]
    st.sidebar.metric("🎯 Filtered Events", len(df_filtered))
    st.sidebar.metric("🚫 Blocked (Filtered)", len(df_filtered[df_filtered['action'] == 'BLOCKED']))

st.markdown("---")
# Footer
st.caption("© 2026 Kriangkrai Khatsom | COSA OMEGA ASI v15 | Data for authorized use only")
st.caption("🔐 Password Protected | Threat Intelligence Dashboard")
