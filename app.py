import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

# ตั้งค่า page
st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# โหลดข้อมูลตัวอย่าง (Threat Intelligence Data)
@st.cache_data
def load_data():
    data = {
        "apt_group": ["APT28", "APT28", "Lazarus", "Lazarus", "Darkhotel", "Darkhotel", "APT36", "Seedworm", "APT32", "APT32"],
        "country": ["Russia", "Russia", "North Korea", "North Korea", "Unknown", "Unknown", "Pakistan", "Unknown", "Vietnam", "Vietnam"],
        "lat": [55.7558, 55.7558, 39.019, 39.019, 35.6895, 35.6895, 30.3753, 25.2048, 21.0285, 21.0285],
        "lon": [37.6173, 37.6173, 125.7545, 125.7545, 139.6917, 139.6917, 69.3451, 55.2708, 105.8542, 105.8542],
        "malicious_ips": [1245, 890, 2100, 1850, 567, 432, 789, 345, 1234, 987],
        "zero_day_attempts": [3400, 2100, 5100, 4800, 1200, 900, 2300, 450, 3100, 2700],
        "last_seen": ["2026-04-01", "2026-04-15", "2026-04-10", "2026-04-20", "2026-04-05", "2026-04-18", "2026-04-12", "2026-04-14", "2026-04-08", "2026-04-22"]
    }
    return pd.DataFrame(data)

df = load_data()

# ==================== SIDEBAR ====================
st.sidebar.title("🎛️ ตัวเลือกควบคุม")
st.sidebar.markdown("---")

# Dropdown เลือก APT Group
apt_options = ["ทั้งหมด"] + sorted(df["apt_group"].unique().tolist())
selected_apt = st.sidebar.selectbox("🔍 เลือก APT Group", apt_options)

# Date Range
st.sidebar.markdown("### 📅 ช่วงเวลา")
min_date = pd.to_datetime(df["last_seen"]).min()
max_date = pd.to_datetime(df["last_seen"]).max()
date_range = st.sidebar.date_input(
    "เลือกช่วงวันที่",
    [min_date, max_date],
    min_value=min_date,
    max_value=max_date
)

# Toggle Layer
show_heatmap = st.sidebar.checkbox("🔥 แสดง Heatmap", value=False)

# Dark/Light Mode
theme = st.sidebar.radio("🌓 Theme", ["Dark", "Light"], index=0)

if theme == "Dark":
    st._config.set_option("theme.base", "dark")
else:
    st._config.set_option("theme.base", "light")

# ปุ่ม Download
csv_data = df.to_csv(index=False).encode("utf-8")
st.sidebar.download_button(
    label="📥 ดาวน์โหลดข้อมูล (CSV)",
    data=csv_data,
    file_name=f"threat_data_{datetime.now().strftime('%Y%m%d')}.csv",
    mime="text/csv"
)

st.sidebar.markdown("---")
st.sidebar.caption(f"🛡️ **COSA OMEGA ASI** | อัปเดตล่าสุด: {datetime.now().strftime('%d/%m/%Y %H:%M')}")

# ==================== FILTER DATA ====================
filtered_df = df.copy()

if selected_apt != "ทั้งหมด":
    filtered_df = filtered_df[filtered_df["apt_group"] == selected_apt]

filtered_df["last_seen"] = pd.to_datetime(filtered_df["last_seen"])
if len(date_range) == 2:
    filtered_df = filtered_df[
        (filtered_df["last_seen"] >= pd.to_datetime(date_range[0])) &
        (filtered_df["last_seen"] <= pd.to_datetime(date_range[1]))
    ]

# ==================== MAIN CONTENT ====================
st.title("🛡️ Threat Intelligence Dashboard")
st.caption("ข้อมูลจาก COSA OMEGA ASI + MISP Threat Feed | ตรวจจับ APT และ Zero-day Attacks แบบ Real-time")

# KPI Cards
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🎯 APT Groups ที่ตรวจจับ", filtered_df["apt_group"].nunique())
with col2:
    st.metric("🌐 Malicious IPs", f"{filtered_df['malicious_ips'].sum():,}")
with col3:
    st.metric("💥 Zero-day Attempts", f"{filtered_df['zero_day_attempts'].sum():,}")
with col4:
    st.metric("📍 ประเทศที่เกี่ยวข้อง", filtered_df["country"].nunique())

st.markdown("---")

# ==================== MAP SECTION ====================
st.subheader("🗺️ แผนที่แสดงตำแหน่ง APT และ Malicious Activities")

if show_heatmap:
    fig = px.density_mapbox(
        filtered_df,
        lat="lat",
        lon="lon",
        z="malicious_ips",
        radius=20,
        center={"lat": 20, "lon": 100},
        zoom=2,
        mapbox_style="stamen-terrain",
        title="Heatmap ของ Malicious IPs จำแนกตาม APT Group"
    )
else:
    fig = px.scatter_mapbox(
        filtered_df,
        lat="lat",
        lon="lon",
        size="malicious_ips",
        color="apt_group",
        hover_name="apt_group",
        hover_data={"country": True, "malicious_ips": True, "zero_day_attempts": True},
        size_max=30,
        zoom=2,
        center={"lat": 20, "lon": 100},
        title="ตำแหน่ง APT Groups และขนาดของ Malicious IPs"
    )

fig.update_layout(height=550, margin={"r":0, "t":40, "l":0, "b":0})
fig.update_layout(mapbox_style="open-street-map")

st.plotly_chart(fig, use_container_width=True)

# ==================== DATA TABLE ====================
st.subheader("📋 ข้อมูล Threat Intelligence แบบละเอียด")
st.dataframe(filtered_df, use_container_width=True)

# ==================== BAR CHART ====================
st.subheader("📊 เปรียบเทียบ Zero-day Attempts ตาม APT Group")
bar_fig = px.bar(
    filtered_df.groupby("apt_group")["zero_day_attempts"].sum().reset_index(),
    x="apt_group",
    y="zero_day_attempts",
    color="apt_group",
    title="Zero-day Attempts ต่อ APT Group"
)
st.plotly_chart(bar_fig, use_container_width=True)

st.markdown("---")
st.caption("© 2026 Kriangkrai Khatsom | COSA OMEGA ASI | MISP Admin ID:1 | Data for demonstration only")