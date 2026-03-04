import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import json
import time

# ================= CONFIG =================

BACKEND_URL = "https://secure-coldchain.onrender.com"

st.set_page_config(
    page_title="Secure Cold Chain Monitor",
    page_icon="❄️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ================= CUSTOM CSS =================

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .violation-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .success-card {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 1rem 2rem;
        font-size: 1.1rem;
    }
</style>
""", unsafe_allow_html=True)

# ================= HELPER FUNCTIONS =================

def fetch_logs(device_id):
    """Fetch all logs for a device"""
    try:
        response = requests.get(
            f"{BACKEND_URL}/logs",
            params={"device_id": device_id},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        st.error(f"Error fetching logs: {str(e)}")
        return []

def parse_event(event_string):
    """Parse event string into structured data"""
    parts = event_string.split("|")
    parsed = {"type": parts[0] if parts else "UNKNOWN"}
    
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            parsed[key] = value
    
    return parsed

def get_violation_stats(logs):
    """Calculate violation statistics"""
    violations = [l for l in logs if l.get("event_type") == "EVENT_VIOLATION"]
    warnings = [l for l in logs if l.get("event_type") == "EVENT_WARNING"]
    
    violation_types = {}
    for v in violations:
        parsed = parse_event(v["event"])
        v_type = parsed["type"]
        violation_types[v_type] = violation_types.get(v_type, 0) + 1
    
    return {
        "total_violations": len(violations),
        "total_warnings": len(warnings),
        "anchored": len([v for v in violations if v.get("is_anchored")]),
        "types": violation_types
    }

def create_timeline_chart(logs):
    """Create timeline visualization of events"""
    if not logs:
        return None
    
    # Parse events
    events_data = []
    for log in logs:
        parsed = parse_event(log["event"])
        timestamp = parsed.get("TS", "Unknown")
        
        events_data.append({
            "id": log["id"],
            "timestamp": timestamp,
            "type": log.get("event_type", "EVENT_LOG"),
            "event": parsed.get("type", "UNKNOWN"),
            "valid": log["is_chain_valid"],
            "anchored": log.get("is_anchored", False)
        })
    
    df = pd.DataFrame(events_data)
    
    # Create color mapping
    color_map = {
        "EVENT_VIOLATION": "red",
        "EVENT_WARNING": "orange",
        "EVENT_LOG": "green"
    }
    
    df["color"] = df["type"].map(color_map)
    
    fig = go.Figure()
    
    for event_type in df["type"].unique():
        df_type = df[df["type"] == event_type]
        fig.add_trace(go.Scatter(
            x=df_type["id"],
            y=[event_type] * len(df_type),
            mode="markers",
            name=event_type,
            marker=dict(
                size=12,
                color=df_type["color"],
                symbol="circle"
            ),
            text=df_type["event"],
            hovertemplate="<b>%{text}</b><br>ID: %{x}<br>Time: " + df_type["timestamp"] + "<extra></extra>"
        ))
    
    fig.update_layout(
        title="Event Timeline",
        xaxis_title="Event ID",
        yaxis_title="Event Type",
        hovermode="closest",
        height=400,
        showlegend=True
    )
    
    return fig

def create_sensor_chart(logs):
    """Create sensor reading charts"""
    sensor_data = {"TEMP": [], "HUM": [], "TILT": [], "timestamps": []}
    
    for log in logs:
        parsed = parse_event(log["event"])
        ts = parsed.get("TS", "Unknown")
        
        if "TEMP" in parsed:
            try:
                sensor_data["TEMP"].append(float(parsed["TEMP"]))
                sensor_data["timestamps"].append(ts)
            except:
                pass
        
        if "HUM" in parsed:
            try:
                sensor_data["HUM"].append(float(parsed["HUM"]))
            except:
                pass
        
        if "TILT" in parsed:
            try:
                sensor_data["TILT"].append(float(parsed["TILT"]))
            except:
                pass
    
    if not sensor_data["TEMP"]:
        return None
    
    fig = go.Figure()
    
    # Temperature
    if sensor_data["TEMP"]:
        fig.add_trace(go.Scatter(
            x=list(range(len(sensor_data["TEMP"]))),
            y=sensor_data["TEMP"],
            name="Temperature (°C)",
            line=dict(color="red", width=2)
        ))
        
        # Add threshold lines
        fig.add_hline(y=8.0, line_dash="dash", line_color="orange", annotation_text="Max Temp (8°C)")
        fig.add_hline(y=2.0, line_dash="dash", line_color="blue", annotation_text="Min Temp (2°C)")
    
    fig.update_layout(
        title="Temperature Over Time",
        xaxis_title="Reading #",
        yaxis_title="Temperature (°C)",
        hovermode="x unified",
        height=400
    )
    
    return fig

# ================= MAIN APP =================

st.markdown('<h1 class="main-header">❄️ Secure Cold Chain Monitor</h1>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.header("🔧 Configuration")
    
    device_id = st.text_input(
        "Device ID",
        value="ESP32_WOK3",
        help="Enter the device ID to monitor"
    )
    
    auto_refresh = st.checkbox("Auto-refresh (10s)", value=False)
    
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()
    
    st.divider()
    
    st.markdown("### 🔗 Quick Links")
    st.markdown(f"[Backend API]({BACKEND_URL})")
    st.markdown("[Sepolia Explorer](https://sepolia.etherscan.io/)")
    
    st.divider()
    
    st.markdown("### ℹ️ About")
    st.markdown("""
    Real-time monitoring dashboard for blockchain-secured cold chain logistics.
    
    **Features:**
    - Live sensor monitoring
    - Violation tracking
    - Blockchain verification
    - Chain integrity audit
    """)

# Auto-refresh logic
if auto_refresh:
    time.sleep(10)
    st.rerun()

# Fetch data
with st.spinner(f"Loading data for {device_id}..."):
    logs = fetch_logs(device_id)

if not logs:
    st.warning(f"⚠️ No data found for device: {device_id}")
    st.info("Make sure the device is registered and sending events to the backend.")
    st.stop()

# Calculate stats
stats = get_violation_stats(logs)
last_log = logs[-1] if logs else None

# ================= METRICS ROW =================

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="📊 Total Events",
        value=len(logs),
        delta=f"+{len([l for l in logs if l['is_chain_valid']])} valid"
    )

with col2:
    st.metric(
        label="🚨 Violations",
        value=stats["total_violations"],
        delta=f"{stats['anchored']} anchored",
        delta_color="inverse"
    )

with col3:
    st.metric(
        label="⚠️ Warnings",
        value=stats["total_warnings"],
        delta=f"{len(logs) - stats['total_violations'] - stats['total_warnings']} normal"
    )

with col4:
    chain_valid = len([l for l in logs if l["is_chain_valid"]])
    integrity = (chain_valid / len(logs) * 100) if logs else 0
    st.metric(
        label="🔗 Chain Integrity",
        value=f"{integrity:.1f}%",
        delta="✅ Verified" if integrity == 100 else "⚠️ Issues"
    )

# ================= TABS =================

tab1, tab2, tab3, tab4 = st.tabs(["📈 Dashboard", "🚨 Violations", "🔍 Event Log", "⛓️ Blockchain"])

# ================= TAB 1: DASHBOARD =================

with tab1:
    
    # Latest Reading
    if last_log:
        parsed = parse_event(last_log["event"])
        
        st.subheader("📡 Latest Reading")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            temp = parsed.get("TEMP", "N/A")
            st.markdown(f"""
            <div class="metric-card">
                <h3>🌡️ Temperature</h3>
                <h2>{temp}°C</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            hum = parsed.get("HUM", "N/A")
            st.markdown(f"""
            <div class="metric-card">
                <h3>💧 Humidity</h3>
                <h2>{hum}%</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            tilt = parsed.get("TILT", "N/A")
            st.markdown(f"""
            <div class="metric-card">
                <h3>📐 Tilt</h3>
                <h2>{tilt}°</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            timestamp = parsed.get("TS", "N/A")
            st.markdown(f"""
            <div class="metric-card">
                <h3>🕒 Last Update</h3>
                <h2>{timestamp}</h2>
            </div>
            """, unsafe_allow_html=True)
    
    st.divider()
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        timeline = create_timeline_chart(logs)
        if timeline:
            st.plotly_chart(timeline, use_container_width=True)
    
    with col2:
        sensor_chart = create_sensor_chart(logs)
        if sensor_chart:
            st.plotly_chart(sensor_chart, use_container_width=True)
    
    # Violation breakdown
    if stats["types"]:
        st.subheader("📊 Violation Breakdown")
        
        fig = px.pie(
            names=list(stats["types"].keys()),
            values=list(stats["types"].values()),
            title="Violation Types"
        )
        st.plotly_chart(fig, use_container_width=True)

# ================= TAB 2: VIOLATIONS =================

with tab2:
    st.subheader("🚨 Violation History")
    
    violations = [l for l in logs if l.get("event_type") == "EVENT_VIOLATION"]
    
    if not violations:
        st.success("✅ No violations detected!")
    else:
        for v in reversed(violations[-10:]):  # Show last 10
            parsed = parse_event(v["event"])
            
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"""
                <div class="violation-card">
                    <h4>⚠️ {parsed['type']}</h4>
                    <p><strong>Device:</strong> {parsed.get('ESP32_WOK3', device_id)}</p>
                    <p><strong>Time:</strong> {parsed.get('TS', 'Unknown')}</p>
                    <p><strong>Details:</strong> {' | '.join([f"{k}={v}" for k,v in parsed.items() if k not in ['type', 'ESP32_WOK3', 'TS']])}</p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                if v.get("is_anchored"):
                    st.success("⛓️ Anchored")
                    if v.get("eth_tx"):
                        st.markdown(f"[View TX](https://sepolia.etherscan.io/tx/{v['eth_tx']})")
                else:
                    st.info("📝 Logged")
                
                if not v["is_chain_valid"]:
                    st.error("❌ Invalid")

# ================= TAB 3: EVENT LOG =================

with tab3:
    st.subheader("🔍 Complete Event Log")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        filter_type = st.selectbox(
            "Filter by type",
            ["All", "EVENT_VIOLATION", "EVENT_WARNING", "EVENT_LOG"]
        )
    
    with col2:
        filter_validity = st.selectbox(
            "Filter by validity",
            ["All", "Valid", "Invalid"]
        )
    
    with col3:
        filter_anchored = st.selectbox(
            "Filter by anchoring",
            ["All", "Anchored", "Not Anchored"]
        )
    
    # Apply filters
    filtered_logs = logs
    
    if filter_type != "All":
        filtered_logs = [l for l in filtered_logs if l.get("event_type") == filter_type]
    
    if filter_validity == "Valid":
        filtered_logs = [l for l in filtered_logs if l["is_chain_valid"]]
    elif filter_validity == "Invalid":
        filtered_logs = [l for l in filtered_logs if not l["is_chain_valid"]]
    
    if filter_anchored == "Anchored":
        filtered_logs = [l for l in filtered_logs if l.get("is_anchored")]
    elif filter_anchored == "Not Anchored":
        filtered_logs = [l for l in filtered_logs if not l.get("is_anchored")]
    
    st.write(f"**Showing {len(filtered_logs)} of {len(logs)} events**")
    
    # Display table
    if filtered_logs:
        df = pd.DataFrame([
            {
                "ID": l["id"],
                "Type": l.get("event_type", "N/A"),
                "Event": parse_event(l["event"])["type"],
                "Valid": "✅" if l["is_chain_valid"] else "❌",
                "Anchored": "⛓️" if l.get("is_anchored") else "📝",
                "Hash": l["hash"][:16] + "...",
                "TX": l.get("eth_tx", "N/A")[:16] + "..." if l.get("eth_tx") else "N/A"
            }
            for l in filtered_logs
        ])
        
        st.dataframe(df, use_container_width=True, height=400)
    else:
        st.info("No events match the selected filters.")

# ================= TAB 4: BLOCKCHAIN =================

with tab4:
    st.subheader("⛓️ Blockchain Verification")
    
    anchored_events = [l for l in logs if l.get("is_anchored")]
    
    if not anchored_events:
        st.info("ℹ️ No events have been anchored to blockchain yet.")
    else:
        st.success(f"✅ {len(anchored_events)} events anchored to Sepolia testnet")
        
        st.write("### Recent Blockchain Transactions")
        
        for event in reversed(anchored_events[-5:]):  # Show last 5
            parsed = parse_event(event["event"])
            
            with st.expander(f"📦 {parsed['type']} - TX: {event['eth_tx'][:16]}..."):
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Event Details:**")
                    st.json(parsed)
                
                with col2:
                    st.write("**Blockchain Info:**")
                    st.code(f"TX Hash: {event['eth_tx']}")
                    st.code(f"Chain: Sepolia (Chain ID: 11155111)")
                    st.code(f"Device Hash: {event['hash']}")
                    
                    st.markdown(f"[🔗 View on Etherscan](https://sepolia.etherscan.io/tx/{event['eth_tx']})")
    
    st.divider()
    
    # Chain integrity check
    st.write("### 🔐 Chain Integrity Verification")
    
    valid_count = len([l for l in logs if l["is_chain_valid"]])
    invalid_count = len(logs) - valid_count
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Valid Events", valid_count, delta="✅")
    
    with col2:
        st.metric("Invalid Events", invalid_count, delta="⚠️" if invalid_count > 0 else "✅")
    
    if invalid_count == 0:
        st.success("🎉 All events in the chain are valid! Chain integrity is intact.")
    else:
        st.error(f"⚠️ {invalid_count} invalid events detected. Chain may be compromised.")
        
        # Show invalid events
        invalid_logs = [l for l in logs if not l["is_chain_valid"]]
        
        st.write("**Invalid Events:**")
        for inv in invalid_logs:
            st.error(f"Event ID {inv['id']}: {parse_event(inv['event'])['type']}")

# ================= FOOTER =================

st.divider()

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("**Device:** " + device_id)

with col2:
    st.markdown("**Backend:** " + BACKEND_URL)

with col3:
    st.markdown("**Last Update:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))