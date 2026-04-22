import streamlit as st
import pandas as pd
import numpy as np
import time
import os
import tempfile
import altair as alt
from datetime import datetime

# Import backend classes
from src.parser import AuthLogParser
import html
import joblib
from src.config import MODEL_PATH
from src.detector import (
    LogDetector, 
    BruteForceRule, 
    TimeAnomalyRule, 
    UserProbingRule, 
    IsolationForestRule, 
    SQLInjectionRule, 
    XSSRule, 
    PathTraversalRule, 
    WebAttackRule
)

# --- STATE MANAGEMENT ---
if 'df_logs' not in st.session_state:
    st.session_state.df_logs = pd.DataFrame()
if 'df_anomalies' not in st.session_state:
    st.session_state.df_anomalies = pd.DataFrame()
if 'latency_ms' not in st.session_state:
    st.session_state.latency_ms = 0
if 'processed' not in st.session_state:
    st.session_state.processed = False
if 'ml_model' not in st.session_state:
    # Pre-cargar el modelo una sola vez
    st.session_state.ml_model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

# --- SOC CONFIGURATION (SECURITY OPERATIONS CENTER) ---
st.set_page_config(
    page_title="LogAI-Analyst | Core Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CSS: DARK ARCHITECTURE (ABSOLUTE SOBRIETY) ---
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono&display=swap');
    
    /* Configuración Base Dark Mode */
    .stApp {
        background-color: #0D1117;
        color: #C9D1D9;
    }

    h1, h2, h3, h4 {
        font-family: 'Inter', sans-serif !important;
        font-weight: 600 !important;
        color: #F0F6FC !important;
        letter-spacing: -1px;
    }

    /* Asegurar que el File Uploader sea visible */
    [data-testid="stFileUploadDropzone"] {
        background-color: #161B22 !important;
        border: 1px dashed #30363D !important;
        border-radius: 6px !important;
    }
    
    [data-testid="stSidebar"] {
        background-color: #010409 !important;
        border-right: 1px solid #30363D !important;
    }

    /* Custom Metrics */
    .custom-metric-card {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 12px 16px;
        position: relative;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .custom-metric-label {
        font-family: 'Inter', sans-serif;
        color: #8B949E;
        font-size: 0.75rem;
        font-weight: 600;
        margin-bottom: 2px;
        display: block;
        letter-spacing: 0.5px;
    }
    .custom-metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.6rem;
        font-weight: 600;
        line-height: 1.2;
    }
    
    .custom-metric-icon {
        position: absolute;
        top: 14px;
        right: 16px;
        color: #484F58;
    }

    /* Visor de Logs TTY */
    .log-container {
        height: 350px;
        overflow-y: auto;
        border: 1px solid #30363D;
        border-radius: 6px;
        background-color: #0D1117;
        padding-bottom: 10px;
    }
    
    .log-entry {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        padding: 8px 12px;
        border-bottom: 1px solid #21262D;
        color: #8B949E;
        transition: 0.1s;
    }
    
    .log-entry:hover {
        background-color: #161B22;
        color: #C9D1D9;
    }
    
    /* Clase asignada sólo a logs con anomalías de ML/Heurística */
    /* Severities */
    .severity-high { border-left: 3px solid #E63946 !important; background-color: rgba(230, 57, 70, 0.08) !important; }
    .severity-medium { border-left: 3px solid #E3B341 !important; background-color: rgba(227, 179, 65, 0.08) !important; }
    .severity-low { border-left: 3px solid #58A6FF !important; background-color: rgba(88, 166, 255, 0.08) !important; }

    .github-link {
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 8px;
        border: 1px solid #30363D;
        border-radius: 6px;
        color: #8B949E !important;
        text-decoration: none;
        font-size: 12px;
        font-family: 'Inter', sans-serif;
        font-weight: 500;
        transition: 0.3s;
    }
    .github-link:hover {
        border-color: #58A6FF;
        background-color: #161B22;
    }
    
    /* Modo Empty State (Estado de espera visual) */
    .empty-state {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 200px;
        border: 1px dashed #30363D;
        border-radius: 6px;
        background-color: transparent;
        color: #8B949E;
        font-family: 'Inter', sans-serif;
    }
    
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

def process_log_file(uploaded_file):
    start_time = time.time()
    
    # Guardar en tmp para inyectar en el parser real
    with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    try:
        # Pipeline 1: Ejecutar el análisis usando el nuevo orquestador (Senior Pipeline)
        progress_bar = st.sidebar.progress(0, text="Analyzing logs...")
        def pg_callback(curr, tot):
            progress_bar.progress(min(curr/tot, 1.0), text=f"Analyzing: {curr}/{tot} lines")

        # El pipeline centraliza Parser, Normalización y Reglas
        from src.pipeline import LogAnalysisPipeline
        # Dependency Injection: Pre-loaded model passed to constructor
        pipeline = LogAnalysisPipeline(model=st.session_state.ml_model)
        
        result = pipeline.run(
            tmp_path, 
            progress_callback=pg_callback
        )
        
        progress_bar.empty()
        end_time = time.time()
        
        # Commit de datos reales al Session State (usando AnalysisResult)
        st.session_state.df_logs = result.df_raw
        st.session_state.df_anomalies = result.df_anomalies
        st.session_state.latency_ms = int(result.metadata.get('latency_ms', (end_time - start_time) * 1000))
        st.session_state.processed = True
    finally:
        os.unlink(tmp_path)

def main():
    # --- SIDEBAR: PIPELINE DE INGESTIÓN ---
    with st.sidebar:
        st.markdown("### `SYSTEM_ENGINE`")
        st.caption("LogAI-Analyst Core v1.0.4")
        st.markdown("---")
        
        # Uploader SIEMPRE visible
        st.markdown("#### INGESTION PIPELINE")
        uploaded_file = st.file_uploader("Upload Security Log", type=['log', 'txt', 'csv'])
        
        # Botón siempre instanciado, se deshabilita si no hay archivo para evitar confusiones
        is_disabled = (uploaded_file is None)
        if st.button("PROCESS_LOGS", use_container_width=True, disabled=is_disabled):
            with st.spinner("Executing analytical pipeline..."):
                process_log_file(uploaded_file)
        
        st.markdown("---")
        st.markdown("#### ENGINE_STATUS")
        if st.session_state.processed:
            st.code("MODE: ANALYTICS\nML_CORE: RUNNING\nPIPELINE: DONE", language="bash")
        else:
            st.code("MODE: IDLE\nML_CORE: STANDBY\nPIPELINE: WAIT", language="bash")
            
        # Top Attackers (Agregación silenciosa IP) mantieniendo simetría
        if st.session_state.processed and not st.session_state.df_anomalies.empty:
            st.markdown("---")
            st.markdown("#### TOP THREAT ACTORS (IP)")
            top_ips = st.session_state.df_anomalies['ip_origen'].value_counts().head(5)
            for ip, count in top_ips.items():
                if pd.notna(ip) and str(ip).strip():
                    st.markdown(f"<span style='font-family: JetBrains Mono; font-size: 13px; color: #8B949E;'>{ip}</span> • <span style='color: #E63946; font-size: 12px; font-weight: 600;'>{count} hits</span>", unsafe_allow_html=True)
                    
        st.markdown("---")
        st.markdown("""
            <a href="https://github.com/ezeeranieri/LogAI-Analyst" class="github-link" target="_blank">
                <svg height="18" viewBox="0 0 16 16" version="1.1" width="18" aria-hidden="true" fill="currentColor" style="margin-right:8px;"><path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path></svg>
                SOURCE_CODE / REPO
            </a>
        """, unsafe_allow_html=True)

    # --- MAIN INTERFACE: TABLERO MAESTRO ---
    st.title("Security Analysis Terminal")
    st.caption("Real-time anomaly and pattern detection via heuristic modeling and Machine Learning.")

    # Guard Clause: Ensure session state keys exist and are not None
    df_logs = st.session_state.get('df_logs')
    df_anomalies = st.session_state.get('df_anomalies')
    is_processed = st.session_state.get('processed', False)

    if is_processed and df_logs is not None:
        total_logs = len(df_logs)
        total_anomalies = len(df_anomalies) if df_anomalies is not None else 0
        latency_str = f"{st.session_state.get('latency_ms', 0)}ms"
        
        threat_level = "LOW"
        threat_color = "#2A9D8F"
        if total_logs > 0:
            ratio = total_anomalies / total_logs
            if ratio > 0.05 or total_anomalies > 50:
                threat_level = "HIGH"
                threat_color = "#E63946"
            elif ratio > 0.01 or total_anomalies > 5:
                threat_level = "ELEVATED"
                threat_color = "#E3B341"
    else:
        total_logs = 0
        total_anomalies = 0
        latency_str = "0ms"
        threat_level = "STANDBY"
        threat_color = "#8B949E"

    # Tarjetas inyectadas
    col1, col2, col3, col4 = st.columns(4)
    svg_logs = '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>'
    svg_anomalies = '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
    svg_shield = '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>'
    svg_latency = '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>'

    with col1: 
        st.markdown(f"<div class='custom-metric-card'><div class='custom-metric-icon'>{svg_logs}</div><span class='custom-metric-label'>TOTAL_LOGS</span><span class='custom-metric-value' style='color: #58A6FF;'>{total_logs:,}</span></div>", unsafe_allow_html=True)
    with col2: 
        anomaly_color = "#E63946" if total_anomalies > 0 else "#8B949E"
        st.markdown(f"<div class='custom-metric-card'><div class='custom-metric-icon'>{svg_anomalies}</div><span class='custom-metric-label'>ANOMALIES</span><span class='custom-metric-value' style='color: {anomaly_color};'>{total_anomalies:,}</span></div>", unsafe_allow_html=True)
    with col3: 
        st.markdown(f"<div class='custom-metric-card'><div class='custom-metric-icon'>{svg_shield}</div><span class='custom-metric-label'>THREAT_LEVEL</span><span class='custom-metric-value' style='color: {threat_color};'>{threat_level}</span></div>", unsafe_allow_html=True)
    with col4: 
        st.markdown(f"<div class='custom-metric-card'><div class='custom-metric-icon'>{svg_latency}</div><span class='custom-metric-label'>LATENCY</span><span class='custom-metric-value' style='color: #58A6FF;'>{latency_str}</span></div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Event Intensity
    st.subheader("Event Intensity")
    if is_processed and df_logs is not None and not df_logs.empty and 'datetime' in df_logs.columns:
        df_time = df_logs.copy()
        df_time = df_time.dropna(subset=['datetime']).sort_values('datetime')
        if not df_time.empty:
            df_g = df_time.set_index('datetime').resample('1H').size().reset_index(name='Events')
            area_chart = alt.Chart(df_g.reset_index()).mark_area(
                line={'color':'#58A6FF', 'size': 2},
                color=alt.Gradient(
                    gradient='linear',
                    stops=[alt.GradientStop(color='rgba(88, 166, 255, 0.4)', offset=0), alt.GradientStop(color='#0D1117', offset=1)],
                    x1=1, x2=1, y1=1, y2=0
                )
            ).encode(
                x=alt.X('datetime:T', axis=None),
                y=alt.Y('Events:Q', axis=alt.Axis(grid=False, labels=False, title=None))
            ).properties(height=140).configure_view(strokeWidth=0)
            st.altair_chart(area_chart, use_container_width=True)
    else:
        # Estado Vacío para el Gráfico
        st.markdown("<div class='empty-state'><svg width='24' height='24' fill='none' stroke='currentColor' stroke-width='2'><path d="+'"M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7"'+"/></svg><br>Awaiting Streamlit File Ingestion...</div>", unsafe_allow_html=True)

    # Forensic Log Viewer
    st.subheader("Forensic Log Viewer")
    with st.container():
        log_html = "<div class='log-container'>"
        
        if is_processed and df_logs is not None and not df_logs.empty:
            # Map of (datetime, ip) -> anomaly info for O(1) lookup during rendering
            anomaly_map = {}
            if df_anomalies is not None and not df_anomalies.empty:
                for _, r in df_anomalies.iterrows():
                    anomaly_map[(r.get('datetime'), r.get('ip_origen'))] = {
                        'rule': r.get('rule', 'Unknown'),
                        'severity': str(r.get('severity', 'low')).lower(),
                        'reason': r.get('reason', '')
                    }
            
            # Mostramos un chunk rápido de logs para no saturar memoria RAM DOM
            for i, row in df_logs.tail(200).iterrows():
                dt = row.get('datetime')
                ip = row.get('ip_origen')
                
                # Check anomaly match (LÓGICA CRÍTICA DE VALIDACIÓN ML/HEURÍSTICA)
                anomaly_info = anomaly_map.get((dt, ip)) if dt else None
                is_anomaly = anomaly_info is not None
                
                status_color = "#2A9D8F" if row.get('status') == "SUCCESS" else "#E63946" if row.get('status') == "FAIL" else "#58A6FF"
                
                severity_class = f"severity-{anomaly_info['severity']}" if is_anomaly else ""
                css_class = f"log-entry {severity_class}"
                
                ts_str = str(dt) if pd.notnull(dt) else str(row.get('timestamp'))
                
                # ESCAPAR HTML para prevenir XSS de logs maliciosos
                safe_action = html.escape(str(row.get('accion', '')))
                action_str = safe_action[:65] + '...' if len(safe_action) > 65 else safe_action
                safe_ip = html.escape(str(ip or ''))
                
                # Explicabilidad Trazable
                if is_anomaly:
                    prefix = f"⚠️ [{anomaly_info['rule'].upper()}] "
                    sev_label = f" <span style='font-size:10px; padding: 2px 4px; border-radius:3px; background:#30363D;'>{anomaly_info['severity'].upper()}</span>"
                else:
                    prefix = ""
                    sev_label = ""
                
                log_html += f"""
                    <div class="{css_class}">
                        <span style="color: {status_color}; font-weight: 600;">[{row.get('status', 'INFO')}]</span> 
                        {ts_str} | {prefix}{action_str} | SRC: {safe_ip}{sev_label}
                    </div>
                """
        else:
            # Estado Vacío formal e invitando a interactuar
            log_html += "<div class='empty-state' style='border:none;'><p>No active logs in buffer. System Idle.</p><p style='font-size:11px;'>Please upload a `.log` file in the left Configuration Panel to engage the ML Engine.</p></div>"
            
        log_html += "</div>"
        st.markdown(log_html, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
