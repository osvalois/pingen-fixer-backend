import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
from datetime import datetime, timedelta
import os
import base64

# Constants and Configuration
API_BASE_URL = 'http://127.0.0.1:5000'
PAGE_TITLE = "PINGEN-FIXER: Advanced Code Analysis"
PAGE_ICON = "🧬"

# API Functions with Enhanced Error Handling and Caching
@st.cache_data(ttl=300)
def fetch_data(endpoint):
    try:
        response = requests.get(f"{API_BASE_URL}/api/{endpoint}")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Error fetching {endpoint}: {str(e)}")
        return None

def export_issues():
    try:
        response = requests.get(f"{API_BASE_URL}/api/export")
        response.raise_for_status()
        return BytesIO(response.content)
    except requests.RequestException as e:
        st.error(f"Error exporting issues: {str(e)}")
        return None

@st.cache_data(ttl=600)
def ai_suggest(issue):
    try:
        response = requests.post(f"{API_BASE_URL}/api/ai_suggest", json={"issue": issue})
        response.raise_for_status()
        return response.json()["suggestion"]
    except requests.RequestException as e:
        st.error(f"Error getting AI suggestions: {str(e)}")
        return None

# Utility Functions
def load_css():
    with open("style.css") as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def display_header():
    st.markdown("""
        <div class="header">
            <h1>🧬 PINGEN-FIXER</h1>
            <p>Advanced AI-Powered Code Analysis Platform</p>
        </div>
    """, unsafe_allow_html=True)

# Data Processing Functions
def prepare_data(issues):
    all_issues = [issue for file_issues in issues.values() for issue in file_issues]
    return pd.DataFrame(all_issues)

def filter_data(df, file, severities, types, date_range, search_term):
    filtered = df[
        (df['severity'].isin(severities)) &
        (df['type'].isin(types)) &
        (pd.to_datetime(df['creationDate']).dt.date.between(date_range[0], date_range[1]))
    ]
    if file != "All Files":
        filtered = filtered[filtered['component'].apply(lambda x: os.path.basename(x) == file)]
    if search_term:
        filtered = filtered[
            filtered['message'].str.contains(search_term, case=False) |
            filtered['rule'].str.contains(search_term, case=False) |
            filtered['component'].str.contains(search_term, case=False)
        ]
    return filtered

# Visualization Functions
def create_severity_chart(summary):
    severity_data = pd.DataFrame(list(summary['by_severity'].items()), columns=['Severity', 'Count'])
    fig = px.bar(severity_data, x='Severity', y='Count', 
                 title='Issue Distribution by Severity',
                 color='Severity',
                 color_discrete_map={
                     'BLOCKER': 'red',
                     'CRITICAL': 'orangered',
                     'MAJOR': 'orange',
                     'MINOR': 'yellow',
                     'INFO': 'lightblue'
                 })
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e0e0', family='Roboto'),
        title_font=dict(size=20, color='#00ffff'),
        legend_title_font=dict(size=12, color='#00ffff'),
        legend_font=dict(size=10, color='#e0e0e0')
    )
    return fig

def create_type_chart(summary):
    type_data = pd.DataFrame(list(summary['by_type'].items()), columns=['Type', 'Count'])
    fig = px.pie(type_data, values='Count', names='Type', 
                 title='Issue Categorization',
                 color_discrete_sequence=px.colors.sequential.Plasma_r)
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e0e0', family='Roboto'),
        title_font=dict(size=20, color='#00ffff'),
        legend_title_font=dict(size=12, color='#00ffff'),
        legend_font=dict(size=10, color='#e0e0e0')
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

def create_trend_chart(filtered_df):
    trend_data = filtered_df.groupby(pd.to_datetime(filtered_df['creationDate']).dt.date).size().reset_index(name='count')
    fig = px.line(trend_data, x='creationDate', y='count', 
                  title='Issue Evolution Over Time',
                  labels={'creationDate': 'Date', 'count': 'Number of Issues'},
                  line_shape='spline', render_mode='svg')
    fig.update_traces(line=dict(color='#00ffff', width=3))
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0.1)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e0e0', family='Roboto'),
        title_font=dict(size=24, color='#00ffff'),
        xaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.1)'),
        yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.1)')
    )
    fig.add_annotation(
        x=trend_data['creationDate'].iloc[-1],
        y=trend_data['count'].iloc[-1],
        text=f"Latest: {trend_data['count'].iloc[-1]}",
        showarrow=True,
        arrowhead=2,
        arrowcolor="#00ffff",
        arrowsize=1,
        arrowwidth=2,
        ax=-40,
        ay=-40
    )
    return fig

# UI Components
def sidebar_filters(df):
    st.sidebar.markdown("## 🔬 Analysis Control Center")
    
    file_options = ["All Files"] + [os.path.basename(file) for file in df['component'].unique()]
    selected_file = st.sidebar.selectbox("📁 Select Project File", options=file_options)
    
    severity_options = df['severity'].unique().tolist()
    selected_severities = st.sidebar.multiselect(
        "🚨 Issue Severity",
        options=severity_options,
        default=severity_options,
        format_func=lambda x: f"{x} {'🔴' if x in ['CRITICAL', 'BLOCKER'] else '🟠' if x == 'MAJOR' else '🟡'}"
    )
    
    type_options = df['type'].unique().tolist()
    selected_types = st.sidebar.multiselect(
        "🏷️ Issue Categories",
        options=type_options,
        default=type_options,
        format_func=lambda x: f"{x} {'🐞' if x == 'BUG' else '🔒' if x == 'VULNERABILITY' else '📊'}"
    )
    
    st.sidebar.markdown("### 📅 Time Frame Analysis")
    date_range = st.sidebar.date_input(
        "Select analysis period",
        value=(datetime.now() - timedelta(days=30), datetime.now()),
        help="Analyze issues within a specific date range"
    )
    
    st.sidebar.markdown("### ⚡ Quick Filters")
    if st.sidebar.button("Recent Issues (Last 7 Days)"):
        date_range = (datetime.now() - timedelta(days=7), datetime.now())
    if st.sidebar.button("Critical & Blocker Issues"):
        selected_severities = ["CRITICAL", "BLOCKER"]
    
    return selected_file, selected_severities, selected_types, date_range

def display_issues(filtered_df):
    for _, issue in filtered_df.iterrows():
        with st.expander(f"{'🔴' if issue['severity'] in ['CRITICAL', 'BLOCKER'] else '🟠' if issue['severity'] == 'MAJOR' else '🟡'} {issue['type']} - {issue['message'][:50]}...", expanded=True):
            st.markdown(f"""
            <div class="issue-card">
                <h4>{issue['message']}</h4>
                <p><strong>Severity:</strong> <span class="severity-{issue['severity'].lower()}">{issue['severity']}</span></p>
                <p><strong>File:</strong> {issue['component']}</p>
                <p><strong>Line:</strong> {issue.get('line', 'N/A')}</p>
                <p><strong>Created:</strong> {issue['creationDate']}</p>
                <p><strong>Rule:</strong> <code>{issue['rule']}</code></p>
            </div>
            """, unsafe_allow_html=True)
            
            if 'textRange' in issue:
                start_line = issue['textRange']['startLine']
                end_line = issue['textRange']['endLine']
                code_snippet = f"// Code from line {start_line} to {end_line}\n// Replace with actual code"
                st.code(code_snippet, language="java")
            
            if st.button("🧠 Get AI Insight", key=issue['key']):
                with st.spinner("🔮 AI is analyzing the issue..."):
                    suggestion = ai_suggest(issue.to_dict())
                if suggestion:
                    st.markdown(f"""
                    <div class="ai-suggestion">
                        <h5>🤖 AI Recommendation:</h5>
                        <p>{suggestion}</p>
                    </div>
                    """, unsafe_allow_html=True)

def display_metrics(summary, filtered_df):
    col1, col2, col3 = st.columns(3)
    
    total_issues = summary.get('total', 0)
    prev_total = total_issues - len(filtered_df[filtered_df['creationDate'] > (datetime.now() - timedelta(days=7)).isoformat()])
    trend = '🔺' if total_issues > prev_total else '🔻' if total_issues < prev_total else '➡️'
    
    col1.metric("📊 Total Issues", 
                f"{total_issues:,}", 
                f"{trend} {abs(total_issues - prev_total)}")

    critical_issues = summary['by_severity'].get('CRITICAL', 0)
    col2.markdown(f"""
        <div class="critical-metric">
            <h4>🚨 Critical Issues</h4>
            <p>{critical_issues}</p>
        </div>
    """, unsafe_allow_html=True)

    blocker_issues = summary['by_severity'].get('BLOCKER', 0)
    col3.metric("🛑 Blocker Issues", blocker_issues)

def display_interactive_table(filtered_df):
    st.markdown("## 🔬 Interactive Issue Explorer")
    
    interactive_table = go.Figure(data=[go.Table(
        header=dict(values=list(filtered_df.columns),
                    fill_color='rgba(0,255,255,0.1)',
                    align='left',
                    font=dict(color='white', size=12)),
        cells=dict(values=[filtered_df[k].tolist() for k in filtered_df.columns],
                   fill_color='rgba(0,0,0,0.1)',
                   align='left',
                   font=dict(color='white', size=11))
    )])
    interactive_table.update_layout(
        height=500,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)"
    )
    st.plotly_chart(interactive_table, use_container_width=True)

def display_ai_insights():
    st.markdown("## 🧠 AI-Powered Code Health Insights")
    
    ai_insights = [
    ]

    for insight in ai_insights:
        st.markdown(f"""
            <div class="ai-insight">
                <p><strong>🤖 AI Insight:</strong> {insight}</p>
            </div>
        """, unsafe_allow_html=True)

# Main Application
def main():
    st.set_page_config(layout="wide", page_title=PAGE_TITLE, page_icon=PAGE_ICON)
    load_css()
    display_header()

    issues = fetch_data("issues")
    summary = fetch_data("summary")

    if issues is None or summary is None:
        st.error("Failed to fetch data from the API. Please check if the server is operational.")
        return

    issues_df = prepare_data(issues)

    selected_file, selected_severities, selected_types, date_range = sidebar_filters(issues_df)
    
    search_term = st.text_input("🔎 Search Issues", key="search_box", 
                                help="Search by message, rule, or file name")

    filtered_df = filter_data(issues_df, selected_file, selected_severities, selected_types, date_range, search_term)

    col1, col2 = st.columns([3, 2])

    with col1:
        st.markdown("## 🔍 Code Health Insights")
        display_issues(filtered_df)

        if st.button("📤 Export Analysis Report"):
            excel_file = export_issues()
            if excel_file:
                st.download_button(
                    label="📥 Download Comprehensive Report",
                    data=excel_file,
                    file_name="nexus_code_analysis_report.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

    with col2:
        st.markdown("## 📊 Analysis Overview")
        display_metrics(summary, filtered_df)
        
        severity_chart = create_severity_chart(summary)
        st.plotly_chart(severity_chart, use_container_width=True)
        
        type_chart = create_type_chart(summary)
        st.plotly_chart(type_chart, use_container_width=True)

    trend_chart = create_trend_chart(filtered_df)
    st.plotly_chart(trend_chart, use_container_width=True)

    display_interactive_table(filtered_df)
    display_ai_insights()

    st.markdown("""
        <footer>
            <p>Powered by Pingen AI 🧬 | © 2024 Advanced Code Analysis Technologies</p>
        </footer>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()