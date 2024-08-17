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
THEME_COLOR = "#2a5298"
ACCENT_COLOR = "#00ffff"

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
        return response.json()
    except requests.RequestException as e:
        st.error(f"Error getting AI suggestions: {str(e)}")
        if hasattr(e.response, 'text'):
            st.error(f"Server response: {e.response.text}")
        return None

# Utility Functions
def load_css():
    with open("style.css") as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def display_header():
    st.markdown(f"""
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
                     'BLOCKER': '#ff4444',
                     'CRITICAL': '#ff6b6b',
                     'MAJOR': '#ffa000',
                     'MINOR': '#ffd54f',
                     'INFO': '#4fc3f7'
                 })
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e0e0', family='Roboto'),
        title_font=dict(size=24, color=ACCENT_COLOR),
        legend_title_font=dict(size=14, color=ACCENT_COLOR),
        legend_font=dict(size=12, color='#e0e0e0'),
        xaxis=dict(title_font=dict(size=16, color=ACCENT_COLOR)),
        yaxis=dict(title_font=dict(size=16, color=ACCENT_COLOR))
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
        title_font=dict(size=24, color=ACCENT_COLOR),
        legend_title_font=dict(size=14, color=ACCENT_COLOR),
        legend_font=dict(size=12, color='#e0e0e0')
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

def create_trend_chart(filtered_df):
    trend_data = filtered_df.groupby(pd.to_datetime(filtered_df['creationDate']).dt.date).size().reset_index(name='count')
    fig = px.line(trend_data, x='creationDate', y='count', 
                  title='Issue Evolution Over Time',
                  labels={'creationDate': 'Date', 'count': 'Number of Issues'},
                  line_shape='spline', render_mode='svg')
    fig.update_traces(line=dict(color=ACCENT_COLOR, width=3))
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0.1)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e0e0', family='Roboto'),
        title_font=dict(size=24, color=ACCENT_COLOR),
        xaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.1)', title_font=dict(size=16, color=ACCENT_COLOR)),
        yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.1)', title_font=dict(size=16, color=ACCENT_COLOR))
    )
    fig.add_annotation(
        x=trend_data['creationDate'].iloc[-1],
        y=trend_data['count'].iloc[-1],
        text=f"Latest: {trend_data['count'].iloc[-1]}",
        showarrow=True,
        arrowhead=2,
        arrowcolor=ACCENT_COLOR,
        arrowsize=1,
        arrowwidth=2,
        ax=-40,
        ay=-40
    )
    return fig

# UI Components
def sidebar_filters(df):
    st.sidebar.markdown(f"<h2 style='color:{ACCENT_COLOR};'>🔬 Analysis Control Center</h2>", unsafe_allow_html=True)
    
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
    
    st.sidebar.markdown(f"<h3 style='color:{ACCENT_COLOR};'>📅 Time Frame Analysis</h3>", unsafe_allow_html=True)
    date_range = st.sidebar.date_input(
        "Select analysis period",
        value=(datetime.now() - timedelta(days=30), datetime.now()),
        help="Analyze issues within a specific date range"
    )
    
    st.sidebar.markdown(f"<h3 style='color:{ACCENT_COLOR};'>⚡ Quick Filters</h3>", unsafe_allow_html=True)
    col1, col2 = st.sidebar.columns(2)
    if col1.button("Recent (7 Days)"):
        date_range = (datetime.now() - timedelta(days=7), datetime.now())
    if col2.button("Critical & Blocker"):
        selected_severities = ["CRITICAL", "BLOCKER"]
    
    return selected_file, selected_severities, selected_types, date_range

def display_issues(filtered_df):
    st.markdown(f"<h3 style='color:{ACCENT_COLOR};'>Issue Filters</h3>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=filtered_df['severity'].unique(),
            default=filtered_df['severity'].unique()
        )
    
    with col2:
        type_filter = st.multiselect(
            "Filter by Type",
            options=filtered_df['type'].unique(),
            default=filtered_df['type'].unique()
        )
    
    with col3:
        sort_option = st.selectbox(
            "Sort issues by",
            options=["Severity", "Type", "Creation Date"],
            index=0
        )

    # Apply filters
    display_df = filtered_df[
        (filtered_df['severity'].isin(severity_filter)) &
        (filtered_df['type'].isin(type_filter))
    ]

    # Sort issues
    if sort_option == "Severity":
        severity_order = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO']
        display_df['severity_rank'] = display_df['severity'].map(lambda x: severity_order.index(x))
        display_df = display_df.sort_values('severity_rank')
    elif sort_option == "Type":
        display_df = display_df.sort_values('type')
    else:  # Creation Date
        display_df = display_df.sort_values('creationDate', ascending=False)

    # Display issue count
    st.markdown(f"<h4 style='color:{ACCENT_COLOR};'>Displaying {len(display_df)} issues</h4>", unsafe_allow_html=True)

    for _, issue in display_df.iterrows():
        severity_icon = '🔴' if issue['severity'] in ['CRITICAL', 'BLOCKER'] else '🟠' if issue['severity'] == 'MAJOR' else '🟡'
        with st.expander(f"{severity_icon} {issue['type']} - {issue['message'][:50]}...", expanded=False):
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
                start_line = issue['textRange'].get('startLine')
                end_line = issue['textRange'].get('endLine')
                code_snippet = f"// Code from line {start_line} to {end_line}\n// Replace with actual code"
                st.code(code_snippet, language="java")
            
            if st.button("🧠 Get AI Insight", key=issue['key']):
                with st.spinner("🔮 AI is analyzing the issue..."):
                    issue_data = {
                        "key": issue['key'],
                        "component": issue['component'],
                        "textRange": issue.get('textRange', {}),
                        "message": issue['message'],
                        "severity": issue['severity'],
                        "type": issue['type']
                    }
                    suggestion = ai_suggest(issue_data)
                if suggestion:
                    st.markdown(f"<h3 style='color:{ACCENT_COLOR};'>🤖 AI Recommendation:</h3>", unsafe_allow_html=True)
                    
                    if 'ADJUSTED_CODE' in suggestion:
                        st.markdown(f"<h4 style='color:{ACCENT_COLOR};'>Adjusted Code:</h4>", unsafe_allow_html=True)
                        st.code(suggestion['ADJUSTED_CODE'], language="java")
                    
                    if 'EXPLANATION' in suggestion:
                        st.markdown(f"<h4 style='color:{ACCENT_COLOR};'>Explanation:</h4>", unsafe_allow_html=True)
                        st.markdown(suggestion['EXPLANATION'])
                    
                    if 'STEPS_TO_FIX' in suggestion:
                        st.markdown(f"<h4 style='color:{ACCENT_COLOR};'>Steps to Fix:</h4>", unsafe_allow_html=True)
                        st.markdown(suggestion['STEPS_TO_FIX'])
                    
                    if 'BEST_PRACTICES' in suggestion:
                        st.markdown(f"<h4 style='color:{ACCENT_COLOR};'>Best Practices:</h4>", unsafe_allow_html=True)
                        st.markdown(suggestion['BEST_PRACTICES'])
                else:
                    st.warning("Unable to generate AI suggestion at this time. Please try again later or contact support if the issue persists.")

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
    st.markdown(f"<h2 style='color:{ACCENT_COLOR};'>🔬 Interactive Issue Explorer</h2>", unsafe_allow_html=True)
    
    interactive_table = go.Figure(data=[go.Table(
        header=dict(values=list(filtered_df.columns),
                    fill_color=THEME_COLOR,
                    align='left',
                    font=dict(color='white', size=14)),
        cells=dict(values=[filtered_df[k].tolist() for k in filtered_df.columns],
                   fill_color='rgba(0,0,0,0.1)',
                   align='left',
                   font=dict(color='white', size=12))
    )])
    interactive_table.update_layout(
        height=500,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)"
    )
    st.plotly_chart(interactive_table, use_container_width=True)

def display_ai_insights():
    st.markdown(f"<h2 style='color:{ACCENT_COLOR};'>🧠 AI-Powered Code Health Insights</h2>", unsafe_allow_html=True)
    
    ai_insights = [
        "Consider implementing automated code reviews to catch issues earlier in the development process.",
        "Regular refactoring sessions can help maintain code quality and reduce technical debt.",
        "Encourage pair programming to improve code quality and knowledge sharing among team members."
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

    tab1, tab2, tab3 = st.tabs(["📊 Overview", "🔍 Detailed Analysis", "📈 Trends"])

    with tab1:
        st.markdown(f"<h2 style='color:{ACCENT_COLOR};'>📊 Analysis Overview</h2>", unsafe_allow_html=True)
        display_metrics(summary, filtered_df)
        
        col1, col2 = st.columns(2)
        with col1:
            severity_chart = create_severity_chart(summary)
            st.plotly_chart(severity_chart, use_container_width=True)
        
        with col2:
            type_chart = create_type_chart(summary)
            st.plotly_chart(type_chart, use_container_width=True)

    with tab2:
        st.markdown(f"<h2 style='color:{ACCENT_COLOR};'>🔍 Detailed Issue Analysis</h2>", unsafe_allow_html=True)
        display_issues(filtered_df)

        if st.button("📤 Export Analysis Report"):
            excel_file = export_issues()
            if excel_file:
                st.download_button(
                    label="📥 Download Comprehensive Report",
                    data=excel_file,
                    file_name="pingen_code_analysis_report.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

    with tab3:
        st.markdown(f"<h2 style='color:{ACCENT_COLOR};'>📈 Issue Trends</h2>", unsafe_allow_html=True)
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