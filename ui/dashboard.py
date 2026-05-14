"""
SecureGate Dashboard - Simple Working Version
Based on app.py, incrementally built with working features only
"""

import streamlit as st
import requests
import json
from typing import Dict, Any
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from ui.prompt_examples import get_prompt_examples_db


# Initialize session state
def init_session_state():
    """Initialize session state variables"""
    if 'user_input' not in st.session_state:
        st.session_state.user_input = ""
    if 'last_result' not in st.session_state:
        st.session_state.last_result = None
    if 'page' not in st.session_state:
        st.session_state.page = "chat"


def test_api_connection() -> bool:
    """Test if API is available"""
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        return response.status_code == 200
    except:
        return False


def send_message(message: str) -> Dict[str, Any]:
    """Send message to API and return result"""
    try:
        response = requests.post(
            "http://localhost:8000/api/chat",
            json={"message": message},
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API Error: {response.status_code}")
            return None
    except Exception as e:
        st.error(f"Request failed: {e}")
        return None


def render_chat_page():
    """Render the chat interface page"""
    st.header("Secure Chat")
    
    # Check API connection
    if not test_api_connection():
        st.error("API is not available. Please start the backend server.")
        return
    
    # Input area
    st.subheader("Enter your message:")
    
    # Text input
    user_input = st.text_area(
        "Message",
        value=st.session_state.user_input,
        height=100,
        key="message_input"
    )
    
    # Update session state
    st.session_state.user_input = user_input
    
    # Action buttons
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Send Message", type="primary"):
            if user_input.strip():
                with st.spinner("Processing..."):
                    result = send_message(user_input)
                    if result:
                        st.session_state.last_result = result
                        st.rerun()
            else:
                st.warning("Please enter a message")
    
    with col2:
        if st.button("Load Malicious Example"):
            try:
                db = get_prompt_examples_db()
                malicious = db.get_malicious_examples()
                if malicious:
                    st.session_state.user_input = malicious[0].text
                    st.rerun()
                else:
                    st.error("No malicious examples available")
            except Exception as e:
                st.error(f"Failed to load example: {e}")
    
    with col3:
        if st.button("Load Benign Example"):
            try:
                db = get_prompt_examples_db()
                benign = db.get_benign_examples()
                if benign:
                    st.session_state.user_input = benign[0].text
                    st.rerun()
                else:
                    st.error("No benign examples available")
            except Exception as e:
                st.error(f"Failed to load example: {e}")
    
    # Display results
    if st.session_state.last_result:
        render_results(st.session_state.last_result)


def render_results(data: Dict[str, Any]):
    """Render analysis results"""
    st.markdown("---")
    st.header("Analysis Results")
    
    # Risk scores
    col1, col2, col3 = st.columns(3)
    
    with col1:
        inbound_score = data.get('inbound_risk_score', 0)
        st.metric("Inbound Risk Score", f"{inbound_score:.3f}")
        if inbound_score >= 0.7:
            st.error("HIGH RISK - Blocked")
        elif inbound_score >= 0.5:
            st.warning("MEDIUM RISK")
        else:
            st.success("LOW RISK")
    
    with col2:
        outbound_score = data.get('outbound_risk_score', 0)
        st.metric("Outbound Risk Score", f"{outbound_score:.3f}")
    
    with col3:
        transformer_score = data.get('transformer_score', 0)
        st.metric("Transformer Score", f"{transformer_score:.3f}")
    
    # Response
    st.subheader("Response")
    st.info(data.get('reply', 'No response'))
    
    # Detailed analysis
    with st.expander("View Detailed Analysis"):
        # Input/Output
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Input Analysis")
            st.text("Original:")
            st.code(data.get('original_prompt', 'N/A'))
            
            sanitized = data.get('sanitized_prompt', '')
            if sanitized and sanitized != data.get('original_prompt', ''):
                st.text("Sanitized:")
                st.code(sanitized)
        
        with col2:
            st.subheader("Output Analysis")
            st.text("Raw Response:")
            st.code(data.get('raw_reply', 'N/A'))
            
            sanitized_reply = data.get('sanitized_reply', '')
            if sanitized_reply and sanitized_reply != data.get('raw_reply', ''):
                st.text("Sanitized Response:")
                st.code(sanitized_reply)
        
        # Security flags
        st.subheader("Security Flags")
        inbound_flags = data.get('inbound_flags', [])
        if inbound_flags:
            st.text("Inbound Flags:")
            for flag in inbound_flags:
                st.warning(str(flag))
        
        outbound_flags = data.get('outbound_flags', [])
        if outbound_flags:
            st.text("Outbound Flags:")
            for flag in outbound_flags:
                st.warning(str(flag))
        
        # Detected entities
        entities = data.get('detected_entities', [])
        if entities:
            st.subheader("Detected Entities")
            for entity in entities:
                st.error(f"Entity: {entity}")
        
        # Explanations
        explanations = data.get('explanations', {})
        if explanations:
            st.subheader("Explanations")
            for key, explanation in explanations.items():
                st.info(f"**{key}:** {explanation}")
        
        # Performance
        latency = data.get('latency_ms', {})
        if latency:
            st.subheader("Performance Metrics")
            for component, time_ms in latency.items():
                st.text(f"{component}: {time_ms:.2f} ms")


def render_examples_page():
    """Render the examples page"""
    st.header("Prompt Examples")
    
    try:
        db = get_prompt_examples_db()
        
        # Filter selection
        filter_type = st.radio(
            "Select example type:",
            ["Malicious", "Benign", "All"],
            horizontal=True
        )
        
        # Get examples
        if filter_type == "Malicious":
            examples = db.get_malicious_examples()
            st.subheader(f"Malicious Examples ({len(examples)})")
        elif filter_type == "Benign":
            examples = db.get_benign_examples()
            st.subheader(f"Benign Examples ({len(examples)})")
        else:
            examples = db.examples
            st.subheader(f"All Examples ({len(examples)})")
        
        # Show examples
        for i, example in enumerate(examples[:10]):  # Show first 10
            with st.container():
                is_malicious = example.category.name.startswith("MALICIOUS")
                
                # Header
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"**Example {i+1}** - {example.difficulty}")
                with col2:
                    st.write("Malicious" if is_malicious else "Benign")
                
                # Description
                st.caption(example.description)
                
                # Prompt
                st.code(example.text)
                
                # Actions
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(f"Use Example {i+1}", key=f"use_{i}"):
                        st.session_state.user_input = example.text
                        st.session_state.page = "chat"
                        st.rerun()
                
                st.markdown("---")
    
    except Exception as e:
        st.error(f"Failed to load examples: {e}")


def render_system_page():
    """Render the system status page"""
    st.header("System Status")
    
    # API Health
    st.subheader("API Connection")
    if test_api_connection():
        st.success("API is online and healthy")
        
        try:
            # Get health data
            response = requests.get("http://localhost:8000/health", timeout=5)
            if response.status_code == 200:
                st.json(response.json())
            
            # Get metrics
            response = requests.get("http://localhost:8000/metrics", timeout=5)
            if response.status_code == 200:
                st.subheader("System Metrics")
                st.json(response.json())
        except:
            st.warning("Could not fetch detailed metrics")
    else:
        st.error("API is offline")
        st.info("Please start the backend server with: python app.py")


def main():
    """Main function"""
    st.set_page_config(
        page_title="SecureGate Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize session state
    init_session_state()
    
    # Sidebar
    with st.sidebar:
        st.title("SecureGate")
        st.markdown("---")
        
        # Navigation
        st.subheader("Navigation")
        
        if st.button("Chat Interface"):
            st.session_state.page = "chat"
            st.rerun()
        
        if st.button("Prompt Examples"):
            st.session_state.page = "examples"
            st.rerun()
        
        if st.button("System Status"):
            st.session_state.page = "system"
            st.rerun()
        
        st.markdown("---")
        
        # Quick test
        if st.button("Test API Connection"):
            if test_api_connection():
                st.success("API is online")
            else:
                st.error("API is offline")
    
    # Main content
    if st.session_state.page == "chat":
        render_chat_page()
    elif st.session_state.page == "examples":
        render_examples_page()
    elif st.session_state.page == "system":
        render_system_page()
    else:
        render_chat_page()


if __name__ == "__main__":
    main()
