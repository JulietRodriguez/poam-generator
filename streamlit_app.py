import streamlit as st

if "data_source" not in st.session_state:
    st.session_state["data_source"] = "AWS Security Hub"

from poam_generator.dashboard import main
main()
