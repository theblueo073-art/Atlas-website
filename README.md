# ATLAS — Attack Surface Mapping & Security Intelligence Platform

This is a GitHub-ready **repository scaffold** for the proposed ATLAS architecture. It includes the directory structure, documentation templates, safe configuration examples, and a GitHub Actions Python-check workflow. It does **not** contain the completed scanning application; replace placeholders with your actual tested source code.

## Quick start
1. Copy your working ATLAS source files into the matching folders.
2. Create a virtual environment: `python3 -m venv .venv`
3. Activate it: `source .venv/bin/activate`
4. Copy `.env.example` to `.env` and configure local values.
5. Add the actual packages your code needs to `requirements.txt`.
6. Install them: `pip install -r requirements.txt`

Only scan systems for which you have explicit permission. Validate target scope on the server, and never expose an unrestricted public scanning endpoint.

Do not commit `.env`, credentials, private keys, databases, or sensitive scan output. GitHub stores source code; it does not run the Flask app.
