import base64
import sys
from email.mime.text import MIMEText
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from mcp.server.mcpserver import MCPServer

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
]

PROJECT_DIR = Path(__file__).resolve().parent.parent
CREDENTIALS_FILE = PROJECT_DIR / "credentials.json"
TOKEN_FILE = PROJECT_DIR / "token.json"

mcp = MCPServer("Gmail OAuth Manager")
_creds = None
_gmail_service = None


def save_token(creds):
    TOKEN_FILE.write_text(creds.to_json(), encoding="utf-8")


def get_gmail_service():
    """Load Gmail credentials from token.json, or sign in once and save it."""
    global _creds, _gmail_service

    if _gmail_service is not None and _creds is not None and _creds.valid:
        return _gmail_service

    if TOKEN_FILE.exists():
        _creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)

    if not _creds or not _creds.valid:
        if _creds and _creds.expired and _creds.refresh_token:
            _creds.refresh(Request())
            save_token(_creds)
        else:
            if not CREDENTIALS_FILE.exists():
                raise FileNotFoundError(f"Missing OAuth client file: {CREDENTIALS_FILE}")
            flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), SCOPES)
            _creds = flow.run_local_server(port=0)
            save_token(_creds)

    _gmail_service = build("gmail", "v1", credentials=_creds)
    return _gmail_service


@mcp.tool()
def read_latest_emails(count: int = 5) -> str:
    """Read latest email subjects from your inbox securely via OAuth."""
    try:
        service = get_gmail_service()
        results = service.users().messages().list(
            userId="me", maxResults=count, labelIds=["INBOX"]
        ).execute()
        messages = results.get("messages", [])

        if not messages:
            return "No emails found inside the inbox."

        output = []
        for msg in messages:
            txt = service.users().messages().get(userId="me", id=msg["id"]).execute()
            headers = txt["payload"]["headers"]
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")
            output.append(f"From: {sender}\nSubject: {subject}\n---")

        return "\n".join(output)
    except Exception as e:
        return f"Gmail Read Error: {str(e)}"


@mcp.tool()
def send_email(to_address: str, subject: str, body: str) -> str:
    """Send an email using secure API transmission."""
    try:
        service = get_gmail_service()
        message = MIMEText(body)
        message["to"] = to_address
        message["subject"] = subject

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
        service.users().messages().send(userId="me", body={"raw": raw_message}).execute()
        return f"Email successfully transmitted to {to_address}."
    except Exception as e:
        return f"Gmail Send Error: {str(e)}"


if __name__ == "__main__":
    if "--login" in sys.argv:
        print("A browser window will open. Sign in with the Gmail account you want the LLM to use.", flush=True)
        get_gmail_service()
        print(f"Login complete. Saved {TOKEN_FILE}", flush=True)
        print("You can now use Gmail from Cursor. Ask: read my latest emails", flush=True)
    elif "--stdio" in sys.argv:
        mcp.run()
    elif "--serve" in sys.argv:
        print("Starting Gmail MCP server...", flush=True)
        print("Tools: read_latest_emails, send_email", flush=True)
        print("Listening at http://127.0.0.1:8765/mcp", flush=True)
        print("Leave this window open. Press Ctrl+C to stop.", flush=True)
        mcp.run("streamable-http", host="127.0.0.1", port=8765)
    else:
        print("Connecting to Gmail...", flush=True)
        print("-" * 40, flush=True)
        print(read_latest_emails(), flush=True)
        print("-" * 40, flush=True)
        print("Done. Inbox printed above.", flush=True)
