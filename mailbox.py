#!/usr/bin/env python3

import sqlite3
import hashlib
import base64
import os
import shutil
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mailserver.db")
DOMAIN = "local.mail"
TRASH_RETENTION_DAYS = 30


class MailClient:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.conn = None
        self.current_user = None
        self.current_folder_name = "inbox"
        self._init_db()

    def _init_db(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._create_tables()
        self._seed_data()

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                is_system INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, name)
            );
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                sender_id INTEGER,
                from_addr TEXT NOT NULL,
                to_addrs TEXT NOT NULL DEFAULT '',
                cc_addrs TEXT NOT NULL DEFAULT '',
                subject TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL DEFAULT '',
                owner_id INTEGER NOT NULL,
                folder_id INTEGER NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                is_starred INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                deleted_at TEXT,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (owner_id) REFERENCES users(id),
                FOREIGN KEY (folder_id) REFERENCES folders(id)
            );
            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                data_base64 TEXT NOT NULL,
                size INTEGER NOT NULL,
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
            );
        """)
        self.conn.commit()

    def _hash_password(self, password):
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _get_user_by_username(self, username):
        row = self.conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None

    def _get_user_by_email(self, email):
        if not email.endswith(f"@{DOMAIN}"):
            return None
        username = email[: -len(f"@{DOMAIN}")]
        return self._get_user_by_username(username)

    def _email_addr(self, username):
        return f"{username}@{DOMAIN}"

    def _get_folder_id(self, user_id, folder_name):
        row = self.conn.execute(
            "SELECT id FROM folders WHERE user_id = ? AND name = ?",
            (user_id, folder_name),
        ).fetchone()
        return row["id"] if row else None

    def _get_or_create_folder(self, user_id, folder_name):
        fid = self._get_folder_id(user_id, folder_name)
        if fid is not None:
            return fid
        cursor = self.conn.execute(
            "INSERT INTO folders (user_id, name, is_system) VALUES (?, ?, 0)",
            (user_id, folder_name),
        )
        self.conn.commit()
        return cursor.lastrowid

    def _ensure_system_folders(self, user_id):
        for name in ("inbox", "sent", "draft", "trash", "starred"):
            existing = self.conn.execute(
                "SELECT id FROM folders WHERE user_id = ? AND name = ?",
                (user_id, name),
            ).fetchone()
            if not existing:
                self.conn.execute(
                    "INSERT INTO folders (user_id, name, is_system) VALUES (?, ?, 1)",
                    (user_id, name),
                )
        self.conn.commit()

    def _cleanup_trash(self, user_id=None):
        cutoff = (datetime.now() - timedelta(days=TRASH_RETENTION_DAYS)).isoformat()
        if user_id:
            trash_fid = self._get_folder_id(user_id, "trash")
            if trash_fid:
                self.conn.execute(
                    "DELETE FROM emails WHERE owner_id = ? AND folder_id = ? AND deleted_at < ?",
                    (user_id, trash_fid, cutoff),
                )
        else:
            self.conn.execute(
                "DELETE FROM emails WHERE folder_id IN (SELECT id FROM folders WHERE name = 'trash') AND deleted_at < ?",
                (cutoff,),
            )
        self.conn.commit()

    def _seed_data(self):
        count = self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count > 0:
            return
        test_users = [
            ("alice", "password123"),
            ("bob", "password123"),
            ("charlie", "password123"),
        ]
        for username, password in test_users:
            self._do_register(username, password)
        now = datetime.now()
        bob_id = self._get_user_by_username("bob")["id"]
        charlie_id = self._get_user_by_username("charlie")["id"]
        alice_id = self._get_user_by_username("alice")["id"]
        bob_folder_sent = self._get_folder_id(bob_id, "sent")
        charlie_folder_sent = self._get_folder_id(charlie_id, "sent")
        alice_folder_inbox = self._get_folder_id(alice_id, "inbox")
        seed_emails = [
            {
                "message_id": f"seed-{i}",
                "sender_id": bob_id,
                "from_addr": self._email_addr("bob"),
                "owner_id": alice_id,
                "folder_id": alice_folder_inbox,
                "to_addrs": self._email_addr("alice"),
                "cc_addrs": "",
                "subject": s,
                "body": b,
                "is_read": 0,
                "created_at": (now - timedelta(days=5 - i)).isoformat(),
            }
            for i, (s, b) in enumerate(
                [
                    ("Project Kickoff", "Hi Alice,\n\nLet's schedule a kickoff meeting for the new project this week.\n\nBest,\nBob"),
                    ("Code Review Request", "Hi Alice,\n\nCould you review my latest pull request? The changes are in the auth module.\n\nThanks,\nBob"),
                    ("Lunch Tomorrow?", "Hey Alice,\n\nWant to grab lunch tomorrow? I know a great new place downtown.\n\nCheers,\nBob"),
                ]
            )
        ] + [
            {
                "message_id": f"seed-{i+3}",
                "sender_id": charlie_id,
                "from_addr": self._email_addr("charlie"),
                "owner_id": alice_id,
                "folder_id": alice_folder_inbox,
                "to_addrs": self._email_addr("alice"),
                "cc_addrs": "",
                "subject": s,
                "body": b,
                "is_read": 0,
                "created_at": (now - timedelta(days=2 - (i - 3) if i >= 3 else 0)).isoformat(),
            }
            for i, (s, b) in enumerate(
                [
                    ("Weekend Hiking", "Hi Alice,\n\nAre you up for hiking this weekend? The weather forecast looks great!\n\n- Charlie"),
                    ("API Documentation", "Hey Alice,\n\nI've finished the API docs. Please take a look when you get a chance.\n\nCharlie"),
                ],
                start=3,
            )
        ]
        for email in seed_emails:
            self.conn.execute(
                """INSERT INTO emails
                   (message_id, sender_id, from_addr, to_addrs, cc_addrs, subject, body,
                    owner_id, folder_id, is_read, is_starred, created_at, deleted_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL)""",
                (
                    email["message_id"], email["sender_id"], email["from_addr"],
                    email["to_addrs"], email["cc_addrs"], email["subject"], email["body"],
                    email["owner_id"], email["folder_id"], email["is_read"], email["created_at"],
                ),
            )
        for email in seed_emails:
            sender_id = email["sender_id"]
            sent_fid = self._get_folder_id(sender_id, "sent")
            self.conn.execute(
                """INSERT INTO emails
                   (message_id, sender_id, from_addr, to_addrs, cc_addrs, subject, body,
                    owner_id, folder_id, is_read, is_starred, created_at, deleted_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, NULL)""",
                (
                    email["message_id"], email["sender_id"], email["from_addr"],
                    email["to_addrs"], email["cc_addrs"], email["subject"], email["body"],
                    sender_id, sent_fid, email["created_at"],
                ),
            )
        self.conn.commit()

    def _do_register(self, username, password):
        if self._get_user_by_username(username):
            return None
        pw_hash = self._hash_password(password)
        now = datetime.now().isoformat()
        cursor = self.conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, pw_hash, now),
        )
        self.conn.commit()
        user_id = cursor.lastrowid
        self._ensure_system_folders(user_id)
        return user_id

    def do_register(self, args):
        parts = args.strip().split(maxsplit=1)
        if len(parts) < 2:
            print("  Usage: register <username> <password>")
            return
        username, password = parts
        if "@" in username or " " in username:
            print("  Error: Username cannot contain '@' or spaces.")
            return
        if self._get_user_by_username(username):
            print(f"  Error: User '{username}' already exists.")
            return
        user_id = self._do_register(username, password)
        if user_id:
            print(f"  Registered: {self._email_addr(username)}")
        else:
            print("  Error: Registration failed.")

    def do_login(self, args):
        parts = args.strip().split(maxsplit=1)
        if len(parts) < 2:
            print("  Usage: login <username> <password>")
            return
        username, password = parts
        user = self._get_user_by_username(username)
        if not user or user["password_hash"] != self._hash_password(password):
            print("  Error: Invalid username or password.")
            return
        self.current_user = dict(user)
        self.current_folder_name = "inbox"
        self._cleanup_trash(user["id"])
        print(f"  Logged in as {self._email_addr(username)}")

    def do_logout(self, _args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        print(f"  Logged out from {self._email_addr(self.current_user['username'])}")
        self.current_user = None
        self.current_folder_name = "inbox"

    def do_switch(self, args):
        if not self.current_user:
            print("  Error: Not logged in. Use 'login' first.")
            return
        username = args.strip()
        if not username:
            print("  Usage: switch <username>")
            return
        user = self._get_user_by_username(username)
        if not user:
            print(f"  Error: User '{username}' not found.")
            return
        if user["id"] == self.current_user["id"]:
            print("  Already logged in as this user.")
            return
        pw = input("  Password: ").strip()
        if user["password_hash"] != self._hash_password(pw):
            print("  Error: Invalid password.")
            return
        self.current_user = dict(user)
        self.current_folder_name = "inbox"
        self._cleanup_trash(user["id"])
        print(f"  Switched to {self._email_addr(username)}")

    def do_whoami(self, _args):
        if not self.current_user:
            print("  Not logged in.")
        else:
            u = self.current_user
            print(f"  {self._email_addr(u['username'])}  (created: {u['created_at'][:19]})")

    def do_compose(self, _args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        print("  Compose new email (enter fields below, or 'cancel' at any prompt)")
        to_input = input("  To: ").strip()
        if to_input.lower() == "cancel":
            print("  Compose cancelled.")
            return
        cc_input = input("  CC: ").strip()
        if cc_input.lower() == "cancel":
            print("  Compose cancelled.")
            return
        subject = input("  Subject: ").strip()
        if subject.lower() == "cancel":
            print("  Compose cancelled.")
            return
        print("  Body (end with a single '.' on a line):")
        body_lines = []
        while True:
            try:
                line = input("  > ")
            except EOFError:
                break
            if line == ".":
                break
            body_lines.append(line)
        body = "\n".join(body_lines)

        attachments = []
        while True:
            cmd = input("  compose> ").strip()
            if not cmd:
                continue
            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            if action == "send":
                self._send_email(to_input, cc_input, subject, body, attachments)
                break
            elif action == "draft":
                self._save_draft(to_input, cc_input, subject, body, attachments)
                break
            elif action == "attach":
                if len(parts) < 2:
                    print("    Usage: attach <file_path>")
                    continue
                fpath = parts[1].strip().strip("'\"")
                if not os.path.isfile(fpath):
                    print(f"    Error: File not found: {fpath}")
                    continue
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    b64 = base64.b64encode(data).decode("utf-8")
                    fname = os.path.basename(fpath)
                    attachments.append({"filename": fname, "data_base64": b64, "size": len(data)})
                    print(f"    Attached: {fname} ({self._fmt_size(len(data))})")
                except Exception as e:
                    print(f"    Error reading file: {e}")
            elif action == "attachments":
                if not attachments:
                    print("    No attachments.")
                else:
                    for i, att in enumerate(attachments, 1):
                        print(f"    {i}. {att['filename']} ({self._fmt_size(att['size'])})")
            elif action in ("cancel", "quit", "exit"):
                print("  Compose cancelled.")
                break
            elif action == "help":
                print("    send       - Send the email")
                print("    draft      - Save as draft")
                print("    attach     - Attach a file: attach <path>")
                print("    attachments - List current attachments")
                print("    cancel     - Cancel composing")
                print("    help       - Show this help")
            else:
                print(f"    Unknown command: {action}. Type 'help' for options.")

    def _parse_recipients(self, addr_str):
        if not addr_str.strip():
            return []
        addrs = [a.strip() for a in addr_str.split(",") if a.strip()]
        result = []
        for addr in addrs:
            if "@" not in addr:
                addr = f"{addr}@{DOMAIN}"
            result.append(addr.lower())
        return result

    def _send_email(self, to_str, cc_str, subject, body, attachments):
        user_id = self.current_user["id"]
        from_addr = self._email_addr(self.current_user["username"])
        to_addrs = self._parse_recipients(to_str)
        cc_addrs = self._parse_recipients(cc_str)
        all_recipients = to_addrs + cc_addrs
        if not all_recipients:
            print("  Error: No recipients specified.")
            return
        now = datetime.now().isoformat()
        message_id = f"msg-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        sent_fid = self._get_folder_id(user_id, "sent")
        if sent_fid is None:
            sent_fid = self._get_or_create_folder(user_id, "sent")
        self._insert_email_copy(
            message_id, user_id, from_addr, ", ".join(to_addrs), ", ".join(cc_addrs),
            subject, body, user_id, sent_fid, is_read=1, created_at=now,
            attachments=attachments,
        )
        delivered = []
        bounced = []
        seen = set()
        for addr in all_recipients:
            if addr in seen:
                continue
            seen.add(addr)
            recipient = self._get_user_by_email(addr)
            if recipient:
                inbox_fid = self._get_folder_id(recipient["id"], "inbox")
                if inbox_fid is None:
                    inbox_fid = self._get_or_create_folder(recipient["id"], "inbox")
                self._insert_email_copy(
                    message_id, user_id, from_addr, ", ".join(to_addrs), ", ".join(cc_addrs),
                    subject, body, recipient["id"], inbox_fid, is_read=0, created_at=now,
                    attachments=attachments,
                )
                delivered.append(addr)
            else:
                bounced.append(addr)
        if bounced:
            bounce_subject = f"Delivery Failure: {subject}"
            bounce_body = (
                f"Your message to {', '.join(bounced)} could not be delivered.\n"
                f"The following recipients do not exist:\n"
            )
            for b in bounced:
                bounce_body += f"  - {b}\n"
            bounce_body += f"\nOriginal subject: {subject}"
            inbox_fid = self._get_folder_id(user_id, "inbox")
            if inbox_fid is None:
                inbox_fid = self._get_or_create_folder(user_id, "inbox")
            bounce_mid = f"bounce-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
            self._insert_email_copy(
                bounce_mid, None, "MAILER-DAEMON@local.mail", from_addr, "",
                bounce_subject, bounce_body, user_id, inbox_fid, is_read=0, created_at=now,
            )
        if delivered:
            print(f"  Email sent to: {', '.join(delivered)}")
        if bounced:
            print(f"  Delivery failed for: {', '.join(bounced)} (bounce notification in inbox)")

    def _save_draft(self, to_str, cc_str, subject, body, attachments):
        user_id = self.current_user["id"]
        from_addr = self._email_addr(self.current_user["username"])
        now = datetime.now().isoformat()
        draft_fid = self._get_folder_id(user_id, "draft")
        if draft_fid is None:
            draft_fid = self._get_or_create_folder(user_id, "draft")
        message_id = f"draft-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        self._insert_email_copy(
            message_id, user_id, from_addr, to_str, cc_str,
            subject, body, user_id, draft_fid, is_read=0, created_at=now,
            attachments=attachments,
        )
        print("  Draft saved.")

    def _insert_email_copy(self, message_id, sender_id, from_addr, to_addrs, cc_addrs,
                           subject, body, owner_id, folder_id, is_read=0, created_at=None,
                           attachments=None):
        if created_at is None:
            created_at = datetime.now().isoformat()
        cursor = self.conn.execute(
            """INSERT INTO emails
               (message_id, sender_id, from_addr, to_addrs, cc_addrs, subject, body,
                owner_id, folder_id, is_read, is_starred, created_at, deleted_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL)""",
            (message_id, sender_id, from_addr, to_addrs, cc_addrs, subject, body,
             owner_id, folder_id, is_read, created_at),
        )
        email_id = cursor.lastrowid
        if attachments:
            for att in attachments:
                self.conn.execute(
                    "INSERT INTO attachments (email_id, filename, data_base64, size) VALUES (?, ?, ?, ?)",
                    (email_id, att["filename"], att["data_base64"], att["size"]),
                )
        self.conn.commit()
        return email_id

    def _get_folder_emails(self, user_id, folder_name, order_by="date_desc"):
        fid = self._get_folder_id(user_id, folder_name)
        if fid is None:
            return []
        order_clause = "created_at DESC"
        if order_by == "date_asc":
            order_clause = "created_at ASC"
        elif order_by == "sender_asc":
            order_clause = "from_addr ASC"
        elif order_by == "sender_desc":
            order_clause = "from_addr DESC"
        rows = self.conn.execute(
            f"""SELECT e.*, 
                (SELECT COUNT(*) FROM attachments WHERE email_id = e.id) AS attachment_count
                FROM emails e
                WHERE e.owner_id = ? AND e.folder_id = ?
                ORDER BY {order_clause}""",
            (user_id, fid),
        ).fetchall()
        return [dict(r) for r in rows]

    def _get_email_by_id(self, email_id, user_id):
        row = self.conn.execute(
            """SELECT e.*,
                (SELECT COUNT(*) FROM attachments WHERE email_id = e.id) AS attachment_count
                FROM emails e
                WHERE e.id = ? AND e.owner_id = ?""",
            (email_id, user_id),
        ).fetchone()
        return dict(row) if row else None

    def do_inbox(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        folder_name = args.strip() if args.strip() else self.current_folder_name
        self._list_folder(folder_name)

    def do_folder(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        name = args.strip()
        if not name:
            self._show_folders()
            return
        user_id = self.current_user["id"]
        fid = self._get_folder_id(user_id, name)
        if fid is None:
            print(f"  Error: Folder '{name}' not found. Use 'mkdir' to create it.")
            return
        self.current_folder_name = name
        self._list_folder(name)

    def _show_folders(self):
        user_id = self.current_user["id"]
        rows = self.conn.execute(
            """SELECT f.name, f.is_system,
                (SELECT COUNT(*) FROM emails WHERE owner_id = ? AND folder_id = f.id) AS total,
                (SELECT COUNT(*) FROM emails WHERE owner_id = ? AND folder_id = f.id AND is_read = 0) AS unread
                FROM folders f
                WHERE f.user_id = ?
                ORDER BY f.is_system DESC, f.name ASC""",
            (user_id, user_id, user_id),
        ).fetchall()
        print(f"\n  {'Folder':<16} {'Total':>5} {'Unread':>7}")
        print("  " + "-" * 32)
        for r in rows:
            marker = " *" if r["name"] == self.current_folder_name else ""
            sys_mark = " (system)" if r["is_system"] else ""
            print(f"  {r['name'] + marker:<16} {r['total']:>5} {r['unread']:>7}{sys_mark}")
        print()

    def _list_folder(self, folder_name, emails=None):
        user_id = self.current_user["id"]
        if emails is None:
            emails = self._get_folder_emails(user_id, folder_name)
        self.current_folder_name = folder_name
        print(f"\n  === {folder_name.upper()} ===")
        if not emails:
            print("  (empty)")
            print()
            return
        print(f"  {'#':<4} {'Read':<5} {'Star':<5} {'From':<24} {'Subject':<30} {'Date':<12} {'Att':<3}")
        print("  " + "-" * 88)
        for i, e in enumerate(emails, 1):
            read_mark = " " if e["is_read"] else "\u2605"
            star_mark = "\u2605" if e["is_starred"] else " "
            from_addr = e["from_addr"][:22]
            subject = e["subject"][:28]
            date_str = e["created_at"][:10]
            att_mark = "+" if e["attachment_count"] > 0 else " "
            print(f"  {i:<4} {read_mark:<5} {star_mark:<5} {from_addr:<24} {subject:<30} {date_str:<12} {att_mark:<3}")
        print()

    def do_read(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        try:
            email_num = int(args.strip())
        except (ValueError, IndexError):
            print("  Usage: read <number>")
            return
        user_id = self.current_user["id"]
        emails = self._get_folder_emails(user_id, self.current_folder_name)
        if email_num < 1 or email_num > len(emails):
            print(f"  Error: Invalid email number. Range: 1-{len(emails)}")
            return
        email = emails[email_num - 1]
        if not email["is_read"]:
            self.conn.execute(
                "UPDATE emails SET is_read = 1 WHERE id = ?", (email["id"],)
            )
            self.conn.commit()
        print(f"\n  From    : {email['from_addr']}")
        print(f"  To      : {email['to_addrs']}")
        if email["cc_addrs"]:
            print(f"  CC      : {email['cc_addrs']}")
        print(f"  Subject : {email['subject']}")
        print(f"  Date    : {email['created_at'][:19]}")
        print(f"  Starred : {'Yes' if email['is_starred'] else 'No'}")
        atts = self.conn.execute(
            "SELECT id, filename, size FROM attachments WHERE email_id = ?",
            (email["id"],),
        ).fetchall()
        if atts:
            print(f"  Attachments ({len(atts)}):")
            for a in atts:
                print(f"    - {a['filename']} ({self._fmt_size(a['size'])})")
        print("  " + "-" * 60)
        for line in email["body"].split("\n"):
            print(f"  {line}")
        print("  " + "-" * 60)
        print()

    def do_star(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        try:
            email_num = int(args.strip())
        except ValueError:
            print("  Usage: star <number>")
            return
        user_id = self.current_user["id"]
        emails = self._get_folder_emails(user_id, self.current_folder_name)
        if email_num < 1 or email_num > len(emails):
            print(f"  Error: Invalid email number. Range: 1-{len(emails)}")
            return
        email = emails[email_num - 1]
        new_star = 0 if email["is_starred"] else 1
        self.conn.execute(
            "UPDATE emails SET is_starred = ? WHERE id = ?", (new_star, email["id"])
        )
        self.conn.commit()
        if new_star:
            starred_fid = self._get_folder_id(user_id, "starred")
            if starred_fid:
                existing = self.conn.execute(
                    "SELECT id FROM emails WHERE owner_id = ? AND folder_id = ? AND message_id = ?",
                    (user_id, starred_fid, email["message_id"]),
                ).fetchone()
                if not existing:
                    self._insert_email_copy(
                        email["message_id"], email["sender_id"], email["from_addr"],
                        email["to_addrs"], email["cc_addrs"], email["subject"], email["body"],
                        user_id, starred_fid, is_read=email["is_read"],
                        created_at=email["created_at"],
                    )
            print("  Email starred.")
        else:
            starred_fid = self._get_folder_id(user_id, "starred")
            if starred_fid:
                self.conn.execute(
                    "DELETE FROM emails WHERE owner_id = ? AND folder_id = ? AND message_id = ?",
                    (user_id, starred_fid, email["message_id"]),
                )
                self.conn.commit()
            print("  Star removed.")

    def do_mark(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        parts = args.strip().split(maxsplit=1)
        if len(parts) < 2:
            print("  Usage: mark <number> <read|unread>")
            return
        try:
            email_num = int(parts[0])
        except ValueError:
            print("  Usage: mark <number> <read|unread>")
            return
        status = parts[1].lower()
        if status not in ("read", "unread"):
            print("  Usage: mark <number> <read|unread>")
            return
        user_id = self.current_user["id"]
        emails = self._get_folder_emails(user_id, self.current_folder_name)
        if email_num < 1 or email_num > len(emails):
            print(f"  Error: Invalid email number. Range: 1-{len(emails)}")
            return
        email = emails[email_num - 1]
        is_read = 1 if status == "read" else 0
        self.conn.execute("UPDATE emails SET is_read = ? WHERE id = ?", (is_read, email["id"]))
        self.conn.commit()
        print(f"  Email marked as {status}.")

    def do_delete(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        try:
            email_num = int(args.strip())
        except ValueError:
            print("  Usage: delete <number>")
            return
        user_id = self.current_user["id"]
        emails = self._get_folder_emails(user_id, self.current_folder_name)
        if email_num < 1 or email_num > len(emails):
            print(f"  Error: Invalid email number. Range: 1-{len(emails)}")
            return
        email = emails[email_num - 1]
        if self.current_folder_name == "trash":
            self.conn.execute("DELETE FROM attachments WHERE email_id = ?", (email["id"],))
            self.conn.execute("DELETE FROM emails WHERE id = ?", (email["id"],))
            self.conn.commit()
            print("  Email permanently deleted.")
        else:
            trash_fid = self._get_or_create_folder(user_id, "trash")
            self.conn.execute(
                "UPDATE emails SET folder_id = ?, deleted_at = ? WHERE id = ?",
                (trash_fid, datetime.now().isoformat(), email["id"]),
            )
            self.conn.commit()
            print("  Email moved to trash.")

    def do_move(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        parts = args.strip().split(maxsplit=1)
        if len(parts) < 2:
            print("  Usage: move <number> <folder_name>")
            return
        try:
            email_num = int(parts[0])
        except ValueError:
            print("  Usage: move <number> <folder_name>")
            return
        target_folder = parts[1].strip()
        user_id = self.current_user["id"]
        emails = self._get_folder_emails(user_id, self.current_folder_name)
        if email_num < 1 or email_num > len(emails):
            print(f"  Error: Invalid email number. Range: 1-{len(emails)}")
            return
        email = emails[email_num - 1]
        target_fid = self._get_folder_id(user_id, target_folder)
        if target_fid is None:
            print(f"  Error: Folder '{target_folder}' not found. Use 'mkdir' to create it.")
            return
        self.conn.execute(
            "UPDATE emails SET folder_id = ? WHERE id = ?",
            (target_fid, email["id"]),
        )
        self.conn.commit()
        print(f"  Email moved to '{target_folder}'.")

    def do_mkdir(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        name = args.strip()
        if not name:
            print("  Usage: mkdir <folder_name>")
            return
        system_folders = {"inbox", "sent", "draft", "trash", "starred"}
        if name.lower() in system_folders:
            print("  Error: Cannot create a folder with a system name.")
            return
        user_id = self.current_user["id"]
        existing = self._get_folder_id(user_id, name)
        if existing:
            print(f"  Error: Folder '{name}' already exists.")
            return
        self._get_or_create_folder(user_id, name)
        print(f"  Folder '{name}' created.")

    def do_rmdir(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        name = args.strip()
        if not name:
            print("  Usage: rmdir <folder_name>")
            return
        system_folders = {"inbox", "sent", "draft", "trash", "starred"}
        if name.lower() in system_folders:
            print("  Error: Cannot remove system folders.")
            return
        user_id = self.current_user["id"]
        fid = self._get_folder_id(user_id, name)
        if fid is None:
            print(f"  Error: Folder '{name}' not found.")
            return
        inbox_fid = self._get_folder_id(user_id, "inbox")
        if inbox_fid:
            self.conn.execute(
                "UPDATE emails SET folder_id = ? WHERE owner_id = ? AND folder_id = ?",
                (inbox_fid, user_id, fid),
            )
        self.conn.execute("DELETE FROM folders WHERE id = ?", (fid,))
        self.conn.commit()
        if self.current_folder_name == name:
            self.current_folder_name = "inbox"
        print(f"  Folder '{name}' removed. Emails moved to inbox.")

    def do_search(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        keyword = args.strip()
        if not keyword:
            print("  Usage: search <keyword>")
            return
        user_id = self.current_user["id"]
        like_kw = f"%{keyword}%"
        rows = self.conn.execute(
            """SELECT e.*,
                (SELECT COUNT(*) FROM attachments WHERE email_id = e.id) AS attachment_count
                FROM emails e
                WHERE e.owner_id = ? AND (e.subject LIKE ? OR e.body LIKE ?)
                ORDER BY e.created_at DESC""",
            (user_id, like_kw, like_kw),
        ).fetchall()
        emails = [dict(r) for r in rows]
        folder_names = {}
        for e in emails:
            if e["folder_id"] not in folder_names:
                row = self.conn.execute(
                    "SELECT name FROM folders WHERE id = ?", (e["folder_id"],)
                ).fetchone()
                folder_names[e["folder_id"]] = row["name"] if row else "?"
        if not emails:
            print(f"  No emails found matching '{keyword}'.")
            return
        print(f"\n  Search results for '{keyword}':")
        print(f"  {'#':<4} {'Read':<5} {'Star':<5} {'From':<24} {'Subject':<30} {'Date':<12} {'Folder':<10}")
        print("  " + "-" * 95)
        for i, e in enumerate(emails, 1):
            read_mark = " " if e["is_read"] else "\u2605"
            star_mark = "\u2605" if e["is_starred"] else " "
            from_addr = e["from_addr"][:22]
            subject = e["subject"][:28]
            date_str = e["created_at"][:10]
            fname = folder_names.get(e["folder_id"], "?")
            print(f"  {i:<4} {read_mark:<5} {star_mark:<5} {from_addr:<24} {subject:<30} {date_str:<12} {fname:<10}")
        print()
        self._search_results = emails

    def do_filter(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        user_id = self.current_user["id"]
        parts = args.strip().split()
        if not parts:
            print("  Usage: filter [--from <sender>] [--date <YYYY-MM-DD>] [--before <YYYY-MM-DD>]")
            print("                [--after <YYYY-MM-DD>] [--unread] [--read] [--has-attachment]")
            return
        conditions = ["e.owner_id = ?"]
        params = [user_id]
        i = 0
        while i < len(parts):
            flag = parts[i]
            if flag == "--from" and i + 1 < len(parts):
                sender = parts[i + 1]
                conditions.append("e.from_addr LIKE ?")
                params.append(f"%{sender}%")
                i += 2
            elif flag == "--date" and i + 1 < len(parts):
                date_val = parts[i + 1]
                conditions.append("DATE(e.created_at) = ?")
                params.append(date_val)
                i += 2
            elif flag == "--before" and i + 1 < len(parts):
                date_val = parts[i + 1]
                conditions.append("DATE(e.created_at) < ?")
                params.append(date_val)
                i += 2
            elif flag == "--after" and i + 1 < len(parts):
                date_val = parts[i + 1]
                conditions.append("DATE(e.created_at) > ?")
                params.append(date_val)
                i += 2
            elif flag == "--unread":
                conditions.append("e.is_read = 0")
                i += 1
            elif flag == "--read":
                conditions.append("e.is_read = 1")
                i += 1
            elif flag == "--has-attachment":
                conditions.append(
                    "e.id IN (SELECT email_id FROM attachments)"
                )
                i += 1
            else:
                print(f"  Unknown filter option: {flag}")
                return
        where = " AND ".join(conditions)
        rows = self.conn.execute(
            f"""SELECT e.*,
                (SELECT COUNT(*) FROM attachments WHERE email_id = e.id) AS attachment_count
                FROM emails e
                WHERE {where}
                ORDER BY e.created_at DESC""",
            params,
        ).fetchall()
        emails = [dict(r) for r in rows]
        if not emails:
            print("  No emails match the filter.")
            return
        print(f"\n  Filtered results ({len(emails)} emails):")
        print(f"  {'#':<4} {'Read':<5} {'Star':<5} {'From':<24} {'Subject':<30} {'Date':<12}")
        print("  " + "-" * 82)
        for i, e in enumerate(emails, 1):
            read_mark = " " if e["is_read"] else "\u2605"
            star_mark = "\u2605" if e["is_starred"] else " "
            from_addr = e["from_addr"][:22]
            subject = e["subject"][:28]
            date_str = e["created_at"][:10]
            print(f"  {i:<4} {read_mark:<5} {star_mark:<5} {from_addr:<24} {subject:<30} {date_str:<12}")
        print()
        self._filter_results = emails

    def do_sort(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        field = args.strip().lower()
        order_map = {
            "date": "date_desc",
            "date-desc": "date_desc",
            "date-asc": "date_asc",
            "sender": "sender_asc",
            "sender-asc": "sender_asc",
            "sender-desc": "sender_desc",
        }
        if field not in order_map:
            print("  Usage: sort <date|date-asc|date-desc|sender|sender-asc|sender-desc>")
            return
        emails = self._get_folder_emails(self.current_user["id"], self.current_folder_name, order_map[field])
        self._list_folder(self.current_folder_name, emails)

    def do_attachments(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        try:
            email_num = int(args.strip())
        except ValueError:
            print("  Usage: attachments <number>")
            return
        user_id = self.current_user["id"]
        emails = self._get_folder_emails(user_id, self.current_folder_name)
        if email_num < 1 or email_num > len(emails):
            print(f"  Error: Invalid email number. Range: 1-{len(emails)}")
            return
        email = emails[email_num - 1]
        atts = self.conn.execute(
            "SELECT id, filename, size FROM attachments WHERE email_id = ?",
            (email["id"],),
        ).fetchall()
        if not atts:
            print("  No attachments.")
            return
        print(f"\n  Attachments for email: {email['subject']}")
        for i, a in enumerate(atts, 1):
            print(f"    {i}. {a['filename']} ({self._fmt_size(a['size'])})")
        print()

    def do_save_attachment(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        parts = args.strip().split(maxsplit=1)
        if len(parts) < 2:
            print("  Usage: save-attachment <email_number> <attachment_number|output_path>")
            return
        try:
            email_num = int(parts[0])
        except ValueError:
            print("  Usage: save-attachment <email_number> <attachment_number|output_path>")
            return
        user_id = self.current_user["id"]
        emails = self._get_folder_emails(user_id, self.current_folder_name)
        if email_num < 1 or email_num > len(emails):
            print(f"  Error: Invalid email number. Range: 1-{len(emails)}")
            return
        email = emails[email_num - 1]
        atts = self.conn.execute(
            "SELECT id, filename, data_base64, size FROM attachments WHERE email_id = ?",
            (email["id"],),
        ).fetchall()
        if not atts:
            print("  No attachments on this email.")
            return
        second = parts[1]
        try:
            att_idx = int(second)
            if att_idx < 1 or att_idx > len(atts):
                print(f"  Error: Attachment number out of range. Range: 1-{len(atts)}")
                return
            att = atts[att_idx - 1]
            output_path = att["filename"]
        except ValueError:
            att = atts[0]
            output_path = second
        try:
            data = base64.b64decode(att["data_base64"])
            with open(output_path, "wb") as f:
                f.write(data)
            print(f"  Attachment saved to: {output_path} ({self._fmt_size(att['size'])})")
        except Exception as e:
            print(f"  Error saving attachment: {e}")

    @staticmethod
    def _fmt_size(size):
        if size < 1024:
            return f"{size}B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f}KB"
        else:
            return f"{size / (1024 * 1024):.1f}MB"

    def do_help(self, _args):
        print("""
  Available Commands:
  ─────────────────────────────────────────────────────
  Account:
    register <user> <pass>    Register a new email account
    login <user> <pass>       Log in to an account
    logout                    Log out of current account
    switch <user>             Switch to another account
    whoami                    Show current user info

  Email:
    compose                   Compose a new email
    inbox [folder]            List emails in current/specified folder
    read <num>                Read an email
    delete <num>              Delete an email (move to trash)
    star <num>                Toggle star on an email
    mark <num> <read|unread>  Mark email as read/unread
    move <num> <folder>       Move email to a folder

  Folders:
    folder [name]             List folders / switch to folder
    mkdir <name>              Create a custom folder
    rmdir <name>              Remove a custom folder

  Search & Filter:
    search <keyword>          Search emails by subject+body
    filter [options]          Filter emails (see filter help)
    sort <field>              Sort emails (date, sender)

  Attachments:
    attachments <num>         List attachments of an email
    save-attachment <num> <att#|path>  Save attachment to disk

  Other:
    help                      Show this help
    quit / exit               Exit the program
  ─────────────────────────────────────────────────────
        """)

    def do_quit(self, _args):
        if self.conn:
            self.conn.close()
        print("  Goodbye!")
        return True

    do_exit = do_quit

    def run(self):
        print()
        print("  ╔══════════════════════════════════════╗")
        print("  ║     Local Mail Client v1.0           ║")
        print("  ║     Domain: @local.mail              ║")
        print("  ╚══════════════════════════════════════╝")
        print()
        print("  Type 'help' for available commands.")
        print("  Preset accounts: alice, bob, charlie (password: password123)")
        print()
        self._search_results = []
        self._filter_results = []
        while True:
            try:
                if self.current_user:
                    prompt = f"  {self.current_user['username']}@{self.current_folder_name}> "
                else:
                    prompt = "  mail> "
                cmd_line = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                self.do_quit(None)
                break
            if not cmd_line:
                continue
            parts = cmd_line.split(maxsplit=1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""
            cmd_map = {
                "register": self.do_register,
                "login": self.do_login,
                "logout": self.do_logout,
                "switch": self.do_switch,
                "whoami": self.do_whoami,
                "compose": self.do_compose,
                "inbox": self.do_inbox,
                "folder": self.do_folder,
                "folders": self.do_folder,
                "read": self.do_read,
                "delete": self.do_delete,
                "star": self.do_star,
                "mark": self.do_mark,
                "move": self.do_move,
                "mkdir": self.do_mkdir,
                "rmdir": self.do_rmdir,
                "search": self.do_search,
                "filter": self.do_filter,
                "sort": self.do_sort,
                "attachments": self.do_attachments,
                "save-attachment": self.do_save_attachment,
                "help": self.do_help,
                "quit": self.do_quit,
                "exit": self.do_exit,
            }
            handler = cmd_map.get(command)
            if handler:
                result = handler(args)
                if result is True:
                    break
            else:
                print(f"  Unknown command: {command}. Type 'help' for available commands.")


if __name__ == "__main__":
    client = MailClient()
    client.run()
