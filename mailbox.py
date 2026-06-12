#!/usr/bin/env python3

import sqlite3
import hashlib
import base64
import os
import shutil
import json
import re
import fnmatch
import argparse
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mailserver.db")
DOMAIN = "local.mail"
TRASH_RETENTION_DAYS = 30
RSA_KEY_SIZE = 2048


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
        self._migrate_existing_users_keys()
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
                is_encrypted INTEGER NOT NULL DEFAULT 0,
                is_signed INTEGER NOT NULL DEFAULT 0,
                signature TEXT,
                encryption_key_id INTEGER,
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
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 0,
                cond_from TEXT,
                cond_subject TEXT,
                cond_has_attachment INTEGER,
                action_type TEXT NOT NULL,
                action_param TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                subject TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, name)
            );
            CREATE TABLE IF NOT EXISTS user_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                public_key_pem TEXT NOT NULL,
                private_key_pem TEXT NOT NULL,
                key_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        self.conn.commit()

    def _hash_password(self, password):
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _generate_rsa_keypair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(der).hexdigest()
        return public_pem, private_pem, fingerprint

    def _get_user_keys(self, user_id):
        row = self.conn.execute(
            "SELECT * FROM user_keys WHERE user_id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else None

    def _load_public_key(self, pem_str):
        return serialization.load_pem_public_key(
            pem_str.encode("utf-8"), backend=default_backend()
        )

    def _load_private_key(self, pem_str):
        return serialization.load_pem_private_key(
            pem_str.encode("utf-8"), password=None, backend=default_backend()
        )

    def _encrypt_with_public_key(self, plaintext, public_key_pem):
        pub_key = self._load_public_key(public_key_pem)
        chunk_size = RSA_KEY_SIZE // 8 - 42
        data = plaintext.encode("utf-8")
        encrypted_chunks = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            enc = pub_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(base64.b64encode(enc).decode("utf-8"))
        return json.dumps(encrypted_chunks)

    def _decrypt_with_private_key(self, encrypted_json, private_key_pem):
        priv_key = self._load_private_key(private_key_pem)
        try:
            chunks = json.loads(encrypted_json)
        except (json.JSONDecodeError, TypeError):
            return None
        decrypted = b""
        try:
            for chunk_b64 in chunks:
                chunk = base64.b64decode(chunk_b64)
                dec = priv_key.decrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted += dec
            return decrypted.decode("utf-8")
        except Exception:
            return None

    def _sign_data(self, data_str, private_key_pem):
        priv_key = self._load_private_key(private_key_pem)
        signature = priv_key.sign(
            data_str.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode("utf-8")

    def _verify_signature(self, data_str, signature_b64, public_key_pem):
        try:
            pub_key = self._load_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64)
            pub_key.verify(
                signature,
                data_str.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def _ensure_user_keys(self, user_id):
        existing = self._get_user_keys(user_id)
        if existing:
            return
        public_pem, private_pem, fingerprint = self._generate_rsa_keypair()
        self.conn.execute(
            "INSERT INTO user_keys (user_id, public_key_pem, private_key_pem, key_fingerprint, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, public_pem, private_pem, fingerprint, datetime.now().isoformat())
        )
        self.conn.commit()

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

    def _migrate_existing_users_keys(self):
        rows = self.conn.execute("SELECT id FROM users").fetchall()
        for r in rows:
            self._ensure_user_keys(r["id"])

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
        self._ensure_user_keys(user_id)
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

    def do_compose(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        encrypt = False
        sign = False
        remaining_args = args.strip()
        for flag in ("--encrypt", "--sign"):
            if flag in remaining_args.split():
                if flag == "--encrypt":
                    encrypt = True
                elif flag == "--sign":
                    sign = True
                remaining_args = remaining_args.replace(flag, "").strip()
        if encrypt:
            print("  [加密模式] 邮件将使用收件人公钥加密")
        if sign:
            print("  [签名模式] 邮件将使用您的私钥签名")
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
        attachments = []
        attach_input = input("  Attachments (file paths, comma-separated; Enter to skip): ").strip()
        if attach_input.lower() == "cancel":
            print("  Compose cancelled.")
            return
        if attach_input:
            for fpath in attach_input.split(","):
                fpath = fpath.strip().strip("'\"")
                if not fpath:
                    continue
                if not os.path.isfile(fpath):
                    print(f"    File not found, skipped: {fpath}")
                    continue
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    b64 = base64.b64encode(data).decode("utf-8")
                    fname = os.path.basename(fpath)
                    attachments.append({"filename": fname, "data_base64": b64, "size": len(data)})
                    print(f"    Attached: {fname} ({self._fmt_size(len(data))})")
                except Exception as e:
                    print(f"    Error reading file, skipped: {fpath} ({e})")
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
        self._send_email(to_input, cc_input, subject, body, attachments,
                         encrypt=encrypt, sign=sign)

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

    def _send_email(self, to_str, cc_str, subject, body, attachments,
                    encrypt=False, sign=False, per_recipient_vars=None):
        user_id = self.current_user["id"]
        username = self.current_user["username"]
        from_addr = self._email_addr(username)
        to_addrs = self._parse_recipients(to_str)
        cc_addrs = self._parse_recipients(cc_str)
        all_recipients = to_addrs + cc_addrs
        if not all_recipients:
            print("  Error: No recipients specified.")
            return
        now = datetime.now().isoformat()
        sender_keys = self._get_user_keys(user_id) if sign or encrypt else None
        signature = None
        if sign and sender_keys:
            sign_data = f"{subject}\n{body}\n{from_addr}"
            signature = self._sign_data(sign_data, sender_keys["private_key_pem"])
        base_message_id = f"msg-{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        sent_fid = self._get_folder_id(user_id, "sent")
        if sent_fid is None:
            sent_fid = self._get_or_create_folder(user_id, "sent")
        self._insert_email_copy(
            base_message_id, user_id, from_addr, ", ".join(to_addrs), ", ".join(cc_addrs),
            subject, body, user_id, sent_fid, is_read=1, created_at=now,
            attachments=attachments,
            is_encrypted=1 if encrypt else 0,
            is_signed=1 if sign else 0,
            signature=signature,
            encryption_key_id=sender_keys["id"] if encrypt and sender_keys else None,
        )
        delivered = []
        bounced = []
        seen = set()
        for idx, addr in enumerate(all_recipients):
            if addr in seen:
                continue
            seen.add(addr)
            recipient = self._get_user_by_email(addr)
            if recipient:
                inbox_fid = self._get_folder_id(recipient["id"], "inbox")
                if inbox_fid is None:
                    inbox_fid = self._get_or_create_folder(recipient["id"], "inbox")
                recip_to_str = addr
                recip_cc_str = ""
                recip_body = body
                vars = {}
                if per_recipient_vars and addr in per_recipient_vars:
                    vars = per_recipient_vars[addr]
                elif per_recipient_vars and "__default__" in per_recipient_vars:
                    vars = per_recipient_vars["__default__"]
                if vars:
                    recip_body = self._apply_template_vars(recip_body, vars)
                    recip_subject = self._apply_template_vars(subject, vars)
                else:
                    recip_subject = subject
                recip_signature = signature
                if sign and sender_keys and vars:
                    sign_data = f"{recip_subject}\n{recip_body}\n{from_addr}"
                    recip_signature = self._sign_data(sign_data, sender_keys["private_key_pem"])
                recip_encrypted = 0
                recip_encryption_key_id = None
                if encrypt:
                    recip_keys = self._get_user_keys(recipient["id"])
                    if recip_keys:
                        recip_body = self._encrypt_with_public_key(recip_body, recip_keys["public_key_pem"])
                        recip_encrypted = 1
                        recip_encryption_key_id = recip_keys["id"]
                    else:
                        print(f"    Warning: No public key for {addr}, sending unencrypted.")
                per_recip_mid = base_message_id if idx == 0 else f"{base_message_id}-{idx}"
                email_id = self._insert_email_copy(
                    per_recip_mid, user_id, from_addr, recip_to_str, recip_cc_str,
                    recip_subject, recip_body, recipient["id"], inbox_fid,
                    is_read=0, created_at=now,
                    attachments=attachments,
                    is_encrypted=recip_encrypted,
                    is_signed=1 if sign else 0,
                    signature=recip_signature,
                    encryption_key_id=recip_encryption_key_id,
                )
                inbox_email = self._get_email_by_id(email_id, recipient["id"])
                if inbox_email:
                    self._apply_rules_to_email(inbox_email, recipient["id"])
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
                           attachments=None, is_encrypted=0, is_signed=0,
                           signature=None, encryption_key_id=None):
        if created_at is None:
            created_at = datetime.now().isoformat()
        cursor = self.conn.execute(
            """INSERT INTO emails
               (message_id, sender_id, from_addr, to_addrs, cc_addrs, subject, body,
                owner_id, folder_id, is_read, is_starred, is_encrypted, is_signed,
                signature, encryption_key_id, created_at, deleted_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, NULL)""",
            (message_id, sender_id, from_addr, to_addrs, cc_addrs, subject, body,
             owner_id, folder_id, is_read, is_encrypted, is_signed,
             signature, encryption_key_id, created_at),
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

    def _get_user_rules(self, user_id):
        rows = self.conn.execute(
            "SELECT * FROM rules WHERE user_id = ? AND enabled = 1 ORDER BY priority ASC, id ASC",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def _get_email_attachments_count(self, email_id):
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM attachments WHERE email_id = ?",
            (email_id,),
        ).fetchone()
        return row["cnt"] if row else 0

    def _rule_matches(self, rule, email, user_id):
        if rule["cond_from"]:
            if not fnmatch.fnmatch(email["from_addr"], rule["cond_from"]):
                return False
        if rule["cond_subject"]:
            if not fnmatch.fnmatch(email["subject"], rule["cond_subject"]):
                return False
        if rule["cond_has_attachment"] is not None and rule["cond_has_attachment"] >= 0:
            att_count = self._get_email_attachments_count(email["id"])
            has_att = 1 if att_count > 0 else 0
            if has_att != rule["cond_has_attachment"]:
                return False
        return True

    def _apply_rule(self, rule, email, user_id):
        action = rule["action_type"]
        param = rule["action_param"]
        if action == "move":
            target_fid = self._get_or_create_folder(user_id, param)
            self.conn.execute(
                "UPDATE emails SET folder_id = ? WHERE id = ?",
                (target_fid, email["id"]),
            )
            self.conn.commit()
            return True, f"moved to '{param}'"
        elif action == "star":
            if not email["is_starred"]:
                self.conn.execute(
                    "UPDATE emails SET is_starred = 1 WHERE id = ?",
                    (email["id"],),
                )
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
                            is_encrypted=email.get("is_encrypted", 0),
                            is_signed=email.get("is_signed", 0),
                            signature=email.get("signature"),
                            encryption_key_id=email.get("encryption_key_id"),
                        )
                self.conn.commit()
            return True, "starred"
        elif action == "mark_read":
            self.conn.execute(
                "UPDATE emails SET is_read = 1 WHERE id = ?",
                (email["id"],),
            )
            self.conn.commit()
            return True, "marked as read"
        elif action == "delete":
            trash_fid = self._get_or_create_folder(user_id, "trash")
            self.conn.execute(
                "UPDATE emails SET folder_id = ?, deleted_at = ? WHERE id = ?",
                (trash_fid, datetime.now().isoformat(), email["id"]),
            )
            self.conn.commit()
            return True, "moved to trash"
        return False, "unknown action"

    def _apply_rules_to_email(self, email, user_id):
        rules = self._get_user_rules(user_id)
        applied = []
        for rule in rules:
            if self._rule_matches(rule, email, user_id):
                ok, result = self._apply_rule(rule, email, user_id)
                if ok:
                    applied.append(f"rule '{rule['name']}': {result}")
        return applied

    def _apply_rules_to_inbox(self, user_id):
        inbox_fid = self._get_folder_id(user_id, "inbox")
        if not inbox_fid:
            return []
        rows = self.conn.execute(
            "SELECT * FROM emails WHERE owner_id = ? AND folder_id = ?",
            (user_id, inbox_fid),
        ).fetchall()
        results = {}
        for row in rows:
            email = dict(row)
            applied = self._apply_rules_to_email(email, user_id)
            if applied:
                results[email["id"]] = applied
        return results

    def do_rules(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        parts = args.strip().split(maxsplit=1)
        subcmd = parts[0].lower() if parts else ""
        rest = parts[1] if len(parts) > 1 else ""
        if subcmd == "add":
            self._do_rules_add(rest)
        elif subcmd == "list":
            self._do_rules_list()
        elif subcmd == "delete" or subcmd == "remove":
            self._do_rules_delete(rest)
        elif subcmd == "reorder":
            self._do_rules_reorder(rest)
        elif subcmd == "test":
            self._do_rules_test()
        else:
            print("  Usage:")
            print("    rules add <name> [--from <pattern>] [--subject <pattern>]")
            print("              [--has-attachment true|false] --action <type:param>")
            print("              (actions: move:folder, star, mark_read, delete)")
            print("    rules list")
            print("    rules delete <name>")
            print("    rules reorder <name1>,<name2>,...")
            print("    rules test")

    def _parse_action(self, action_str):
        if ":" in action_str:
            atype, _, aparam = action_str.partition(":")
            return atype.strip().lower(), aparam.strip()
        return action_str.strip().lower(), None

    def _do_rules_add(self, args):
        tokens = args.strip().split()
        if not tokens:
            print("  Error: Specify rule name.")
            return
        name = tokens[0]
        cond_from = None
        cond_subject = None
        cond_has_att = None
        action_type = None
        action_param = None
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok == "--from" and i + 1 < len(tokens):
                cond_from = tokens[i + 1].strip('"').strip("'")
                i += 2
            elif tok == "--subject" and i + 1 < len(tokens):
                cond_subject = tokens[i + 1].strip('"').strip("'")
                i += 2
            elif tok == "--has-attachment" and i + 1 < len(tokens):
                val = tokens[i + 1].lower()
                if val in ("true", "1", "yes"):
                    cond_has_att = 1
                elif val in ("false", "0", "no"):
                    cond_has_att = 0
                i += 2
            elif tok == "--action" and i + 1 < len(tokens):
                action_type, action_param = self._parse_action(tokens[i + 1])
                i += 2
            else:
                print(f"  Unknown token: {tok}")
                return
        if action_type is None:
            print("  Error: --action is required.")
            return
        if cond_from is None and cond_subject is None and cond_has_att is None:
            print("  Error: At least one condition (--from, --subject, --has-attachment) is required.")
            return
        valid_actions = {"move", "star", "mark_read", "delete"}
        if action_type not in valid_actions:
            print(f"  Error: Invalid action '{action_type}'. Valid: {', '.join(valid_actions)}")
            return
        if action_type == "move" and not action_param:
            print("  Error: move action requires a folder name (e.g. --action move:work)")
            return
        user_id = self.current_user["id"]
        existing = self.conn.execute(
            "SELECT id FROM rules WHERE user_id = ? AND name = ?",
            (user_id, name),
        ).fetchone()
        if existing:
            print(f"  Error: Rule '{name}' already exists.")
            return
        max_priority = self.conn.execute(
            "SELECT COALESCE(MAX(priority), -1) AS mp FROM rules WHERE user_id = ?",
            (user_id,),
        ).fetchone()["mp"]
        self.conn.execute(
            """INSERT INTO rules (user_id, name, priority, cond_from, cond_subject,
               cond_has_attachment, action_type, action_param)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, max_priority + 1, cond_from, cond_subject,
             cond_has_att, action_type, action_param),
        )
        self.conn.commit()
        print(f"  Rule '{name}' added.")
        print(f"    Conditions: ", end="")
        conds = []
        if cond_from:
            conds.append(f"from ~ '{cond_from}'")
        if cond_subject:
            conds.append(f"subject ~ '{cond_subject}'")
        if cond_has_att is not None:
            conds.append(f"has-attachment = {bool(cond_has_att)}")
        print(", ".join(conds))
        print(f"    Action: {action_type}" + (f": {action_param}" if action_param else ""))

    def _do_rules_list(self):
        user_id = self.current_user["id"]
        rows = self.conn.execute(
            "SELECT * FROM rules WHERE user_id = ? ORDER BY priority ASC, id ASC",
            (user_id,),
        ).fetchall()
        if not rows:
            print("  No rules defined.")
            return
        print(f"\n  {'#':<4} {'Name':<16} {'Conditions':<40} {'Action':<18}")
        print("  " + "-" * 80)
        for i, r in enumerate(rows, 1):
            conds = []
            if r["cond_from"]:
                conds.append(f"from={r['cond_from']}")
            if r["cond_subject"]:
                conds.append(f"subj={r['cond_subject']}")
            if r["cond_has_attachment"] is not None and r["cond_has_attachment"] >= 0:
                conds.append(f"att={'T' if r['cond_has_attachment'] else 'F'}")
            cond_str = ",".join(conds) if conds else "(none)"
            act_str = r["action_type"]
            if r["action_param"]:
                act_str += f":{r['action_param']}"
            print(f"  {i:<4} {r['name']:<16} {cond_str[:40]:<40} {act_str:<18}")
        print()

    def _do_rules_delete(self, args):
        name = args.strip()
        if not name:
            print("  Usage: rules delete <name>")
            return
        user_id = self.current_user["id"]
        existing = self.conn.execute(
            "SELECT id FROM rules WHERE user_id = ? AND name = ?",
            (user_id, name),
        ).fetchone()
        if not existing:
            print(f"  Error: Rule '{name}' not found.")
            return
        self.conn.execute(
            "DELETE FROM rules WHERE id = ?", (existing["id"],)
        )
        self.conn.commit()
        print(f"  Rule '{name}' deleted.")

    def _do_rules_reorder(self, args):
        names = [n.strip() for n in args.strip().split(",") if n.strip()]
        if not names:
            print("  Usage: rules reorder name1,name2,...")
            return
        user_id = self.current_user["id"]
        existing = {}
        for r in self.conn.execute(
            "SELECT id, name FROM rules WHERE user_id = ?", (user_id,)
        ).fetchall():
            existing[r["name"]] = r["id"]
        for n in names:
            if n not in existing:
                print(f"  Error: Rule '{n}' not found.")
                return
        seen = set()
        dups = [n for n in names if n in seen or seen.add(n)]
        if dups:
            print(f"  Error: Duplicate names in list: {', '.join(dups)}")
            return
        priority = 0
        for n in names:
            self.conn.execute(
                "UPDATE rules SET priority = ? WHERE id = ?",
                (priority, existing[n]),
            )
            priority += 1
        remaining = [rid for name, rid in existing.items() if name not in names]
        for rid in remaining:
            self.conn.execute(
                "UPDATE rules SET priority = ? WHERE id = ?",
                (priority, rid),
            )
            priority += 1
        self.conn.commit()
        print(f"  Reordered {len(names)} rules.")
        self._do_rules_list()

    def _do_rules_test(self):
        user_id = self.current_user["id"]
        print("  Applying rules to all inbox emails...")
        results = self._apply_rules_to_inbox(user_id)
        if not results:
            print("  No emails matched any rule.")
            return
        print(f"\n  Rules applied to {len(results)} emails:")
        for eid, actions in results.items():
            row = self.conn.execute(
                "SELECT subject, from_addr FROM emails WHERE id = ?", (eid,)
            ).fetchone()
            if row:
                print(f"    [{row['from_addr']}] {row['subject']}:")
                for a in actions:
                    print(f"      -> {a}")
        print()

    def _apply_template_vars(self, text, vars):
        if not text:
            return text
        result = text
        for key, value in vars.items():
            placeholder = "{" + key + "}"
            if placeholder in result:
                result = result.replace(placeholder, str(value))
        return result

    def _default_template_vars(self, recipient_username=None):
        now = datetime.now()
        vars = {
            "date": now.strftime("%Y-%m-%d"),
            "datetime": now.strftime("%Y-%m-%d %H:%M:%S"),
            "time": now.strftime("%H:%M:%S"),
            "year": str(now.year),
            "month": str(now.month),
            "day": str(now.day),
            "domain": DOMAIN,
        }
        if recipient_username:
            vars["name"] = recipient_username
            vars["email"] = self._email_addr(recipient_username)
        if self.current_user:
            vars["sender"] = self.current_user["username"]
            vars["sender_email"] = self._email_addr(self.current_user["username"])
        return vars

    def do_template(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        parts = args.strip().split(maxsplit=1)
        subcmd = parts[0].lower() if parts else ""
        rest = parts[1] if len(parts) > 1 else ""
        if subcmd == "add":
            self._do_template_add(rest)
        elif subcmd == "list":
            self._do_template_list()
        elif subcmd == "use":
            self._do_template_use(rest)
        elif subcmd == "delete" or subcmd == "remove":
            self._do_template_delete(rest)
        else:
            print("  Usage:")
            print("    template add <name>       Create/edit a template (editor mode)")
            print("    template list             List all templates")
            print("    template use <name>       Compose using a template (vars auto-filled)")
            print("    template delete <name>    Delete a template")

    def _do_template_add(self, args):
        name = args.strip()
        if not name:
            print("  Error: Specify template name.")
            return
        print(f"  Editing template: {name}")
        print("  Enter Subject (empty to skip):")
        subject = input("  > ").strip()
        print("  Enter Body (end with '.' on a single line):")
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
        user_id = self.current_user["id"]
        existing = self.conn.execute(
            "SELECT id FROM templates WHERE user_id = ? AND name = ?",
            (user_id, name),
        ).fetchone()
        now = datetime.now().isoformat()
        if existing:
            self.conn.execute(
                "UPDATE templates SET subject = ?, body = ? WHERE id = ?",
                (subject, body, existing["id"]),
            )
            self.conn.commit()
            print(f"  Template '{name}' updated.")
        else:
            self.conn.execute(
                "INSERT INTO templates (user_id, name, subject, body, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, name, subject, body, now),
            )
            self.conn.commit()
            print(f"  Template '{name}' created.")
        if subject:
            print(f"    Subject: {subject}")
        if body:
            print(f"    Body ({len(body_lines)} lines)")

    def _do_template_list(self):
        user_id = self.current_user["id"]
        rows = self.conn.execute(
            "SELECT * FROM templates WHERE user_id = ? ORDER BY name ASC",
            (user_id,),
        ).fetchall()
        if not rows:
            print("  No templates defined.")
            return
        print(f"\n  {'Name':<20} {'Subject':<40} {'Body Lines':>10} {'Created':<16}")
        print("  " + "-" * 88)
        for r in rows:
            line_count = len(r["body"].split("\n")) if r["body"] else 0
            created = r["created_at"][:16]
            print(f"  {r['name']:<20} {r['subject'][:40]:<40} {line_count:>10} {created:<16}")
        print()

    def _get_template_by_name(self, user_id, name):
        row = self.conn.execute(
            "SELECT * FROM templates WHERE user_id = ? AND name = ?",
            (user_id, name),
        ).fetchone()
        return dict(row) if row else None

    def _do_template_use(self, args):
        name = args.strip()
        if not name:
            print("  Usage: template use <name>")
            return
        user_id = self.current_user["id"]
        tmpl = self._get_template_by_name(user_id, name)
        if not tmpl:
            print(f"  Error: Template '{name}' not found.")
            return
        print(f"  Using template: {name}")
        print("  Compose new email (pre-filled from template)")
        try:
            to_input = input("  To: ").strip()
        except EOFError:
            print("\n  Compose cancelled.")
            return
        if to_input.lower() == "cancel":
            print("  Compose cancelled.")
            return
        recipient_username = None
        to_addrs = self._parse_recipients(to_input)
        if to_addrs:
            first_addr = to_addrs[0]
            recip = self._get_user_by_email(first_addr)
            if recip:
                recipient_username = recip["username"]
        vars = self._default_template_vars(recipient_username=recipient_username)
        subject = self._apply_template_vars(tmpl["subject"], vars)
        body = self._apply_template_vars(tmpl["body"], vars)
        try:
            cc_input = input("  CC: ").strip()
        except EOFError:
            print("\n  Compose cancelled.")
            return
        if cc_input.lower() == "cancel":
            print("  Compose cancelled.")
            return
        subject_default = subject if subject else ""
        try:
            subject_input = input(f"  Subject [{subject_default}]: ").strip()
        except EOFError:
            print("\n  Compose cancelled.")
            return
        if subject_input.lower() == "cancel":
            print("  Compose cancelled.")
            return
        final_subject = subject_input if subject_input else subject_default
        attachments = []
        try:
            attach_input = input("  Attachments (file paths, comma-separated; Enter to skip): ").strip()
        except EOFError:
            print("\n  Compose cancelled.")
            return
        if attach_input.lower() == "cancel":
            print("  Compose cancelled.")
            return
        if attach_input:
            for fpath in attach_input.split(","):
                fpath = fpath.strip().strip("'\"")
                if not fpath:
                    continue
                if not os.path.isfile(fpath):
                    print(f"    File not found, skipped: {fpath}")
                    continue
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    b64 = base64.b64encode(data).decode("utf-8")
                    fname = os.path.basename(fpath)
                    attachments.append({"filename": fname, "data_base64": b64, "size": len(data)})
                    print(f"    Attached: {fname} ({self._fmt_size(len(data))})")
                except Exception as e:
                    print(f"    Error reading file, skipped: {fpath} ({e})")
        print("  Body (end with '.' on a single line; '.' alone uses template body):")
        print(f"  --- Template body preview ---")
        for line in body.split("\n")[:5]:
            print(f"  > {line}")
        if len(body.split("\n")) > 5:
            print(f"  > ... ({len(body.split(chr(10))) - 5} more lines)")
        print(f"  -----------------------------")
        body_lines = []
        while True:
            try:
                line = input("  > ")
            except EOFError:
                break
            if line == ".":
                break
            body_lines.append(line)
        final_body = "\n".join(body_lines) if body_lines else body
        self._send_email(to_input, cc_input, final_subject, final_body, attachments)

    def _do_template_delete(self, args):
        name = args.strip()
        if not name:
            print("  Usage: template delete <name>")
            return
        user_id = self.current_user["id"]
        existing = self.conn.execute(
            "SELECT id FROM templates WHERE user_id = ? AND name = ?",
            (user_id, name),
        ).fetchone()
        if not existing:
            print(f"  Error: Template '{name}' not found.")
            return
        self.conn.execute("DELETE FROM templates WHERE id = ?", (existing["id"],))
        self.conn.commit()
        print(f"  Template '{name}' deleted.")

    def do_broadcast(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        user_id = self.current_user["id"]
        tokens = args.strip().split()
        if not tokens:
            print("  Usage:")
            print("    broadcast --to-all [--template <name>]")
            print("    broadcast --to \"user1,user2,...\" [--template <name>]")
            return
        to_all = False
        to_list = []
        template_name = None
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "--to-all":
                to_all = True
                i += 1
            elif tok == "--to" and i + 1 < len(tokens):
                raw = tokens[i + 1].strip('"').strip("'")
                to_list = [u.strip() for u in raw.split(",") if u.strip()]
                i += 2
            elif tok == "--template" and i + 1 < len(tokens):
                template_name = tokens[i + 1]
                i += 2
            else:
                print(f"  Unknown token: {tok}")
                return
        recipients = []
        if to_all:
            rows = self.conn.execute(
                "SELECT id, username FROM users WHERE id != ?", (user_id,)
            ).fetchall()
            recipients = [(dict(r)["username"], dict(r)["id"]) for r in rows]
        elif to_list:
            for uname in to_list:
                user = self._get_user_by_username(uname)
                if user:
                    recipients.append((user["username"], user["id"]))
                else:
                    print(f"  Warning: User '{uname}' not found, skipped.")
        else:
            print("  Error: Specify --to-all or --to.")
            return
        if not recipients:
            print("  Error: No valid recipients.")
            return
        tmpl = None
        if template_name:
            tmpl = self._get_template_by_name(user_id, template_name)
            if not tmpl:
                print(f"  Error: Template '{template_name}' not found.")
                return
        if tmpl:
            print(f"  Composing broadcast from template: {template_name}")
            print(f"  Recipients: {', '.join(r[0] for r in recipients)}")
            print("  Confirm sending? (y/n): ", end="")
            confirm = input().strip().lower()
            if confirm not in ("y", "yes"):
                print("  Broadcast cancelled.")
                return
            template_subject = tmpl["subject"]
            template_body = tmpl["body"]
            per_recipient_vars = {}
            for username, uid in recipients:
                addr = self._email_addr(username)
                vars = self._default_template_vars(recipient_username=username)
                per_recipient_vars[addr] = vars
            to_str = ",".join(self._email_addr(r[0]) for r in recipients)
            self._send_email(
                to_str, "", template_subject, template_body, [],
                encrypt=False, sign=False,
                per_recipient_vars=per_recipient_vars,
            )
            print(f"  Broadcast sent to {len(recipients)} recipients.")
        else:
            print(f"  Composing broadcast email to {len(recipients)} recipients.")
            print("  Enter Subject:")
            subject = input("  > ").strip()
            print("  Enter Body (end with '.' on a single line):")
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
            per_recipient_vars = {}
            for username, uid in recipients:
                addr = self._email_addr(username)
                vars = self._default_template_vars(recipient_username=username)
                per_recipient_vars[addr] = vars
            to_str = ",".join(self._email_addr(r[0]) for r in recipients)
            print(f"  Confirm sending to {len(recipients)} recipients? (y/n): ", end="")
            confirm = input().strip().lower()
            if confirm not in ("y", "yes"):
                print("  Broadcast cancelled.")
                return
            self._send_email(
                to_str, "", subject, body, [],
                encrypt=False, sign=False,
                per_recipient_vars=per_recipient_vars,
            )
            print(f"  Broadcast sent.")

    def do_keys(self, args):
        if not self.current_user:
            print("  Error: Not logged in.")
            return
        parts = args.strip().split(maxsplit=1)
        subcmd = parts[0].lower() if parts else ""
        rest = parts[1] if len(parts) > 1 else ""
        if subcmd == "show":
            self._do_keys_show()
        elif subcmd == "export":
            self._do_keys_export(rest)
        elif subcmd == "import":
            print("  Note: Your own key pair is auto-generated. Import not required for personal use.")
        else:
            print("  Usage:")
            print("    keys show                 Show your key fingerprint")
            print("    keys export [file.pub]    Export your public key")

    def _do_keys_show(self):
        user_id = self.current_user["id"]
        keys = self._get_user_keys(user_id)
        if not keys:
            print("  Error: No keys found. This should not happen.")
            return
        fp = keys["key_fingerprint"]
        fp_colon = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))
        print(f"\n  Key Fingerprint (SHA256):")
        print(f"  {fp_colon}")
        print(f"  Key created: {keys['created_at'][:19]}")
        print(f"  Public key size: {RSA_KEY_SIZE} bits (RSA)")
        print()

    def _do_keys_export(self, args):
        output_path = args.strip()
        user_id = self.current_user["id"]
        keys = self._get_user_keys(user_id)
        if not keys:
            print("  Error: No keys found.")
            return
        default_name = f"{self.current_user['username']}_public_key.pem"
        if not output_path:
            output_path = default_name
        try:
            with open(output_path, "w") as f:
                f.write(keys["public_key_pem"])
            print(f"  Public key exported to: {output_path}")
            print(f"  Fingerprint: {keys['key_fingerprint'][:16]}...")
        except Exception as e:
            print(f"  Error exporting key: {e}")

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
        print(f"  {'#':<4} {'Read':<5} {'Star':<5} {'Enc':<4} {'From':<24} {'Subject':<30} {'Date':<12} {'Att':<3}")
        print("  " + "-" * 92)
        for i, e in enumerate(emails, 1):
            read_mark = " " if e["is_read"] else "\u2605"
            star_mark = "\u2605" if e["is_starred"] else " "
            enc_mark = "E" if e["is_encrypted"] else " "
            from_addr = e["from_addr"][:22]
            subject = e["subject"][:28]
            if e["is_encrypted"]:
                subject = "[加密]" + subject[:22]
            date_str = e["created_at"][:10]
            att_mark = "+" if e["attachment_count"] > 0 else " "
            print(f"  {i:<4} {read_mark:<5} {star_mark:<5} {enc_mark:<4} {from_addr:<24} {subject:<30} {date_str:<12} {att_mark:<3}")
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
        if email["is_encrypted"]:
            print("  加密    : 是 [加密]")
        if email["is_signed"]:
            print("  签名    : 是")
        atts = self.conn.execute(
            "SELECT id, filename, size FROM attachments WHERE email_id = ?",
            (email["id"],),
        ).fetchall()
        if atts:
            print(f"  Attachments ({len(atts)}):")
            for a in atts:
                print(f"    - {a['filename']} ({self._fmt_size(a['size'])})")
        print("  " + "-" * 60)
        display_body = email["body"]
        if email["is_encrypted"]:
            my_keys = self._get_user_keys(user_id)
            if my_keys:
                decrypted = self._decrypt_with_private_key(display_body, my_keys["private_key_pem"])
                if decrypted is not None:
                    display_body = decrypted
                    print("  [邮件已解密]")
                else:
                    print("  [解密失败 - 无法读取加密内容]")
            else:
                print("  [无私钥 - 无法解密]")
        if email["is_signed"] and email["signature"] and email["sender_id"]:
            sender_keys = self._get_user_keys(email["sender_id"])
            if sender_keys:
                sign_data = f"{email['subject']}\n{display_body}\n{email['from_addr']}"
                valid = self._verify_signature(sign_data, email["signature"], sender_keys["public_key_pem"])
                if valid:
                    print("  ✓ 签名验证通过")
                else:
                    print("  ✗ 签名验证失败")
            else:
                print("  [无法验证签名 - 未找到发件人公钥]")
        for line in display_body.split("\n"):
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
    compose [--encrypt] [--sign]  Compose a new email (with optional encryption/signing)
    inbox [folder]            List emails in current/specified folder
    read <num>                Read an email (auto-decrypt/verify)
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

  Rules (Auto-classification):
    rules add <name> --from <pattern> --subject <pattern>
           --has-attachment true|false --action <type:param>
                              Add a rule (actions: move:folder, star, mark_read, delete)
    rules list                List all rules
    rules delete <name>       Delete a rule
    rules reorder <n1,n2,...> Reorder rule priorities
    rules test                Re-apply rules to inbox emails

  Templates & Broadcast:
    template add <name>       Create/edit a template (supports {name}/{date} vars)
    template list             List all templates
    template use <name>       Compose using a template
    template delete <name>    Delete a template
    broadcast --to-all [--template <name>]   Send to all users
    broadcast --to "u1,u2" [--template <name>]  Send to specific users

  Encryption & Signing:
    keys show                 Show your public key fingerprint
    keys export [file.pub]    Export your public key
    compose --encrypt         Encrypt email with recipient's public key
    compose --sign            Sign email with your private key

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
                "rules": self.do_rules,
                "template": self.do_template,
                "broadcast": self.do_broadcast,
                "keys": self.do_keys,
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
