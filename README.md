# Private Flask Webserver – Personal Infrastructure on Raspberry Pi

This repository documents a basic but steadily evolving Flask-based webserver infrastructure, running behind an Nginx reverse proxy on a Raspberry Pi. Initially created as a personal side project and learning environment, the server now integrates multiple components for private data management, home automation, and self-hosted services.

> Please note: This server is **not production-grade**. It was designed primarily for experimentation and private use.

---

## Overview

The server combines various features under a single modular architecture:

- **Private document storage and access**
- **Hashed file sharing** via 128-bit tokenized links
- **SmartHome integration** with direct Philips Hue Bridge control
- **Study tools** including a Pomodoro-style timer and flashcard system
- **Inventory system** with item management, QR label printing and MongoDB backend
- **Basic activity logging** and access event tracking

---

## Architecture

- **Backend:** Python 3 / Flask (modular route system with login-protected endpoints)
- **Frontend:** HTML templates with CSS and JS enhancements (minimal)
- **Reverse Proxy:** Nginx with HTTPS (Let’s Encrypt certificates)
- **Host Machine:** Raspberry Pi (Debian-based), additional PC for Windows-only label printer

---

## Key Features

### 1. Document Management

- Upload, view, and download files
- Support for nested folders and file type restrictions
- Access control via session login and optional public token links (128-bit hash URLs)

### 2. SmartHome Control

- Direct API access to Hue Bridge (no cloud dependency)
- Light control and status monitoring via internal web dashboard

### 3. Learning Tools

- Flashcard system with custom decks and spaced repetition
- Pomodoro-style timer with session statistics

### 4. Inventory + Label Printing

- Items stored in MongoDB with metadata (location, room, contents, timestamp)
- Auto-generated QR codes upon creation
- Label printed via API interface to Windows machine running Brother label printer

---

## Security Measures

> Still in early development – applied cautiously with room for improvement.

- CSRF protection via Flask-WTF  
- Password hashing with fail counter and lockout after multiple attempts  
- HTTPS enforcement via Nginx and X.509 Let's Encrypt certificates  
- Restricted upload types and extension checks  
- Admin panel behind login

---

## Logging & Monitoring

- Simple activity logging (logins, file accesses, failed attempts)
- Plan to implement rate limiting and alert system for abnormal behavior

---

## Roadmap / Ideas

- User role system (admin, read-only)
- File versioning and expiration
- Offline-first support with service workers
- 2FA or hardware key integration
- API keys for device-based automation

---

## Final Notes

This project grew out of first principles and personal tinkering – combining learning goals with tools I actually use daily. It’s far from perfect, but each part reflects a new layer of understanding and control over my digital environment.

Use with care. Break things. Learn.

---

## Contact

**Maximilian Schreber**  
max.schreber@tum.de  
[github.com/MSchreber](https://github.com/MSchreber)