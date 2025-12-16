#!/usr/bin/env python3
"""
Telegram OTP Bot - Complete Implementation
Monitors IVASMS.com for new OTPs and sends them to Telegram groups
Includes Flask web dashboard for monitoring and control
"""

import os
import sys
import json
import asyncio
import logging
import re
import requests
import threading
import time
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from bs4 import BeautifulSoup
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import func
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup

load_dotenv()

log_level = logging.DEBUG if os.environ.get('DEBUG') == '1' else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('otp_bot.log', mode='a') if os.path.exists('.') else logging.NullHandler()
    ]
)
logger = logging.getLogger(__name__)

SIGNATURE = "𝐌ʀ 𝐀ғʀɪx 𝐓ᴇᴄʜ™"
BANNER_IMAGE_URL = "https://files.catbox.moe/3fr0yx.jpg"
CHANNEL_LINK = "https://t.me/mrafrix"
OTP_GROUP_LINK = "https://t.me/+_76TZqOFTeBkMWFk"
OWNER_LINK = "https://t.me/jadenafrix"

DASHBOARD_EMAIL = "tawandamahachi07@gmail.com"
DASHBOARD_PASSWORD = "mahachi2007"

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

app = Flask(__name__, template_folder='Templates')
app.secret_key = os.environ.get("SESSION_SECRET", "telegram-otp-bot-secret-key-mr-afrix-tech")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///bot.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
db.init_app(app)

class OTPLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    otp_code = db.Column(db.String(20), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    service_name = db.Column(db.String(100), nullable=True)
    raw_message = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    sent_to_telegram = db.Column(db.Boolean, default=False, nullable=False)
    
    def __repr__(self):
        return f'<OTPLog {self.id}: {self.otp_code} - {self.service_name}>'

class BotStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stat_name = db.Column(db.String(50), unique=True, nullable=False)
    stat_value = db.Column(db.String(255), nullable=True)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<BotStats {self.stat_name}: {self.stat_value}>'

def get_inline_keyboard():
    keyboard = [
        [
            InlineKeyboardButton("📱 NUMBER CHANNEL", url=CHANNEL_LINK),
            InlineKeyboardButton("🔐 OTP GROUP", url=OTP_GROUP_LINK),
        ],
        [
            InlineKeyboardButton("👤 OWNER", url=OWNER_LINK),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

def format_otp_message(otp_data):
    otp = otp_data.get('otp', 'N/A')
    phone = otp_data.get('phone', 'N/A')
    service = otp_data.get('service', 'Unknown')
    timestamp = otp_data.get('timestamp', datetime.now().strftime('%H:%M:%S'))
    
    message = f"""🔐 <b>New OTP Received</b>

🔢 OTP: <code>{otp}</code>
📱 Number: <code>{phone}</code>
🌐 Service: <b>{service}</b>
⏰ Time: {timestamp}

<i>Tap the OTP to copy it!</i>

━━━━━━━━━━━━━━━━━━━━
<b>{SIGNATURE}</b>"""
    
    return message

def format_multiple_otps(otp_list):
    if not otp_list:
        return "No new OTPs found."
    
    if len(otp_list) == 1:
        return format_otp_message(otp_list[0])
    
    header = f"🔐 <b>{len(otp_list)} New OTPs Received</b>\n\n"
    
    messages = []
    for i, otp_data in enumerate(otp_list, 1):
        otp = otp_data.get('otp', 'N/A')
        phone = otp_data.get('phone', 'N/A')
        service = otp_data.get('service', 'Unknown')
        
        msg = f"<b>{i}.</b> <code>{otp}</code> | {service} | <code>{phone}</code>"
        messages.append(msg)
    
    footer = f"\n\n<i>Tap any OTP to copy it!</i>\n\n━━━━━━━━━━━━━━━━━━━━\n<b>{SIGNATURE}</b>"
    
    return header + "\n".join(messages) + footer

def extract_otp_from_text(text):
    if not text:
        return None
    
    patterns = [
        r'\b(\d{6})\b',
        r'\b(\d{5})\b',
        r'\b(\d{4})\b',
        r'code[:\s]*(\d+)',
        r'verification[:\s]*(\d+)',
        r'otp[:\s]*(\d+)',
        r'pin[:\s]*(\d+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None

def clean_phone_number(phone):
    if not phone:
        return "N/A"
    
    cleaned = re.sub(r'[^\d+]', '', phone)
    
    if cleaned and not cleaned.startswith('+'):
        if cleaned.startswith('88'):
            cleaned = '+' + cleaned
        elif len(cleaned) >= 10:
            cleaned = '+' + cleaned
    
    return cleaned or phone

def clean_service_name(service):
    if not service:
        return "Unknown"
    
    cleaned = service.strip().title()
    
    service_mappings = {
        'fb': 'Facebook',
        'google': 'Google',
        'whatsapp': 'WhatsApp',
        'telegram': 'Telegram',
        'instagram': 'Instagram',
        'twitter': 'Twitter',
        'linkedin': 'LinkedIn',
        'tiktok': 'TikTok',
        'snapchat': 'Snapchat',
        'discord': 'Discord'
    }
    
    service_lower = cleaned.lower()
    for key, value in service_mappings.items():
        if key in service_lower:
            return value
    
    return cleaned

def get_status_message(stats):
    uptime = stats.get('uptime', 'Unknown')
    total_otps = stats.get('total_otps_sent', 0)
    last_check = stats.get('last_check', 'Never')
    cache_size = stats.get('cache_size', 0)
    
    return f"""🤖 <b>Bot Status</b>

⚡ Status: <b>Online</b>
⏱️ Uptime: {uptime}
📨 Total OTPs Sent: <b>{total_otps}</b>
🔍 Last Check: {last_check}
💾 Cache Size: {cache_size} items

<i>Bot is running and monitoring for new OTPs</i>

━━━━━━━━━━━━━━━━━━━━
<b>{SIGNATURE}</b>"""

class OTPFilter:
    def __init__(self, cache_file='otp_cache.json', expire_minutes=30):
        self.cache_file = cache_file
        self.expire_minutes = expire_minutes
        self.cache = self._load_cache()
    
    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                pass
        return {}
    
    def _save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving cache: {e}")
    
    def _cleanup_expired(self):
        current_time = datetime.now()
        expired_keys = []
        
        for key, entry in self.cache.items():
            try:
                entry_time = datetime.fromisoformat(entry['timestamp'])
                if current_time - entry_time > timedelta(minutes=self.expire_minutes):
                    expired_keys.append(key)
            except (KeyError, ValueError):
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.cache[key]
    
    def _generate_key(self, otp_data):
        otp = otp_data.get('otp', '')
        phone = otp_data.get('phone', '')
        service = otp_data.get('service', '')
        return f"{otp}_{phone}_{service}"
    
    def is_duplicate(self, otp_data):
        self._cleanup_expired()
        key = self._generate_key(otp_data)
        return key in self.cache
    
    def add_otp(self, otp_data):
        key = self._generate_key(otp_data)
        self.cache[key] = {
            'timestamp': datetime.now().isoformat(),
            'otp': otp_data.get('otp', ''),
            'phone': otp_data.get('phone', ''),
            'service': otp_data.get('service', '')
        }
        self._save_cache()
    
    def filter_new_otps(self, otp_list):
        new_otps = []
        
        for otp_data in otp_list:
            if not self.is_duplicate(otp_data):
                new_otps.append(otp_data)
                self.add_otp(otp_data)
        
        return new_otps
    
    def get_cache_stats(self):
        self._cleanup_expired()
        return {
            'total_cached': len(self.cache),
            'cache_file': self.cache_file,
            'expire_minutes': self.expire_minutes
        }
    
    def clear_cache(self):
        self.cache = {}
        self._save_cache()
        return "Cache cleared successfully"

class IVASMSScraper:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.session = requests.Session()
        self.base_url = "https://www.ivasms.com"
        self.is_logged_in = False

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
        })

    def login(self):
        try:
            logger.info("Attempting to login to IVASMS...")
            login_url = f"{self.base_url}/login"
            response = self.session.get(login_url, timeout=30)
            if response.status_code != 200:
                logger.error(f"Login page unreachable. Status: {response.status_code}")
                return False

            soup = BeautifulSoup(response.content, 'html.parser')
            csrf_input = soup.find('input', {'name': '_token'})
            csrf_token = csrf_input.get('value', '') if csrf_input else ''
            
            if not csrf_token:
                logger.warning("CSRF token not found, attempting login without it")

            login_data = {
                'email': self.email,
                'password': self.password,
                '_token': csrf_token
            }

            self.session.headers.update({
                'Referer': login_url,
                'Origin': self.base_url,
                'Content-Type': 'application/x-www-form-urlencoded',
            })

            login_response = self.session.post(login_url, data=login_data, timeout=30, allow_redirects=True)
            
            if login_response.status_code == 200:
                response_text = login_response.text.lower()
                if "logout" in response_text or "dashboard" in response_text or "my_sms" in response_text:
                    self.is_logged_in = True
                    logger.info("✅ Login successful to IVASMS")
                    return True
                elif "invalid" in response_text or "incorrect" in response_text:
                    logger.error("❌ Login failed - Invalid credentials")
                    return False

            if login_response.status_code in [301, 302, 303]:
                self.is_logged_in = True
                logger.info("✅ Login successful (redirect detected)")
                return True

            logger.error(f"❌ Login failed with status: {login_response.status_code}")
            return False
        except requests.exceptions.Timeout:
            logger.error("Login timeout - IVASMS server not responding")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Login error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected login error: {e}")
            return False

    def fetch_messages(self):
        if not self.is_logged_in:
            logger.info("Not logged in, attempting login...")
            if not self.login():
                logger.error("Failed to login, cannot fetch messages")
                return []

        try:
            url = f"{self.base_url}/portal/live/my_sms"
            logger.debug(f"Fetching messages from: {url}")
            response = self.session.get(url, timeout=30)
            
            if response.status_code != 200:
                logger.error(f"Failed to load SMS page. Status: {response.status_code}")
                self.is_logged_in = False
                return []

            if "login" in response.url.lower() and "my_sms" not in response.url.lower():
                logger.warning("Session expired, re-logging in...")
                self.is_logged_in = False
                if self.login():
                    return self.fetch_messages()
                return []

            soup = BeautifulSoup(response.content, 'html.parser')
            messages = self._extract_messages(soup)
            logger.info(f"Fetched {len(messages)} messages from IVASMS")
            return messages
        except requests.exceptions.Timeout:
            logger.error("Timeout fetching messages")
            return []
        except Exception as e:
            logger.error(f"Error fetching messages: {e}")
            return []

    def _extract_messages(self, soup):
        messages = []

        tables = soup.find_all('table')
        for table in tables:
            rows = table.find_all('tr')
            for row in rows[1:]:
                cells = row.find_all('td')
                if len(cells) < 3:
                    continue

                phone = clean_phone_number(cells[0].text)
                service = clean_service_name(cells[1].text)
                raw_text = cells[2].text.strip()
                otp = extract_otp_from_text(raw_text)

                if otp:
                    messages.append({
                        'otp': otp,
                        'phone': phone or "N/A",
                        'service': service or "Unknown",
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'raw_message': raw_text
                    })

        if not messages:
            rows = soup.find_all('tr')
            for row in rows[1:]:
                cells = row.find_all('td')
                if len(cells) < 3:
                    continue

                phone = clean_phone_number(cells[0].text)
                service = clean_service_name(cells[1].text)
                raw_text = cells[2].text.strip()
                otp = extract_otp_from_text(raw_text)

                if otp:
                    messages.append({
                        'otp': otp,
                        'phone': phone or "N/A",
                        'service': service or "Unknown",
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'raw_message': raw_text
                    })

        return messages

class TelegramOTPBot:
    def __init__(self, token, group_id):
        self.token = token
        self.group_id = group_id
        self.bot = Bot(token=token)
        self.start_time = datetime.now()

    async def send_otp_message(self, otp_data):
        message = format_otp_message(otp_data)
        keyboard = get_inline_keyboard()
        
        try:
            await self.bot.send_photo(
                chat_id=self.group_id,
                photo=BANNER_IMAGE_URL,
                caption=message,
                parse_mode='HTML',
                reply_markup=keyboard
            )
            return True
        except Exception as e:
            logger.error(f"Error sending OTP message with photo: {e}")
            try:
                await self.bot.send_message(
                    chat_id=self.group_id,
                    text=message,
                    parse_mode='HTML',
                    reply_markup=keyboard
                )
                return True
            except Exception as e2:
                logger.error(f"Fallback message also failed: {e2}")
                return False

    async def send_multiple_otps(self, otp_list):
        message = format_multiple_otps(otp_list)
        keyboard = get_inline_keyboard()
        
        try:
            await self.bot.send_photo(
                chat_id=self.group_id,
                photo=BANNER_IMAGE_URL,
                caption=message,
                parse_mode='HTML',
                reply_markup=keyboard
            )
            return True
        except Exception as e:
            logger.error(f"Error sending multiple OTPs with photo: {e}")
            try:
                await self.bot.send_message(
                    chat_id=self.group_id,
                    text=message,
                    parse_mode='HTML',
                    reply_markup=keyboard
                )
                return True
            except Exception as e2:
                logger.error(f"Fallback message also failed: {e2}")
                return False

    async def send_test_message(self):
        test_message = f"""🧪 <b>Test Message</b>

This is a test message to verify that the Telegram OTP Bot is working correctly.

✅ Bot is online and functional
✅ Message formatting is working
✅ Connection to Telegram is established

<i>Test completed successfully!</i>

━━━━━━━━━━━━━━━━━━━━
<b>{SIGNATURE}</b>"""
        
        keyboard = get_inline_keyboard()
        
        try:
            await self.bot.send_photo(
                chat_id=self.group_id,
                photo=BANNER_IMAGE_URL,
                caption=test_message,
                parse_mode='HTML',
                reply_markup=keyboard
            )
            return True
        except Exception as e:
            logger.error(f"Error sending test message with photo: {e}")
            try:
                await self.bot.send_message(
                    chat_id=self.group_id,
                    text=test_message,
                    parse_mode='HTML',
                    reply_markup=keyboard
                )
                return True
            except Exception as e2:
                logger.error(f"Fallback test message also failed: {e2}")
                return False

class OTPBotController:
    def __init__(self):
        self.scraper = None
        self.telegram_bot = None
        self.otp_filter = OTPFilter()
        self.is_running = False
        self.monitor_thread = None
        self.start_time = datetime.now()
        
        self._init_scraper()
        self._init_telegram_bot()

    def _init_scraper(self):
        try:
            email = os.environ.get("IVASMS_EMAIL")
            password = os.environ.get("IVASMS_PASSWORD")
            
            if not email or not password:
                logger.warning("IVASMS credentials not found in environment variables. Scraper will not be initialized.")
                logger.debug(f"Email: {'Found' if email else 'Missing'}, Password: {'Found' if password else 'Missing'}")
                return False
            
            self.scraper = IVASMSScraper(email, password)
            logger.info("IVASMS scraper initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize IVASMS scraper: {e}")
            return False

    def _init_telegram_bot(self):
        try:
            token = os.environ.get("TELEGRAM_BOT_TOKEN")
            group_id = os.environ.get("TELEGRAM_GROUP_ID")
            
            if not token or not group_id:
                logger.warning("Telegram credentials not found in environment variables. Bot will not be initialized.")
                logger.debug(f"Token: {'Found' if token else 'Missing'}, Group ID: {'Found' if group_id else 'Missing'}")
                return False
            
            self.telegram_bot = TelegramOTPBot(token, group_id)
            logger.info("Telegram bot initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Telegram bot: {e}")
            return False

    def start_monitoring(self):
        if self.is_running:
            return "Monitoring is already running"
        
        if not self.scraper:
            logger.error("IVASMS scraper not initialized. Please check your credentials.")
            return "Error: IVASMS scraper not initialized. Please check your IVASMS_EMAIL and IVASMS_PASSWORD environment variables."
        
        if not self.telegram_bot:
            logger.error("Telegram bot not initialized. Please check your credentials.")
            return "Error: Telegram bot not initialized. Please check your TELEGRAM_BOT_TOKEN and TELEGRAM_GROUP_ID environment variables."
        
        try:
            self.is_running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            logger.info("OTP monitoring started successfully")
            return "OTP monitoring started successfully"
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            self.is_running = False
            return f"Error starting monitoring: {str(e)}"

    def stop_monitoring(self):
        self.is_running = False
        logger.info("OTP monitoring stopped")
        return "OTP monitoring stopped"

    def _monitor_loop(self):
        while self.is_running:
            try:
                messages = self.scraper.fetch_messages()
                
                if messages:
                    new_otps = self.otp_filter.filter_new_otps(messages)
                    
                    if new_otps:
                        self._log_otps_to_db(new_otps)
                        
                        if len(new_otps) == 1:
                            asyncio.run(self.telegram_bot.send_otp_message(new_otps[0]))
                        else:
                            asyncio.run(self.telegram_bot.send_multiple_otps(new_otps))
                        
                        logger.info(f"Sent {len(new_otps)} new OTPs to Telegram")
                
                self._update_stats()
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)

    def _log_otps_to_db(self, otp_list):
        try:
            with app.app_context():
                for otp_data in otp_list:
                    otp_log = OTPLog(
                        otp_code=otp_data.get('otp', ''),
                        phone_number=otp_data.get('phone', ''),
                        service_name=otp_data.get('service', ''),
                        raw_message=otp_data.get('raw_message', ''),
                        sent_to_telegram=True
                    )
                    db.session.add(otp_log)
                
                db.session.commit()
        except Exception as e:
            logger.error(f"Error logging OTPs to database: {e}")

    def _update_stats(self):
        try:
            with app.app_context():
                last_check_stat = db.session.query(BotStats).filter_by(stat_name='last_check').first()
                if last_check_stat:
                    last_check_stat.stat_value = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    last_check_stat.last_updated = datetime.utcnow()
                else:
                    last_check_stat = BotStats(
                        stat_name='last_check',
                        stat_value=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    )
                    db.session.add(last_check_stat)
                
                db.session.commit()
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")

    def get_stats(self):
        try:
            with app.app_context():
                total_otps = db.session.query(OTPLog).count()
                sent_otps = db.session.query(OTPLog).filter_by(sent_to_telegram=True).count()
                
                uptime = datetime.now() - self.start_time
                uptime_str = f"{uptime.days}d {uptime.seconds//3600}h {(uptime.seconds//60)%60}m"
                
                last_check_stat = db.session.query(BotStats).filter_by(stat_name='last_check').first()
                last_check = last_check_stat.stat_value if last_check_stat else 'Never'
                
                cache_stats = self.otp_filter.get_cache_stats()
                
                return {
                    'is_running': self.is_running,
                    'uptime': uptime_str,
                    'total_otps_logged': total_otps,
                    'total_otps_sent': sent_otps,
                    'last_check': last_check,
                    'cache_size': cache_stats['total_cached']
                }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

    async def send_test_message(self):
        if not self.telegram_bot:
            return False
        return await self.telegram_bot.send_test_message()

    def check_for_otps_manually(self):
        try:
            if not self.scraper:
                logger.warning("Manual check requested but scraper not initialized")
                return "❌ Error: IVASMS scraper not initialized. Please check credentials."
            
            logger.info("Manual OTP check initiated")
            messages = self.scraper.fetch_messages()
            new_otps = self.otp_filter.filter_new_otps(messages)
            
            if new_otps:
                logger.info(f"Processing {len(new_otps)} new OTPs")
                self._log_otps_to_db(new_otps)
                
                if self.telegram_bot:
                    success = False
                    if len(new_otps) == 1:
                        success = asyncio.run(self.telegram_bot.send_otp_message(new_otps[0]))
                    else:
                        success = asyncio.run(self.telegram_bot.send_multiple_otps(new_otps))
                    
                    if success:
                        return f"✅ Found and sent {len(new_otps)} new OTPs to Telegram"
                    else:
                        return f"⚠️ Found {len(new_otps)} new OTPs but failed to send to Telegram"
                else:
                    return f"⚠️ Found {len(new_otps)} new OTPs but Telegram bot not initialized"
            else:
                return "✅ Check completed - No new OTPs found (might be duplicates)"
                
        except Exception as e:
            logger.error(f"Error in manual OTP check: {e}")
            return f"❌ Error checking for OTPs: {str(e)}"

bot_controller = None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        
        if email == DASHBOARD_EMAIL and password == DASHBOARD_PASSWORD:
            session['logged_in'] = True
            session['user_email'] = email
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid email or password'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/status')
@login_required
def api_status():
    if bot_controller is None:
        return jsonify({
            'error': 'Bot controller not initialized',
            'is_running': False,
            'uptime': '0d 0h 0m',
            'total_otps_logged': 0,
            'total_otps_sent': 0,
            'last_check': 'Never',
            'cache_size': 0
        })
    
    stats = bot_controller.get_stats()
    return jsonify(stats)

@app.route('/api/start', methods=['POST'])
@login_required
def api_start():
    if bot_controller is None:
        return jsonify({'message': 'Bot controller not initialized', 'success': False})
    
    result = bot_controller.start_monitoring()
    success = not result.startswith('Error')
    return jsonify({'message': result, 'success': success})

@app.route('/api/stop', methods=['POST'])
@login_required
def api_stop():
    if bot_controller is None:
        return jsonify({'message': 'Bot controller not initialized', 'success': False})
    
    result = bot_controller.stop_monitoring()
    return jsonify({'message': result, 'success': True})

@app.route('/api/test', methods=['POST'])
@login_required
def api_test():
    if bot_controller is None:
        return jsonify({'message': 'Bot controller not initialized', 'success': False})
    
    try:
        result = asyncio.run(bot_controller.send_test_message())
        return jsonify({
            'message': 'Test message sent successfully' if result else 'Failed to send test message',
            'success': result
        })
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}', 'success': False})

@app.route('/api/check', methods=['POST'])
@login_required
def api_check():
    if bot_controller is None:
        return jsonify({'message': 'Bot controller not initialized', 'success': False})
    
    result = bot_controller.check_for_otps_manually()
    success = not result.startswith('❌')
    return jsonify({'message': result, 'success': success})

@app.route('/api/clear-cache', methods=['POST'])
@login_required
def api_clear_cache():
    if bot_controller is None:
        return jsonify({'message': 'Bot controller not initialized', 'success': False})
    
    result = bot_controller.otp_filter.clear_cache()
    return jsonify({'message': result, 'success': True})

@app.route('/api/logs')
@login_required
def api_logs():
    try:
        logs = db.session.query(OTPLog).order_by(OTPLog.timestamp.desc()).limit(20).all()
        log_data = []
        
        for log in logs:
            log_data.append({
                'id': log.id,
                'otp_code': log.otp_code,
                'phone_number': log.phone_number,
                'service_name': log.service_name,
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'sent_to_telegram': log.sent_to_telegram
            })
        
        return jsonify({'logs': log_data, 'success': True})
    except Exception as e:
        logger.error(f"Error fetching logs: {e}")
        return jsonify({'logs': [], 'success': False, 'error': str(e)})

@app.route('/api/debug')
@login_required
def api_debug():
    debug_info = {
        'python_version': f"{sys.version}",
        'flask_app_running': True,
        'environment_variables': {
            'TELEGRAM_BOT_TOKEN': 'Found' if os.environ.get('TELEGRAM_BOT_TOKEN') else 'Missing',
            'TELEGRAM_GROUP_ID': 'Found' if os.environ.get('TELEGRAM_GROUP_ID') else 'Missing',
            'IVASMS_EMAIL': 'Found' if os.environ.get('IVASMS_EMAIL') else 'Missing',
            'IVASMS_PASSWORD': 'Found' if os.environ.get('IVASMS_PASSWORD') else 'Missing',
            'DATABASE_URL': 'Found' if os.environ.get('DATABASE_URL') else 'Missing',
            'DEBUG': os.environ.get('DEBUG', '0')
        },
        'bot_controller_status': 'Initialized' if bot_controller else 'Not Initialized',
        'database_status': 'Connected',
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'log_level': logging.getLevelName(logger.level)
    }
    
    if bot_controller:
        debug_info['scraper_status'] = 'Initialized' if bot_controller.scraper else 'Not Initialized'
        debug_info['telegram_bot_status'] = 'Initialized' if bot_controller.telegram_bot else 'Not Initialized'
        debug_info['monitoring_status'] = 'Running' if bot_controller.is_running else 'Stopped'
    
    return jsonify(debug_info)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

bot_controller = None

try:
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully")
except Exception as e:
    logger.error(f"Database initialization failed: {e}")

try:
    bot_controller = OTPBotController()
    logger.info("Bot controller initialized successfully")
except Exception as e:
    logger.error(f"Bot controller initialization failed: {e}")
    logger.debug("This might be due to missing environment variables or network issues")
    bot_controller = None

if bot_controller and (os.environ.get("TELEGRAM_BOT_TOKEN") and 
    os.environ.get("TELEGRAM_GROUP_ID") and 
    os.environ.get("IVASMS_EMAIL") and 
    os.environ.get("IVASMS_PASSWORD")):
    
    def delayed_start():
        try:
            time.sleep(5)
            result = bot_controller.start_monitoring()
            logger.info(f"Auto-start result: {result}")
        except Exception as e:
            logger.error(f"Auto-start failed: {e}")
    
    threading.Thread(target=delayed_start, daemon=True).start()
    logger.info("Auto-starting OTP monitoring...")
else:
    logger.warning("Auto-start disabled: Missing credentials or bot controller not initialized")
    if not bot_controller:
        logger.error("Bot controller is None - check initialization errors above")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
