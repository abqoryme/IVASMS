import requests
import re
import json
import time
import logging
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import os
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler
import asyncio
import urllib.parse
import threading
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

# Try selenium with undetected-chromedriver for Cloudflare bypass
HAS_SELENIUM = False
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    import undetected_chromedriver as uc
    HAS_SELENIUM = True
    logging.info("[SELENIUM] Selenium with undetected-chromedriver loaded - will use for Cloudflare bypass")
except ImportError as e:
    logging.warning(f"[SELENIUM] Selenium not available: {e}")

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

ADMIN_IDS = [7500869913, 6524840104]
bot_users = set()

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        response = b'''<!DOCTYPE html>
<html><head><title>IVASMS Bot</title></head>
<body><h1>IVASMS Bot is running!</h1><p>Status: OK</p></body></html>'''
        self.wfile.write(response)
    
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    
    def log_message(self, format, *args):
        pass

def run_health_server():
    """Run a simple HTTP server for health checks."""
    port = int(os.environ.get("PORT", 10000))
    server = HTTPServer(('0.0.0.0', port), HealthHandler)
    logger.info(f"[HEALTH] Health server listening on 0.0.0.0:{port}")
    server.serve_forever()

BANNER_URL = "https://files.catbox.moe/koc535.jpg"

def get_inline_keyboard():
    """Return inline keyboard with channel/group buttons - vertical layout."""
    keyboard = [
        [InlineKeyboardButton("𝐍ᴜᴍʙᴇʀ 𝐂ʜᴀɴɴᴇʟ", url="https://t.me/mrafrixtech")],
        [InlineKeyboardButton("𝐎ᴛᴘ 𝐆𝐫𝐨𝐮𝐩", url="https://t.me/afrixotpgc")],
        [InlineKeyboardButton("𝐑ᴇɴᴛ sᴄʀɪᴘᴛ", url="https://t.me/jaden_afrix")],
    ]
    return InlineKeyboardMarkup(keyboard)

def get_powered_by_caption():
    """Return the powered by caption with auto-updated year."""
    current_year = datetime.now().year
    return f"©ᴘᴏᴡᴇʀᴇᴅ ʙʏ 𝐀ᴜʀᴏʀᴀ𝐈ɪɴᴄ {current_year}"

def is_admin(user_id):
    return user_id in ADMIN_IDS

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
]

def get_random_headers():
    """Return random headers to appear as a real browser."""
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0',
    }

class IVASMSBot:
    def __init__(self):
        self.email = os.getenv("IVASMS_EMAIL", "")
        self.password = os.getenv("IVASMS_PASSWORD", "")
        self.bot_token = os.getenv("BOT_TOKEN", "")
        self.chat_id = os.getenv("CHAT_ID", "")
        self.session = requests.Session()
        self.driver = None
        self.consecutive_failures = 0
        self.last_sms = {}
        
        if not all([self.email, self.password, self.bot_token, self.chat_id]):
            logger.error("[INIT] Missing required environment variables!")
            sys.exit(1)
    
    def init_selenium_driver(self):
        """Initialize Selenium driver with undetected-chromedriver."""
        if not HAS_SELENIUM:
            logger.warning("[SELENIUM] Selenium not available, cannot initialize driver")
            return False
        
        try:
            logger.info("[SELENIUM] Initializing undetected Chrome driver...")
            options = uc.ChromeOptions()
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-web-resources")
            options.add_argument("--disable-features=VizDisplayCompositor")
            options.add_argument("--headless=new")
            options.add_argument(f"--user-agent={random.choice(USER_AGENTS)}")
            
            self.driver = uc.Chrome(options=options, version_main=None)
            logger.info("[SELENIUM] Chrome driver initialized successfully")
            return True
        except Exception as e:
            logger.error(f"[SELENIUM] Failed to initialize Chrome driver: {e}")
            self.driver = None
            return False
    
    def selenium_login(self):
        """Login using Selenium - bypasses Cloudflare properly."""
        if not HAS_SELENIUM or not self.driver:
            logger.warning("[SELENIUM] Selenium not available, falling back to requests")
            return self.requests_login()
        
        try:
            logger.info("[SELENIUM] Starting login with Selenium...")
            
            # Visit home page first to warm up
            logger.info("[SELENIUM] Warming up connection...")
            self.driver.get("https://www.ivasms.com/")
            time.sleep(random.uniform(2, 4))
            
            # Navigate to login
            logger.info("[SELENIUM] Navigating to login page...")
            self.driver.get("https://www.ivasms.com/login")
            time.sleep(random.uniform(3, 5))
            
            # Wait for page to load
            WebDriverWait(self.driver, 15).until(
                EC.presence_of_all_elements_located((By.TAG_NAME, "input"))
            )
            
            logger.info("[SELENIUM] Login page loaded, filling form...")
            
            # Find email field and type slowly (human-like)
            email_input = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.NAME, "email"))
            )
            for char in self.email:
                email_input.send_keys(char)
                time.sleep(random.uniform(0.05, 0.15))
            
            time.sleep(random.uniform(1, 2))
            
            # Find password field and type slowly
            password_input = self.driver.find_element(By.NAME, "password")
            for char in self.password:
                password_input.send_keys(char)
                time.sleep(random.uniform(0.05, 0.15))
            
            time.sleep(random.uniform(1, 2))
            
            # Submit form
            logger.info("[SELENIUM] Submitting login form...")
            submit_button = self.driver.find_element(By.XPATH, "//button[@type='submit']")
            submit_button.click()
            
            # Wait for redirect
            logger.info("[SELENIUM] Waiting for login response...")
            time.sleep(random.uniform(3, 6))
            
            # Check if login was successful
            current_url = self.driver.current_url
            if "dashboard" in current_url or "home" in current_url:
                logger.info("[SELENIUM] ✓ Login successful!")
                self.consecutive_failures = 0
                return True
            else:
                logger.error("[SELENIUM] Login may have failed - check credentials")
                return False
                
        except Exception as e:
            logger.error(f"[SELENIUM] Selenium login error: {e}")
            return False
    
    def requests_login(self):
        """Fallback login using requests with advanced headers."""
        try:
            logger.info("[LOGIN] Starting login with requests...")
            
            # Warm up - visit homepage
            logger.info("[LOGIN] Warming up connection...")
            for attempt in range(3):
                try:
                    resp = self.session.get("https://www.ivasms.com/", 
                                          headers=get_random_headers(),
                                          timeout=15)
                    if resp.status_code == 200:
                        logger.info("[LOGIN] Homepage loaded successfully")
                        break
                except Exception as e:
                    logger.warning(f"[LOGIN] Homepage warmup attempt {attempt+1} failed: {e}")
                    time.sleep(random.uniform(2, 4))
            
            time.sleep(random.uniform(2, 4))
            
            # Login attempt
            for attempt in range(5):
                try:
                    logger.info(f"[LOGIN] Login attempt {attempt+1}/5...")
                    
                    login_data = {
                        "email": self.email,
                        "password": self.password
                    }
                    
                    login_response = self.session.post(
                        "https://www.ivasms.com/login",
                        data=login_data,
                        headers=get_random_headers(),
                        timeout=20,
                        allow_redirects=True
                    )
                    
                    if login_response.status_code == 200:
                        if "dashboard" in login_response.url or "home" in login_response.url or "Logout" in login_response.text:
                            logger.info("[LOGIN] ✓ Login successful!")
                            self.consecutive_failures = 0
                            return True
                        else:
                            logger.warning("[LOGIN] Status 200 but not authenticated")
                    else:
                        logger.error(f"[LOGIN] Status {login_response.status_code}: {login_response.reason}")
                        
                except requests.Timeout:
                    logger.warning(f"[LOGIN] Timeout on attempt {attempt+1}, retrying...")
                except requests.RequestException as e:
                    logger.error(f"[LOGIN] Request error on attempt {attempt+1}: {e}")
                
                if attempt < 4:
                    wait_time = random.uniform(5, 15) * (attempt + 1)
                    logger.info(f"[LOGIN] Waiting {wait_time:.1f}s before retry...")
                    time.sleep(wait_time)
            
            logger.error("[LOGIN] All login attempts failed")
            self.consecutive_failures += 1
            return False
            
        except Exception as e:
            logger.error(f"[LOGIN] Unexpected error: {e}")
            self.consecutive_failures += 1
            return False
    
    def check_sms(self):
        """Check for new SMS messages."""
        try:
            logger.info("[SMS] Fetching SMS messages...")
            
            response = self.session.get(
                "https://www.ivasms.com/api/sms",
                headers=get_random_headers(),
                timeout=15
            )
            
            if response.status_code == 200:
                try:
                    sms_data = response.json()
                    new_messages = []
                    
                    if isinstance(sms_data, list):
                        for sms in sms_data:
                            sms_id = sms.get("id", str(random.random()))
                            if sms_id not in self.last_sms:
                                new_messages.append(sms)
                                self.last_sms[sms_id] = True
                    
                    if new_messages:
                        logger.info(f"[SMS] Found {len(new_messages)} new message(s)")
                        return new_messages
                    else:
                        logger.info("[SMS] No new messages")
                        return []
                except json.JSONDecodeError:
                    logger.warning("[SMS] Could not parse JSON response")
                    return []
            else:
                logger.error(f"[SMS] API error: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"[SMS] Error checking SMS: {e}")
            return []
    
    async def send_telegram_message(self, bot, message_text):
        """Send message to Telegram."""
        try:
            await bot.send_message(
                chat_id=self.chat_id,
                text=message_text,
                parse_mode="HTML"
            )
            logger.info("[TELEGRAM] Message sent successfully")
        except Exception as e:
            logger.error(f"[TELEGRAM] Error sending message: {e}")
    
    async def send_sms_notification(self, bot, sms):
        """Send SMS notification to Telegram with banner and buttons."""
        try:
            # Format message
            message = f"""
<b>📱 New SMS Received</b>

<b>From:</b> {sms.get('sender', 'Unknown')}
<b>Message:</b> {sms.get('message', 'No content')}
<b>Time:</b> {sms.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}

{get_powered_by_caption()}
"""
            
            # Send with banner
            with open("src/notification.mp3", "rb") if os.path.exists("src/notification.mp3") else None as audio:
                await bot.send_photo(
                    chat_id=self.chat_id,
                    photo=BANNER_URL,
                    caption=message,
                    parse_mode="HTML",
                    reply_markup=get_inline_keyboard()
                )
            
            logger.info("[NOTIFICATION] SMS notification sent")
            
        except Exception as e:
            logger.error(f"[NOTIFICATION] Error sending notification: {e}")
    
    async def handle_command(self, update, context):
        """Handle Telegram commands."""
        user_id = update.effective_user.id
        command = update.message.text.split()[0].lower()
        
        if command == "/start":
            await update.message.reply_text(
                "👋 Welcome to IVASMS Bot!\n\n"
                "🤖 I monitor your ivasms.com account and notify you about incoming SMS.\n\n"
                "📝 Commands:\n"
                "/status - Check bot status\n"
                "/help - Show this message\n",
                reply_markup=get_inline_keyboard()
            )
        
        elif command == "/help":
            await update.message.reply_text(
                "📖 Available Commands:\n\n"
                "/start - Welcome message\n"
                "/status - Bot status\n"
                "/help - This message\n",
                reply_markup=get_inline_keyboard()
            )
        
        elif command == "/status":
            status = "🟢 Online and monitoring" if not self.consecutive_failures else f"🟡 Issues detected ({self.consecutive_failures} failures)"
            await update.message.reply_text(
                f"Bot Status: {status}\n"
                f"Messages tracked: {len(self.last_sms)}\n\n"
                f"{get_powered_by_caption()}",
                reply_markup=get_inline_keyboard()
            )
        
        elif command == "/stats" and is_admin(user_id):
            await update.message.reply_text(
                f"📊 Admin Stats:\n"
                f"Messages tracked: {len(self.last_sms)}\n"
                f"Consecutive failures: {self.consecutive_failures}\n"
                f"Last check: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"{get_powered_by_caption()}",
                reply_markup=get_inline_keyboard()
            )
        
        elif command == "/broadcast" and is_admin(user_id):
            if len(context.args) > 0:
                msg = " ".join(context.args)
                await bot.send_message(chat_id=self.chat_id, text=msg, reply_markup=get_inline_keyboard())
                await update.message.reply_text("✓ Broadcast sent!")
            else:
                await update.message.reply_text("Usage: /broadcast <message>")
        
        elif command == "/restart" and is_admin(user_id):
            await update.message.reply_text("🔄 Restarting bot...")
            self.consecutive_failures = 0
            logger.info("[ADMIN] Bot restarted by admin")

async def main():
    """Main bot loop."""
    
    # Start health server in background
    health_thread = threading.Thread(target=run_health_server, daemon=True)
    health_thread.start()
    
    # Initialize bot
    bot = Bot(token=os.getenv("BOT_TOKEN"))
    application = Application.builder().token(os.getenv("BOT_TOKEN")).build()
    
    # Initialize IVASMS bot
    ivasms = IVASMSBot()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", ivasms.handle_command))
    application.add_handler(CommandHandler("help", ivasms.handle_command))
    application.add_handler(CommandHandler("status", ivasms.handle_command))
    application.add_handler(CommandHandler("stats", ivasms.handle_command))
    application.add_handler(CommandHandler("broadcast", ivasms.handle_command))
    application.add_handler(CommandHandler("restart", ivasms.handle_command))
    
    # Start application
    await application.initialize()
    await application.start()
    
    # Try Selenium first, fallback to requests
    if HAS_SELENIUM:
        if ivasms.init_selenium_driver():
            login_success = ivasms.selenium_login()
        else:
            login_success = ivasms.requests_login()
    else:
        login_success = ivasms.requests_login()
    
    if not login_success:
        logger.error("[MAIN] Initial login failed - check your credentials")
        await application.stop()
        return
    
    logger.info("[MAIN] Bot started successfully - monitoring for SMS...")
    
    # Main monitoring loop
    try:
        while True:
            try:
                sms_messages = ivasms.check_sms()
                
                if sms_messages:
                    for sms in sms_messages:
                        await ivasms.send_sms_notification(bot, sms)
                
                # Random interval between checks (30-60 seconds)
                wait_time = random.uniform(30, 60)
                logger.info(f"[MAIN] Next check in {wait_time:.1f}s...")
                await asyncio.sleep(wait_time)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[MAIN] Error in monitoring loop: {e}")
                ivasms.consecutive_failures += 1
                
                if ivasms.consecutive_failures >= 10:
                    logger.error("[MAIN] Too many failures, attempting re-login...")
                    if HAS_SELENIUM and ivasms.driver:
                        ivasms.selenium_login()
                    else:
                        ivasms.requests_login()
                    ivasms.consecutive_failures = 0
                
                await asyncio.sleep(random.uniform(60, 120))
    
    except KeyboardInterrupt:
        logger.info("[MAIN] Bot interrupted by user")
    
    finally:
        if ivasms.driver:
            ivasms.driver.quit()
        await application.stop()

if __name__ == "__main__":
    asyncio.run(main())
