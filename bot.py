import os
import logging
import tempfile
import asyncio
import aiofiles
import subprocess
import sys
import importlib
import importlib.util
from typing import Dict, List, Tuple
import json
from datetime import datetime
import socket
import ssl
import concurrent.futures
import threading
import random
from urllib.parse import urlparse
from io import BytesIO

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from telegram.request import HTTPXRequest

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Bot configuration
BOT_TOKEN = os.getenv('BOT_TOKEN', '8307126286:AAHIZJg7Zr47bCoFAXNHJydTA-r1vpWcj5k')
ADMIN_USER_ID = int(os.getenv('ADMIN_USER_ID', '7012262263'))

# Channel links
CHANNELS = {
    "Channel 1": "https://t.me/redsmoker2",
    "Channel 2": "https://t.me/redsmoker1", 
    "Channel 3": "https://t.me/redsmoker0",
    "Admin": "https://t.me/lookingforme8"
}

# Dynamic code storage
DYNAMIC_CODE_FILE = 'dynamic_code.py'
user_sessions: Dict[int, Dict] = {}

class NetworkScanner:
    def __init__(self, protocol: str, hosts_file: str, user_ip: str = "Unknown"):
        self.hosts_file = hosts_file
        self.max_workers = 30
        self.connect_timeout = 5
        self.rate_limit_delay = 0.1
        self.success_log_file = 'Success_hosts.txt'
        self.scan_lock = threading.Lock()
        self.user_ip = user_ip

        self.protocol = protocol.lower()
        self.ssl_context = None
        self.success_response = ''
        self.server_hostname = None
        self.vless_path = None
        self.port = 443

        if self.protocol in ['tls', 'vless', 'cloudfront_tls', 'dynamic_tls']:
            self.ssl_context = self._create_ssl_context()

        if self.protocol == 'tls':
            self.success_response = 'HTTP/1.1 101 Switching Protocols'
            self.server_hostname = 'nl1.wstunnel.xyz'
        elif self.protocol == 'http':
            self.success_response = 'HTTP/1.1 200 OK'
        elif self.protocol == 'vless':
            self.success_response = 'HTTP/1.1 101 Switching Protocols'
            self.server_hostname = 'sa3.vpnjantit.com'
            self.vless_path = '/vpnjantit'
        elif self.protocol == 'cloudfront_tls':
            self.success_response = 'HTTP/1.1 101 Switching Protocols'
            self.server_hostname = 'd3s0y8ulwafau2.cloudfront.net'
        elif self.protocol == 'dynamic_tls':
            self.success_response = 'HTTP/1.1'
            self.server_hostname = 'sambal-ijo.premm.shop'
        else:
            raise ValueError("Unsupported protocol")

    def _create_ssl_context(self):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3
            return context
        except Exception as e:
            logger.error(f"SSL context error: {e}")
            raise

    def _generate_handshake(self, host: str) -> bytes:
        try:
            host_header = self.server_hostname if self.server_hostname else host
            
            if self.protocol == 'cloudfront_tls':
                return (
                    f'PUT / HTTP/1.3\r\n'
                    f'Host: {host}\r\n'
                    f'\r\n'
                    f'\n\n'
                    f'X / HTTP/1.2\r\n'
                    f'Host: {host}\r\n'
                    f'\n\r\n'
                    f'GET / HTTP/1.1\r\n'
                    f'Host: d3s0y8ulwafau2.cloudfront.net\r\n'
                    f'Upgrade: websocket\r\n'
                    f'Connection: Upgrade\r\n'
                    f'\r\n'
                ).encode('utf-8')
            elif self.protocol == 'dynamic_tls':
                user_agents = [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                ]
                ua = random.choice(user_agents)
                return (
                    f'GET /cdn-cgi/trace HTTP/1.1\r\n'
                    f'Host: {host}\r\n'
                    f'\r\n'
                    f'UNLOCK /? HTTP/1.1\r\n'
                    f'Host: sambal-ijo.premm.shop\r\n'
                    f'Connection: upgrade\r\n'
                    f'User-Agent: {ua}\r\n'
                    f'Upgrade: websocket\r\n'
                    f'\r\n'
                    f'UNLOCK /? HTTP/1.1\r\n'
                    f'Host: {host}\r\n'
                    f'Content-Length: 999999999999\r\n'
                    f'\r\n'
                ).encode('utf-8')
            elif self.protocol in ['tls', 'vless']:
                path = self.vless_path if self.protocol == 'vless' else '/'
                return (
                    f'GET {path} HTTP/1.1\r\n'
                    f'Host: {host_header}\r\n'
                    f'Upgrade: websocket\r\n'
                    f'Connection: Upgrade\r\n'
                    f'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
                    f'Sec-WebSocket-Version: 13\r\n'
                    f'\r\n'
                ).encode('utf-8')
            elif self.protocol == 'http':
                return (
                    f'GET / HTTP/1.1\r\n'
                    f'Host: {host}\r\n'
                    f'Connection: close\r\n'
                    f'\r\n'
                ).encode('utf-8')
            return b''
        except Exception as e:
            logger.error(f"Handshake error for {host}: {e}")
            return b''

    def _log_successful_host(self, host: str):
        try:
            with self.scan_lock:
                with open(self.success_log_file, 'a', encoding='utf-8') as log_file:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    sni_info = f" (SNI: {self.server_hostname})" if self.server_hostname else ""
                    log_file.write(f"{timestamp} - User: {self.user_ip} - {self.protocol.upper()}://{host}:{self.port}{sni_info}\n")
        except Exception as e:
            logger.error(f"Log error: {e}")

    def _safe_socket_operation(self, host: str, operation_func):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return operation_func(sock)
        except Exception as e:
            return None
        finally:
            try:
                if 'sock' in locals():
                    sock.close()
            except:
                pass

    def check_host(self, host: str) -> Tuple[str, bool]:
        time.sleep(self.rate_limit_delay)
        
        def socket_operation(sock):
            sock.connect((host, self.port))
            if self.protocol in ['tls', 'vless', 'cloudfront_tls', 'dynamic_tls']:
                sni_hostname = self.server_hostname if self.server_hostname else host
                wrapped_sock = self.ssl_context.wrap_socket(sock, server_hostname=sni_hostname, do_handshake_on_connect=True)
                try:
                    wrapped_sock.sendall(self._generate_handshake(host))
                    response = wrapped_sock.recv(4096).decode('utf-8', errors='ignore')
                    wrapped_sock.close()
                except Exception:
                    if wrapped_sock:
                        try:
                            wrapped_sock.close()
                        except:
                            pass
                    raise
            else:
                sock.sendall(self._generate_handshake(host))
                response = sock.recv(4096).decode('utf-8', errors='ignore')
            return response

        response = self._safe_socket_operation(host, socket_operation)
        if response is None:
            return (host, False)

        try:
            if self.protocol in ['cloudfront_tls', 'dynamic_tls'] and 'HTTP/' in response:
                self._log_successful_host(host)
                return (host, True)
            elif self.protocol in ['tls', 'vless'] and response.startswith('HTTP/1.1 101 Switching Protocols'):
                self._log_successful_host(host)
                return (host, True)
            elif response.startswith(self.success_response):
                self._log_successful_host(host)
                return (host, True)
            else:
                return (host, False)
        except Exception as e:
            logger.error(f"Response processing error for {host}: {e}")
            return (host, False)

    def load_hosts(self, file_content: str) -> List[str]:
        hosts = []
        for line_num, line in enumerate(file_content.splitlines(), 1):
            host = line.strip()
            if host and not host.startswith('#'):
                try:
                    if ':' in host:
                        host = host.split(':')[0]
                    parsed = urlparse(f"//{'[::1]' if ':' in host else host}")
                    if parsed.hostname:
                        hosts.append(parsed.hostname)
                except Exception as e:
                    logger.warning(f"Invalid host at line {line_num}: {host} - {e}")
        return hosts

    def run_scan(self, hosts: List[str]) -> Dict[str, bool]:
        results = {}
        try:
            open(self.success_log_file, 'w').close()
        except Exception as e:
            logger.error(f"Could not clear log file: {e}")
        
        successful_hosts = 0
        total_hosts = len(hosts)
        
        if total_hosts == 0:
            return {}
        
        chunk_size = 500
        for chunk_start in range(0, total_hosts, chunk_size):
            chunk_end = min(chunk_start + chunk_size, total_hosts)
            chunk = hosts[chunk_start:chunk_end]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_host = {executor.submit(self.check_host, host): host for host in chunk}
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        _, success = future.result(timeout=self.connect_timeout + 5)
                        results[host] = success
                        if success:
                            successful_hosts += 1
                    except Exception:
                        results[host] = False
        
        return {
            'total': total_hosts,
            'successful': successful_hosts,
            'failed': total_hosts - successful_hosts,
            'success_rate': (successful_hosts/total_hosts)*100 if total_hosts > 0 else 0
        }

# Admin Functions
async def execute_dynamic_code():
    """Execute dynamically loaded code if exists"""
    if os.path.exists(DYNAMIC_CODE_FILE):
        try:
            spec = importlib.util.spec_from_file_location("dynamic_code", DYNAMIC_CODE_FILE)
            if spec and spec.loader:
                dynamic_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(dynamic_module)
                logger.info("Dynamic code executed successfully")
                return True
        except Exception as e:
            logger.error(f"Error executing dynamic code: {e}")
    return False

async def stop_bot(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Stop the bot (admin only)"""
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("❌ Admin only command")
        return
    
    await update.message.reply_text("🛑 Bot is shutting down...")
    logger.info("Bot stopped by admin")
    os._exit(0)

async def restart_bot(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Restart the bot (admin only)"""
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("❌ Admin only command")
        return
    
    await update.message.reply_text("🔄 Restarting bot and server...")
    logger.info("Bot restart initiated by admin")
    
    python = sys.executable
    os.execl(python, python, *sys.argv)

async def add_code(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Add dynamic code to bot (admin only)"""
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("❌ Admin only command")
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /addcode <python code>")
        return
    
    code = ' '.join(context.args)
    
    try:
        compile(code, '<string>', 'exec')
        
        with open(DYNAMIC_CODE_FILE, 'w') as f:
            f.write(code)
        
        await execute_dynamic_code()
        await update.message.reply_text("✅ Code added and executed successfully!")
        
    except Exception as e:
        await update.message.reply_text(f"❌ Code error: {str(e)}")

async def eval_code(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Execute Python code (admin only)"""
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("❌ Admin only command")
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /eval <python code>")
        return
    
    code = ' '.join(context.args)
    
    try:
        local_vars = {}
        exec(code, globals(), local_vars)
        result = local_vars.get('result', 'Code executed successfully')
        await update.message.reply_text(f"✅ Result: {result}")
        
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show admin panel"""
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("❌ Admin only command")
        return
    
    keyboard = [
        [InlineKeyboardButton("🛑 Stop Bot", callback_data="admin_stop")],
        [InlineKeyboardButton("🔄 Restart Bot", callback_data="admin_restart")],
        [InlineKeyboardButton("📊 Bot Stats", callback_data="admin_stats")],
        [InlineKeyboardButton("💾 Dynamic Code", callback_data="admin_code")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "🛠️ *Admin Panel*\n\n"
        "Available commands:\n"
        "/stop - Stop bot\n"
        "/restart - Restart bot\n" 
        "/addcode <code> - Add dynamic code\n"
        "/eval <code> - Execute code\n"
        "/stats - Show bot statistics",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show bot statistics"""
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("❌ Admin only command")
        return
    
    stats_text = (
        f"📊 *Bot Statistics*\n\n"
        f"• Active sessions: {len(user_sessions)}\n"
        f"• Admin ID: {ADMIN_USER_ID}\n"
        f"• Bot running since: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"• Dynamic code loaded: {os.path.exists(DYNAMIC_CODE_FILE)}"
    )
    
    await update.message.reply_text(stats_text, parse_mode='Markdown')

# User Handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    user_ip = update.effective_user.id
    
    user_sessions[user_id] = {'ip': user_ip, 'stage': 'protocol_selection'}
    
    keyboard = [
        [InlineKeyboardButton("HTTP", callback_data="protocol_http")],
        [InlineKeyboardButton("TLS", callback_data="protocol_tls")],
        [InlineKeyboardButton("VLESS", callback_data="protocol_vless")],
        [InlineKeyboardButton("CloudFront TLS", callback_data="protocol_cloudfront_tls")],
        [InlineKeyboardButton("Dynamic TLS", callback_data="protocol_dynamic_tls")],
        [InlineKeyboardButton("📢 Our Channels", callback_data="channels")],
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = """
🤖 *Welcome to Hydra Nation Scanner Bot!*

*Features:*
• Scan hosts files for working servers
• Multiple protocol support  
• Real-time scanning progress
• Success hosts file generation

*Select a protocol to start scanning:*
    """
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')

async def channels_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    
    channels_text = "📢 *Our Channels:*\n\n"
    for name, url in CHANNELS.items():
        channels_text += f"• [{name}]({url})\n"
    
    keyboard = [[InlineKeyboardButton("🔙 Back to Main Menu", callback_data="back_to_main")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(channels_text, reply_markup=reply_markup, parse_mode='Markdown', disable_web_page_preview=True)

async def protocol_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    protocol = query.data.replace('protocol_', '')
    
    user_sessions[user_id] = {'protocol': protocol, 'stage': 'waiting_file', 'ip': user_id}
    
    keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        f"✅ Selected protocol: *{protocol.upper()}*\n\n"
        "📁 Now please send me your hosts file (text file with one host per line)",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    
    if user_id not in user_sessions or user_sessions[user_id].get('stage') != 'waiting_file':
        await update.message.reply_text("❌ Please select a protocol first using /start")
        return
    
    document = update.message.document
    
    if not document.mime_type.startswith('text/') and not document.file_name.endswith('.txt'):
        await update.message.reply_text("❌ Please send a valid text file (.txt)")
        return
    
    try:
        file = await context.bot.get_file(document.file_id)
        file_content = await file.download_as_bytearray()
        file_text = file_content.decode('utf-8')
        
        user_sessions[user_id]['file_content'] = file_text
        user_sessions[user_id]['stage'] = 'ready_to_scan'
        
        lines = [line.strip() for line in file_text.splitlines() if line.strip() and not line.strip().startswith('#')]
        
        keyboard = [
            [InlineKeyboardButton("🚀 Start Scan", callback_data="start_scan")],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_protocol")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            f"📊 File received!\n• Total hosts: {len(lines)}\n• Protocol: {user_sessions[user_id]['protocol'].upper()}\n\nClick 'Start Scan' to begin:",
            reply_markup=reply_markup
        )
        
    except Exception as e:
        logger.error(f"File handling error: {e}")
        await update.message.reply_text("❌ Error processing file. Please try again.")

async def start_scan_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    
    if user_id not in user_sessions or user_sessions[user_id].get('stage') != 'ready_to_scan':
        await query.edit_message_text("❌ Session expired. Please start over with /start")
        return
    
    protocol = user_sessions[user_id]['protocol']
    file_content = user_sessions[user_id]['file_content']
    user_ip = user_sessions[user_id]['ip']
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(file_content)
        temp_file = f.name
    
    try:
        scanner = NetworkScanner(protocol, temp_file, user_ip)
        hosts = scanner.load_hosts(file_content)
        
        if not hosts:
            await query.edit_message_text("❌ No valid hosts found in the file.")
            return
        
        progress_msg = await query.edit_message_text(
            f"🔍 *Scanning Started*\n\n• Protocol: {protocol.upper()}\n• Total hosts: {len(hosts)}\n• Status: Initializing...\n\n⏳ Please wait...",
            parse_mode='Markdown'
        )
        
        results = scanner.run_scan(hosts)
        
        result_text = (
            f"✅ *Scan Complete!*\n\n📊 *Results:*\n• Total hosts: {results['total']}\n"
            f"• ✅ Successful: {results['successful']}\n• ❌ Failed: {results['failed']}\n"
            f"• 📈 Success rate: {results['success_rate']:.1f}%\n• 👤 User IP: {user_ip}\n\n"
        )
        
        if os.path.exists(scanner.success_log_file):
            success_count = results['successful']
            if success_count > 0:
                async with aiofiles.open(scanner.success_log_file, 'r') as f:
                    success_content = await f.read()
                
                user_success_file = f"Success_hosts_{user_id}.txt"
                async with aiofiles.open(user_success_file, 'w') as f:
                    await f.write(success_content)
                
                await context.bot.send_document(
                    chat_id=query.message.chat_id,
                    document=user_success_file,
                    filename=f"Success_hosts_{protocol}.txt",
                    caption=f"📁 Successful hosts file ({success_count} hosts)"
                )
                
                os.remove(user_success_file)
                result_text += f"📁 Success file sent with {success_count} working hosts!"
            else:
                result_text += "❌ No successful hosts found."
        else:
            result_text += "❌ No successful hosts found."
        
        keyboard = [
            [InlineKeyboardButton("🔄 Scan Again", callback_data="back_to_main")],
            [InlineKeyboardButton("📢 Our Channels", callback_data="channels")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(result_text, reply_markup=reply_markup, parse_mode='Markdown')
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        await query.edit_message_text(f"❌ Scan failed: {str(e)}")
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        if user_id in user_sessions:
            user_sessions[user_id]['stage'] = 'completed'

async def back_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    
    if query.data == "back_to_main":
        keyboard = [
            [InlineKeyboardButton("HTTP", callback_data="protocol_http")],
            [InlineKeyboardButton("TLS", callback_data="protocol_tls")],
            [InlineKeyboardButton("VLESS", callback_data="protocol_vless")],
            [InlineKeyboardButton("CloudFront TLS", callback_data="protocol_cloudfront_tls")],
            [InlineKeyboardButton("Dynamic TLS", callback_data="protocol_dynamic_tls")],
            [InlineKeyboardButton("📢 Our Channels", callback_data="channels")],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("🤖 *Hydra Nation Scanner Bot*\n\nSelect a protocol to start scanning:", reply_markup=reply_markup, parse_mode='Markdown')
    elif query.data == "back_to_protocol":
        if user_id in user_sessions:
            user_sessions[user_id]['stage'] = 'protocol_selection'
        keyboard = [
            [InlineKeyboardButton("HTTP", callback_data="protocol_http")],
            [InlineKeyboardButton("TLS", callback_data="protocol_tls")],
            [InlineKeyboardButton("VLESS", callback_data="protocol_vless")],
            [InlineKeyboardButton("CloudFront TLS", callback_data="protocol_cloudfront_tls")],
            [InlineKeyboardButton("Dynamic TLS", callback_data="protocol_dynamic_tls")],
            [InlineKeyboardButton("📢 Our Channels", callback_data="channels")],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Select a protocol:", reply_markup=reply_markup)

async def admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    
    if query.from_user.id != ADMIN_USER_ID:
        await query.edit_message_text("❌ Admin only")
        return
    
    if query.data == "admin_stop":
        await query.edit_message_text("🛑 Bot is shutting down...")
        os._exit(0)
    elif query.data == "admin_restart":
        await query.edit_message_text("🔄 Restarting bot and server...")
        python = sys.executable
        os.execl(python, python, *sys.argv)
    elif query.data == "admin_stats":
        stats_text = f"📊 *Bot Statistics*\n\n• Active sessions: {len(user_sessions)}\n• Admin ID: {ADMIN_USER_ID}\n• Bot running since: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        await query.edit_message_text(stats_text, parse_mode='Markdown')
    elif query.data == "admin_code":
        code_text = "💾 *Dynamic Code*\n\nUse /addcode <code> to add new features dynamically."
        await query.edit_message_text(code_text, parse_mode='Markdown')

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error(f"Exception while handling an update: {context.error}")
    try:
        if update and update.effective_message:
            await update.effective_message.reply_text("❌ An error occurred. Please try again or contact admin.")
    except Exception as e:
        logger.error(f"Error in error handler: {e}")

def main() -> None:
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN environment variable is required")
    
    # Execute any existing dynamic code
    asyncio.run(execute_dynamic_code())
    
    request = HTTPXRequest(connection_pool_size=50)
    application = Application.builder().token(BOT_TOKEN).request(request).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("stop", stop_bot))
    application.add_handler(CommandHandler("restart", restart_bot))
    application.add_handler(CommandHandler("addcode", add_code))
    application.add_handler(CommandHandler("eval", eval_code))
    application.add_handler(CommandHandler("admin", admin_panel))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CallbackQueryHandler(protocol_callback, pattern="^protocol_"))
    application.add_handler(CallbackQueryHandler(channels_callback, pattern="^channels$"))
    application.add_handler(CallbackQueryHandler(start_scan_callback, pattern="^start_scan$"))
    application.add_handler(CallbackQueryHandler(back_button, pattern="^back_to_"))
    application.add_handler(CallbackQueryHandler(admin_callback, pattern="^admin_"))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_error_handler(error_handler)
    
    print("🤖 Hydra Nation Scanner Bot is running...")
    print(f"👑 Admin ID: {ADMIN_USER_ID}")
    print("🚀 Bot started successfully!")
    
    # Start the bot with error handling
    try:
        application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
