import os
import logging
import re
import json
import socket
import ssl
import time
import dns.resolver
import requests
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler
from telegram.constants import ParseMode
import asyncio
import aiohttp
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Environment variables
BOT_TOKEN = os.environ.get('BOT_TOKEN', 'YOUR_BOT_TOKEN_HERE')
PORT = int(os.environ.get('PORT', 8080))

class WebsiteTools:
    """Core class handling all website tools functionality"""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Ensure URL has proper scheme"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    @staticmethod
    async def check_website_status(url: str) -> Dict[str, Any]:
        """Check if a website is online and get status code"""
        try:
            url = WebsiteTools.normalize_url(url)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, allow_redirects=True) as response:
                    return {
                        'status': 'online',
                        'status_code': response.status,
                        'url': str(response.url),
                        'reason': response.reason
                    }
        except aiohttp.ClientError as e:
            return {'status': 'offline', 'error': str(e)}
        except asyncio.TimeoutError:
            return {'status': 'offline', 'error': 'Connection timeout'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    @staticmethod
    async def check_response_time(url: str) -> Dict[str, Any]:
        """Check website response time"""
        try:
            url = WebsiteTools.normalize_url(url)
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    end_time = time.time()
                    response_time = (end_time - start_time) * 1000
                    return {
                        'response_time': round(response_time, 2),
                        'status_code': response.status
                    }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    async def check_ssl_certificate(url: str) -> Dict[str, Any]:
        """Check SSL certificate details"""
        try:
            parsed_url = urlparse(WebsiteTools.normalize_url(url))
            hostname = parsed_url.hostname
            
            if not hostname:
                return {'error': 'Invalid URL'}
            
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.connect((hostname, 443))
                cert = s.getpeercert()
                
            cert_der = s.getpeercert(binary_form=True)
            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
            
            subject = dict(cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
            issuer = dict(cert_obj.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
            
            not_before = cert_obj.not_valid_before_utc
            not_after = cert_obj.not_valid_after_utc
            
            days_remaining = (not_after - datetime.now()).days
            
            return {
                'issued_to': subject.get(x509.NameOID.COMMON_NAME, 'N/A'),
                'issued_by': issuer.get(x509.NameOID.COMMON_NAME, 'N/A'),
                'valid_from': not_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'valid_until': not_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'days_remaining': days_remaining,
                'expired': days_remaining <= 0
            }
        except Exception as e:
            return {'error': f'SSL certificate check failed: {str(e)}'}
    
    @staticmethod
    async def dns_lookup(domain: str) -> Dict[str, Any]:
        """Perform DNS lookup for a domain"""
        try:
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            
            a_records = []
            try:
                answers = dns.resolver.resolve(domain, 'A')
                a_records = [str(r) for r in answers]
            except:
                pass
            
            mx_records = []
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                mx_records = [f"{str(r.exchange)} (priority: {r.preference})" for r in answers]
            except:
                pass
            
            ns_records = []
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                ns_records = [str(r) for r in answers]
            except:
                pass
            
            txt_records = []
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                txt_records = [str(r) for r in answers]
            except:
                pass
            
            return {
                'domain': domain,
                'a_records': a_records if a_records else ['No A records found'],
                'mx_records': mx_records if mx_records else ['No MX records found'],
                'ns_records': ns_records if ns_records else ['No NS records found'],
                'txt_records': txt_records if txt_records else ['No TXT records found']
            }
        except Exception as e:
            return {'error': f'DNS lookup failed: {str(e)}'}
    
    @staticmethod
    async def ip_lookup(domain: str) -> Dict[str, Any]:
        """Get IP address(es) for a domain"""
        try:
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            ips = socket.gethostbyname_ex(domain)
            
            return {
                'domain': domain,
                'hostname': ips[0],
                'ips': ips[2],
                'aliases': ips[1]
            }
        except Exception as e:
            return {'error': f'IP lookup failed: {str(e)}'}
    
    @staticmethod
    async def get_domain_info(domain: str) -> Dict[str, Any]:
        """Get WHOIS information for a domain"""
        try:
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            w = whois.whois(domain)
            
            def parse_date(date_val):
                if isinstance(date_val, list):
                    return [d.strftime('%Y-%m-%d %H:%M:%S') if d else 'N/A' for d in date_val]
                return date_val.strftime('%Y-%m-%d %H:%M:%S') if date_val else 'N/A'
            
            return {
                'domain': domain,
                'registrar': w.registrar if w.registrar else 'N/A',
                'creation_date': parse_date(w.creation_date),
                'expiration_date': parse_date(w.expiration_date),
                'name_servers': w.name_servers if w.name_servers else ['N/A'],
                'status': w.status if w.status else ['N/A']
            }
        except Exception as e:
            return {'error': f'Domain info lookup failed: {str(e)}'}
    
    @staticmethod
    async def check_redirect(url: str) -> Dict[str, Any]:
        """Check redirect chain for a URL"""
        try:
            url = WebsiteTools.normalize_url(url)
            redirects = []
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, allow_redirects=False, timeout=10) as response:
                    status_code = response.status
                    redirect_url = response.headers.get('Location')
                    
                    redirects.append({
                        'url': str(response.url),
                        'status_code': status_code,
                        'redirect_to': redirect_url if redirect_url else 'Final destination'
                    })
                    
                    count = 0
                    while redirect_url and count < 5:
                        count += 1
                        next_url = urljoin(str(response.url), redirect_url)
                        try:
                            async with session.get(next_url, allow_redirects=False, timeout=10) as resp:
                                status_code = resp.status
                                redirect_url = resp.headers.get('Location')
                                redirects.append({
                                    'url': str(resp.url),
                                    'status_code': status_code,
                                    'redirect_to': redirect_url if redirect_url else 'Final destination'
                                })
                        except:
                            break
            
            return {
                'redirect_chain': redirects,
                'total_redirects': len(redirects) - 1
            }
        except Exception as e:
            return {'error': f'Redirect check failed: {str(e)}'}
    
    @staticmethod
    async def get_http_headers(url: str) -> Dict[str, Any]:
        """Get HTTP headers for a URL"""
        try:
            url = WebsiteTools.normalize_url(url)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    headers = dict(response.headers)
                    
                    formatted_headers = {}
                    for key, value in headers.items():
                        formatted_headers[key] = value
                    
                    return {
                        'headers': formatted_headers,
                        'status_code': response.status,
                        'server': response.headers.get('Server', 'N/A')
                    }
        except Exception as e:
            return {'error': f'Header check failed: {str(e)}'}
    
    @staticmethod
    async def get_page_metadata(url: str) -> Dict[str, Any]:
        """Extract page title and metadata"""
        try:
            url = WebsiteTools.normalize_url(url)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    title = soup.title.string.strip() if soup.title else 'No title found'
                    
                    description = ''
                    meta_desc = soup.find('meta', attrs={'name': 'description'})
                    if meta_desc:
                        description = meta_desc.get('content', '')
                    
                    keywords = ''
                    meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
                    if meta_keywords:
                        keywords = meta_keywords.get('content', '')
                    
                    og_title = ''
                    og_description = ''
                    og_image = ''
                    
                    og_meta = soup.find('meta', property='og:title')
                    if og_meta:
                        og_title = og_meta.get('content', '')
                    
                    og_meta = soup.find('meta', property='og:description')
                    if og_meta:
                        og_description = og_meta.get('content', '')
                    
                    og_meta = soup.find('meta', property='og:image')
                    if og_meta:
                        og_image = og_meta.get('content', '')
                    
                    return {
                        'title': title,
                        'description': description,
                        'keywords': keywords,
                        'og_title': og_title,
                        'og_description': og_description,
                        'og_image': og_image
                    }
        except Exception as e:
            return {'error': f'Metadata extraction failed: {str(e)}'}
    
    @staticmethod
    async def check_mobile_friendly(url: str) -> Dict[str, Any]:
        """Check if a website is mobile-friendly"""
        try:
            url = WebsiteTools.normalize_url(url)
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    viewport = soup.find('meta', attrs={'name': 'viewport'})
                    has_viewport = bool(viewport)
                    
                    has_media_queries = '@media' in html.lower()
                    
                    has_mobile_tag = bool(soup.find('meta', attrs={'name': 'mobileoptimized'}) or 
                                        soup.find('meta', attrs={'name': 'handheldfriendly'}))
                    
                    css_found = bool(soup.find('link', rel='stylesheet'))
                    
                    images = soup.find_all('img')
                    images_without_maxwidth = 0
                    
                    for img in images:
                        if not img.get('style') or 'max-width' not in img.get('style', ''):
                            images_without_maxwidth += 1
                    
                    return {
                        'has_viewport': has_viewport,
                        'has_media_queries': has_media_queries,
                        'has_mobile_tag': has_mobile_tag,
                        'has_css': css_found,
                        'images_without_responsive': images_without_maxwidth,
                        'total_images': len(images),
                        'mobile_friendly': has_viewport and has_media_queries,
                        'score': 'Good' if (has_viewport and has_media_queries) else 'Needs improvement'
                    }
        except Exception as e:
            return {'error': f'Mobile-friendly check failed: {str(e)}'}
    
    @staticmethod
    async def get_robots_txt(url: str) -> Dict[str, Any]:
        """Check robots.txt file"""
        try:
            parsed_url = urlparse(WebsiteTools.normalize_url(url))
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(robots_url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        return {
                            'exists': True,
                            'status_code': response.status,
                            'content': content[:500] + ('...' if len(content) > 500 else '')
                        }
                    else:
                        return {
                            'exists': False,
                            'status_code': response.status
                        }
        except Exception as e:
            return {'error': f'Robots.txt check failed: {str(e)}'}
    
    @staticmethod
    async def get_sitemap(url: str) -> Dict[str, Any]:
        """Check sitemap.xml"""
        try:
            parsed_url = urlparse(WebsiteTools.normalize_url(url))
            sitemap_url = f"{parsed_url.scheme}://{parsed_url.netloc}/sitemap.xml"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(sitemap_url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'xml')
                        urls = soup.find_all('url')
                        
                        if not urls:
                            sitemaps = soup.find_all('sitemap')
                            if sitemaps:
                                url_count = len(sitemaps)
                                return {
                                    'exists': True,
                                    'type': 'sitemap_index',
                                    'sitemap_count': url_count,
                                    'content': content[:500] + ('...' if len(content) > 500 else '')
                                }
                        
                        return {
                            'exists': True,
                            'type': 'sitemap',
                            'url_count': len(urls),
                            'first_urls': [url.find('loc').text if url.find('loc') else '' for url in urls[:5]],
                            'content': content[:500] + ('...' if len(content) > 500 else '')
                        }
                    else:
                        return {
                            'exists': False,
                            'status_code': response.status
                        }
        except Exception as e:
            return {'error': f'Sitemap check failed: {str(e)}'}

class BotHandlers:
    """Handles all bot commands and interactions"""
    
    def __init__(self):
        self.tools = WebsiteTools()
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        welcome_text = """
Welcome to Website Tools Bot!

I can help you analyze websites with various tools:

Available Commands:
/help - Show all available commands
/check_status - Check if a website is online
/response_time - Check website response time
/ssl_check - Verify SSL certificate
/dns_lookup - DNS records lookup
/ip_lookup - IP address lookup
/domain_info - Domain WHOIS information
/redirect_check - Check redirect chain
/headers - HTTP headers checker
/metadata - Page title and metadata
/mobile_friendly - Mobile-friendly check
/robots - Robots.txt checker
/sitemap - Sitemap checker

How to use:
1. Type the command
2. Send the URL when prompted
3. Get detailed analysis!
"""
        keyboard = [
            [InlineKeyboardButton("Check Website", callback_data='check_website')],
            [InlineKeyboardButton("Full Analysis", callback_data='full_analysis')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            welcome_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=reply_markup
        )
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_text = """
Website Tools Bot - Help

Available Commands:

/check_status - Check if a website is online
   Example: Check if website is accessible

/response_time - Measure website response time
   Example: How fast does the site respond?

/ssl_check - SSL certificate details
   Example: Check SSL validity and issuer

/dns_lookup - Get DNS records
   Example: A, MX, NS, TXT records

/ip_lookup - Find IP addresses
   Example: All IPs associated with domain

/domain_info - WHOIS information
   Example: Domain registration details

/redirect_check - Check redirect chain
   Example: Track all redirects

/headers - HTTP headers analysis
   Example: Server, content-type, etc.

/metadata - Page metadata extraction
   Example: Title, description, OpenGraph

/mobile_friendly - Check mobile optimization
   Example: Is the site mobile-friendly?

/robots - Check robots.txt
   Example: See robots.txt content

/sitemap - Check sitemap.xml
   Example: See sitemap structure

Commands Usage:
Type the command, then send the URL when prompted.

Tips:
* Include https:// or http:// in URLs
* Some commands work with just domain names
* Results are formatted for easy reading
"""
        await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)
    
    async def handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle inline keyboard callbacks"""
        query = update.callback_query
        await query.answer()
        
        if query.data == 'check_website':
            await query.message.reply_text("Please send me the URL you want to check:")
            context.user_data['awaiting_url'] = 'check_status'
        elif query.data == 'full_analysis':
            await query.message.reply_text("Please send me the URL for full analysis:")
            context.user_data['awaiting_url'] = 'full_analysis'
    
    async def handle_url_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle URL input from user"""
        user_input = update.message.text.strip()
        
        if 'awaiting_url' not in context.user_data:
            return
        
        action = context.user_data['awaiting_url']
        del context.user_data['awaiting_url']
        
        if not user_input.startswith(('http://', 'https://')):
            user_input = 'https://' + user_input
        
        try:
            progress_msg = await update.message.reply_text("Analyzing website... Please wait.")
            
            if action == 'check_status':
                result = await self.tools.check_website_status(user_input)
                response = self.format_status_result(result, user_input)
                await progress_msg.edit_text(response, parse_mode=ParseMode.MARKDOWN)
            
            elif action == 'full_analysis':
                results = {}
                
                status_result = await self.tools.check_website_status(user_input)
                results['status'] = status_result
                
                if status_result.get('status') == 'online':
                    response_time_result = await self.tools.check_response_time(user_input)
                    results['response_time'] = response_time_result
                
                ssl_result = await self.tools.check_ssl_certificate(user_input)
                results['ssl'] = ssl_result
                
                metadata_result = await self.tools.get_page_metadata(user_input)
                results['metadata'] = metadata_result
                
                mobile_result = await self.tools.check_mobile_friendly(user_input)
                results['mobile'] = mobile_result
                
                response = self.format_full_analysis(results, user_input)
                await progress_msg.edit_text(response, parse_mode=ParseMode.MARKDOWN)
            
            else:
                result = await self.handle_tool_command(action, user_input)
                if result:
                    await progress_msg.edit_text(result, parse_mode=ParseMode.MARKDOWN)
                else:
                    await progress_msg.edit_text("Error: Could not perform the requested analysis.")
        
        except Exception as e:
            logger.error(f"Error handling URL input: {e}")
            await update.message.reply_text(f"Error: {str(e)}")
    
    async def handle_tool_command(self, action: str, url: str):
        """Execute specific tool command"""
        if action == 'check_status':
            result = await self.tools.check_website_status(url)
            return self.format_status_result(result, url)
        elif action == 'response_time':
            result = await self.tools.check_response_time(url)
            return self.format_response_time_result(result, url)
        elif action == 'ssl_check':
            result = await self.tools.check_ssl_certificate(url)
            return self.format_ssl_result(result, url)
        elif action == 'dns_lookup':
            result = await self.tools.dns_lookup(url)
            return self.format_dns_result(result)
        elif action == 'ip_lookup':
            result = await self.tools.ip_lookup(url)
            return self.format_ip_result(result)
        elif action == 'domain_info':
            result = await self.tools.get_domain_info(url)
            return self.format_domain_info_result(result)
        elif action == 'redirect_check':
            result = await self.tools.check_redirect(url)
            return self.format_redirect_result(result, url)
        elif action == 'headers':
            result = await self.tools.get_http_headers(url)
            return self.format_headers_result(result, url)
        elif action == 'metadata':
            result = await self.tools.get_page_metadata(url)
            return self.format_metadata_result(result, url)
        elif action == 'mobile_friendly':
            result = await self.tools.check_mobile_friendly(url)
            return self.format_mobile_result(result, url)
        elif action == 'robots':
            result = await self.tools.get_robots_txt(url)
            return self.format_robots_result(result, url)
        elif action == 'sitemap':
            result = await self.tools.get_sitemap(url)
            return self.format_sitemap_result(result, url)
        return None
    
    # Formatting methods for results
    def format_status_result(self, result: Dict[str, Any], url: str) -> str:
        if result.get('status') == 'online':
            return f"""
Website Status
URL: {url}
Status: Online
Status Code: {result.get('status_code')}
Reason: {result.get('reason', 'OK')}
Final URL: {result.get('url', url)}
"""
        else:
            return f"""
Website Status
URL: {url}
Status: Offline
Error: {result.get('error', 'Unknown error')}
"""
    
    def format_response_time_result(self, result: Dict[str, Any], url: str) -> str:
        if 'error' in result:
            return f"Response Time Check Failed\nError: {result['error']}"
        
        status = "Fast" if result['response_time'] < 500 else "Slow" if result['response_time'] < 1000 else "Very Slow"
        return f"""
Response Time Analysis
URL: {url}
Response Time: {result['response_time']} ms
Status: {status}
Status Code: {result.get('status_code')}
"""
    
    def format_ssl_result(self, result: Dict[str, Any], url: str) -> str:
        if 'error' in result:
            return f"SSL Certificate Check Failed\nError: {result['error']}"
        
        expiry_status = "Valid" if result['days_remaining'] > 30 else "Expiring Soon" if result['days_remaining'] > 7 else "Expired/Critical"
        
        return f"""
SSL Certificate Details
Domain: {url}
Issued To: {result.get('issued_to')}
Issued By: {result.get('issued_by')}
Valid From: {result.get('valid_from')}
Valid Until: {result.get('valid_until')}
Days Remaining: {result.get('days_remaining')}
Status: {expiry_status}
"""
    
    def format_dns_result(self, result: Dict[str, Any]) -> str:
        if 'error' in result:
            return f"DNS Lookup Failed\nError: {result['error']}"
        
        response = f"""
DNS Records for {result['domain']}

A Records:
{chr(10).join(result['a_records'])}

MX Records:
{chr(10).join(result['mx_records'])}

NS Records:
{chr(10).join(result['ns_records'])}

TXT Records:
{chr(10).join(result['txt_records'])}
"""
        return response
    
    def format_ip_result(self, result: Dict[str, Any]) -> str:
        if 'error' in result:
            return f"IP Lookup Failed\nError: {result['error']}"
        
        return f"""
IP Address Information
Domain: {result['domain']}
Hostname: {result['hostname']}
IP Addresses:
{chr(10).join(result['ips'])}
Aliases: {', '.join(result['aliases']) if result['aliases'] else 'None'}
"""
    
    def format_domain_info_result(self, result: Dict[str, Any]) -> str:
        if 'error' in result:
            return f"Domain Info Lookup Failed\nError: {result['error']}"
        
        return f"""
Domain WHOIS Information
Domain: {result['domain']}
Registrar: {result['registrar']}
Creation Date: {result['creation_date']}
Expiration Date: {result['expiration_date']}
Name Servers:
{chr(10).join(result['name_servers'])}
Status:
{chr(10).join(result['status'])}
"""
    
    def format_redirect_result(self, result: Dict[str, Any], url: str) -> str:
        if 'error' in result:
            return f"Redirect Check Failed\nError: {result['error']}"
        
        response = f"""
Redirect Analysis
Initial URL: {url}
Total Redirects: {result['total_redirects']}
Redirect Chain:
"""
        for i, redirect in enumerate(result['redirect_chain']):
            response += f"{i+1}. {redirect['url']}\n   Status: {redirect['status_code']}\n"
            if redirect['redirect_to'] != 'Final destination':
                response += f"   Redirects to: {redirect['redirect_to']}\n"
            else:
                response += f"   Final destination\n"
        
        return response
    
    def format_headers_result(self, result: Dict[str, Any], url: str) -> str:
        if 'error' in result:
            return f"HTTP Headers Check Failed\nError: {result['error']}"
        
        response = f"""
HTTP Headers Analysis
URL: {url}
Status Code: {result['status_code']}
Server: {result.get('server', 'N/A')}
Headers:
"""
        important_headers = ['content-type', 'content-length', 'cache-control', 'expires', 'last-modified']
        other_headers = []
        
        for key, value in sorted(result['headers'].items()):
            if key.lower() in important_headers:
                response += f"{key}: {value}\n"
            else:
                other_headers.append(f"{key}: {value}")
        
        if other_headers:
            response += "\nOther Headers:\n" + '\n'.join(other_headers[:10])
            if len(other_headers) > 10:
                response += f"\n... and {len(other_headers) - 10} more"
        
        return response
    
    def format_metadata_result(self, result: Dict[str, Any], url: str) -> str:
        if 'error' in result:
            return f"Metadata Extraction Failed\nError: {result['error']}"
        
        return f"""
Page Metadata Analysis
URL: {url}
Title: {result.get('title', 'N/A')}
Description: {result.get('description', 'N/A')}
Keywords: {result.get('keywords', 'N/A')}
Open Graph Title: {result.get('og_title', 'N/A')}
Open Graph Description: {result.get('og_description', 'N/A')}
Open Graph Image: {result.get('og_image', 'N/A')}
"""
    
    def format_mobile_result(self, result: Dict[str, Any], url: str) -> str:
        if 'error' in result:
            return f"Mobile-Friendly Check Failed\nError: {result['error']}"
        
        status = "Good" if result['mobile_friendly'] else "Needs improvement"
        return f"""
Mobile-Friendly Analysis
URL: {url}
Status: {status}
Viewport Meta: {'Yes' if result['has_viewport'] else 'No'}
Media Queries: {'Yes' if result['has_media_queries'] else 'No'}
Mobile Tags: {'Yes' if result['has_mobile_tag'] else 'No'}
CSS Found: {'Yes' if result['has_css'] else 'No'}
Images without max-width: {result['images_without_responsive']} / {result['total_images']}
"""
    
    def format_robots_result(self, result: Dict[str, Any], url: str) -> str:
        if 'error' in result:
            return f"Robots.txt Check Failed\nError: {result['error']}"
        
        if result.get('exists'):
            return f"""
Robots.txt Analysis
URL: {url}
Status: File exists
Status Code: {result['status_code']}
Content:
{result.get('content', 'N/A')}
"""
        else:
            return f"""
Robots.txt Analysis
URL: {url}
Status: File not found
Status Code: {result.get('status_code', 'N/A')}
"""
    
    def format_sitemap_result(self, result: Dict[str, Any], url: str) -> str:
        if 'error' in result:
            return f"Sitemap Check Failed\nError: {result['error']}"
        
        if result.get('exists'):
            response = f"""
Sitemap Analysis
URL: {url}
Status: Sitemap exists
Type: {result.get('type', 'Unknown')}
"""
            if result.get('type') == 'sitemap':
                response += f"URLs Found: {result.get('url_count', 0)}\n"
                if result.get('first_urls'):
                    response += "First URLs:\n" + '\n'.join(result['first_urls'])
            else:
                response += f"Sitemaps Found: {result.get('sitemap_count', 0)}\n"
            
            response += f"\nContent Preview:\n{result.get('content', 'N/A')}"
            return response
        else:
            return f"""
Sitemap Analysis
URL: {url}
Status: Sitemap not found
Status Code: {result.get('status_code', 'N/A')}
"""
    
    def format_full_analysis(self, results: Dict[str, Any], url: str) -> str:
        """Format complete website analysis"""
        response = f"""
Complete Website Analysis
URL: {url}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=========================================
"""
        
        if 'status' in results:
            status = results['status']
            response += "\nWebsite Status: "
            if status.get('status') == 'online':
                response += f"Online (Status: {status.get('status_code')})"
            else:
                response += f"Offline - {status.get('error', 'Unknown error')}"
        
        if 'response_time' in results and 'error' not in results['response_time']:
            response += f"\nResponse Time: {results['response_time']['response_time']} ms"
        
        if 'ssl' in results and 'error' not in results['ssl']:
            ssl = results['ssl']
            response += f"\nSSL Status: {'Valid' if ssl.get('days_remaining', 0) > 30 else 'Expiring Soon' if ssl.get('days_remaining', 0) > 7 else 'Expired'}"
            response += f"\nSSL Expiry: {ssl.get('days_remaining', 'N/A')} days"
        
        if 'metadata' in results and 'error' not in results['metadata']:
            metadata = results['metadata']
            response += f"\n\nPage Title: {metadata.get('title', 'N/A')}"
            response += f"\nDescription: {metadata.get('description', 'N/A')[:100]}..."
        
        if 'mobile' in results and 'error' not in results['mobile']:
            mobile = results['mobile']
            response += f"\n\nMobile Friendly: {'Yes' if mobile.get('mobile_friendly') else 'No'}"
            response += f"\nMobile Score: {mobile.get('score', 'N/A')}"
        
        return response

def main():
    """Start the bot"""
    # Create application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Initialize handlers
    handlers = BotHandlers()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", handlers.start_command))
    application.add_handler(CommandHandler("help", handlers.help_command))
    application.add_handler(CommandHandler("check_status", lambda u, c: u.message.reply_text("Please send the URL to check:") or c.user_data.update({'awaiting_url': 'check_status'})))
    application.add_handler(CommandHandler("response_time", lambda u, c: u.message.reply_text("Please send the URL to check response time:") or c.user_data.update({'awaiting_url': 'response_time'})))
    application.add_handler(CommandHandler("ssl_check", lambda u, c: u.message.reply_text("Please send the URL to check SSL certificate:") or c.user_data.update({'awaiting_url': 'ssl_check'})))
    application.add_handler(CommandHandler("dns_lookup", lambda u, c: u.message.reply_text("Please send the domain for DNS lookup:") or c.user_data.update({'awaiting_url': 'dns_lookup'})))
    application.add_handler(CommandHandler("ip_lookup", lambda u, c: u.message.reply_text("Please send the domain for IP lookup:") or c.user_data.update({'awaiting_url': 'ip_lookup'})))
    application.add_handler(CommandHandler("domain_info", lambda u, c: u.message.reply_text("Please send the domain for WHOIS information:") or c.user_data.update({'awaiting_url': 'domain_info'})))
    application.add_handler(CommandHandler("redirect_check", lambda u, c: u.message.reply_text("Please send the URL to check redirects:") or c.user_data.update({'awaiting_url': 'redirect_check'})))
    application.add_handler(CommandHandler("headers", lambda u, c: u.message.reply_text("Please send the URL to check HTTP headers:") or c.user_data.update({'awaiting_url': 'headers'})))
    application.add_handler(CommandHandler("metadata", lambda u, c: u.message.reply_text("Please send the URL to extract metadata:") or c.user_data.update({'awaiting_url': 'metadata'})))
    application.add_handler(CommandHandler("mobile_friendly", lambda u, c: u.message.reply_text("Please send the URL to check mobile-friendliness:") or c.user_data.update({'awaiting_url': 'mobile_friendly'})))
    application.add_handler(CommandHandler("robots", lambda u, c: u.message.reply_text("Please send the URL to check robots.txt:") or c.user_data.update({'awaiting_url': 'robots'})))
    application.add_handler(CommandHandler("sitemap", lambda u, c: u.message.reply_text("Please send the URL to check sitemap:") or c.user_data.update({'awaiting_url': 'sitemap'})))
    
    # Add callback and message handlers
    application.add_handler(CallbackQueryHandler(handlers.handle_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.handle_url_input))
    
    # Start the bot
    logger.info("Starting bot...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
