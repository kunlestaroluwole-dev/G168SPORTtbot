# Website Tools Telegram Bot

A comprehensive Telegram bot for website analysis with 12 different tools.

## Features

- Website Status Checker
- Website Response-Time Checker
- SSL Certificate Checker
- DNS Lookup
- IP Address Lookup
- Domain Information
- Redirect Checker
- HTTP Headers Checker
- Website Title & Metadata Checker
- Mobile-Friendly Checker
- Robots.txt Checker
- Sitemap Checker

## Deployment on Railway

1. Fork this repository on GitHub
2. Create a new project on Railway
3. Connect your GitHub repository
4. Add environment variable: `BOT_TOKEN`
5. Deploy!

## Local Development

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Create `.env` file with your BOT_TOKEN
4. Run: `python bot.py`

## Commands

- `/start` - Start the bot
- `/help` - Show all commands
- `/check_status` - Check website status
- `/response_time` - Check response time
- `/ssl_check` - Check SSL certificate
- `/dns_lookup` - DNS lookup
- `/ip_lookup` - IP address lookup
- `/domain_info` - Domain WHOIS info
- `/redirect_check` - Check redirects
- `/headers` - Check HTTP headers
- `/metadata` - Extract page metadata
- `/mobile_friendly` - Check mobile-friendliness
- `/robots` - Check robots.txt
- `/sitemap` - Check sitemap.xml

## License

MIT
