def get_base_html(title: str, content: str, action_url: str = None, action_text: str = None) -> str:
    action_html = ""
    if action_url and action_text:
        action_html = f'''
        <div style="text-align: center; margin: 30px 0;">
            <a href="{action_url}" style="background-color: #06b6d4; color: #0f172a; font-weight: 700; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">{action_text}</a>
        </div>
        '''
        
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 0; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ padding: 20px 0; border-bottom: 1px solid #1e293b; text-align: center; }}
            .logo {{ font-size: 24px; font-weight: 800; color: #06b6d4; letter-spacing: -1px; text-decoration: none; }}
            .content {{ padding: 40px 20px; background-color: #1e293b; border-radius: 12px; margin-top: 20px; }}
            h1 {{ font-size: 20px; margin-top: 0; }}
            p {{ line-height: 1.6; color: #cbd5e1; font-size: 15px; }}
            .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #64748b; }}
            .footer a {{ color: #06b6d4; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <a href="#" class="logo">PENTRIXA</a>
            </div>
            <div class="content">
                <h1>{title}</h1>
                {content}
                {action_html}
            </div>
            <div class="footer">
                <p>You're receiving this because you registered at Pentrixa.app.</p>
                <p><a href="#">Privacy Policy</a> &middot; <a href="#">Terms of Service</a></p>
            </div>
        </div>
    </body>
    </html>
    '''
