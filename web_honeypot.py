#Libraries
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for


#Logging Format
logging_format = logging.Formatter('%(asctime)s %(message)s')

#HTTP Logger
funnel_logger = logging.getLogger('HTTP logger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('http_audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

#Baseline honeypot
def web_honeypot(input_username='admin', input_password='password'):
    app = Flask(__name__)

    @app.route('/')
    
    def index():
        return render_template('wp-admin.html')
    
    @app.route('/wp-admin-login', methods=['POST'])
    
    def login():
        username= request.form['username']
        password= request.form['password']
        ip_address = request.remote_addr

        funnel_logger.info(f"Client with IP: {ip_address} entered\n Username: '{username}' and Password: '{password}'")

        if username == input_username and password == input_password:
            return redirect(url_for('success'))
        else:
            funnel_logger.warning(f"Failed login attempt from IP: {ip_address} with Username: '{username}' and Password: '{password}'")
            return "Failed Login!"

    @app.route('/success')
    def success():
        return "Successful Login!"
    
    # return the Flask app instance so callers can run or test it
    return app
        
def run_web_honeypot(port=5000, input_username='admin', input_password='password'):
    run_web_honeypot_app = web_honeypot(input_username, input_password)
    run_web_honeypot_app.run(debug=True, port=port, host='0.0.0.0')

    return run_web_honeypot_app


if __name__ == '__main__':
    # When executed directly, start the web honeypot on port 5000
    run_web_honeypot(port=5000)

