import os
import json
import uuid # For generating unique IDs for applications
from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime

app = Flask(__name__)
# IMPORTANT: For production, set SECRET_KEY in Replit Secrets!
# Example: Key: SECRET_KEY, Value: <a_very_long_random_string>
app.secret_key = os.environ.get('SECRET_KEY', 'a_super_secret_key_that_should_be_strong_in_production_do_not_use_this_default')

# --- Configuration ---
# IMPORTANT: For production, set ADMIN_USERNAME and ADMIN_PASSWORD in Replit Secrets!
# Example: Key: ADMIN_USERNAME, Value: your_admin_user
# Example: Key: ADMIN_PASSWORD, Value: your_strong_admin_password
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin') # Default for testing, CHANGE IN PRODUCTION
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'ucds_secret') # Default for testing, CHANGE IN PRODUCTION!

FLAGGED_IPS_FILE = 'flagged_ips.txt'
VISITOR_IPS_FILE = 'visitor_ips.txt'
CITIZENSHIP_APPLICATIONS_FILE = 'citizenship_applications.jsonl' # New file for applications

# Function to load flagged IPs
def load_flagged_ips():
    """Loads flagged IP addresses from the flagged_ips.txt file."""
    if not os.path.exists(FLAGGED_IPS_FILE):
        return set()
    try:
        with open(FLAGGED_IPS_FILE, 'r') as f:
            return {line.strip() for line in f if line.strip()}
    except IOError as e:
        print(f"Error loading flagged IPs file: {e}")
        return set()

# Function to save flagged IPs
def save_flagged_ips(flagged_ips_set):
    """Saves flagged IP addresses to the flagged_ips.txt file."""
    try:
        with open(FLAGGED_IPS_FILE, 'w') as f:
            for ip in sorted(list(flagged_ips_set)): # Sort for consistent file order
                f.write(ip + '\n')
    except IOError as e:
        print(f"Error saving flagged IPs file: {e}")

# Function to log visitor IPs
def log_visitor_ip():
    """Logs the visitor's IP address and timestamp to visitor_ips.txt."""
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp},{ip_address}\n"
    try:
        with open(VISITOR_IPS_FILE, 'a') as f:
            f.write(log_entry)
    except IOError as e:
        print(f"Error logging visitor IP to file: {e}")

# --- New Functions for Citizenship Applications ---
def load_applications():
    """Loads citizenship applications from the JSONL file."""
    applications = []
    if not os.path.exists(CITIZENSHIP_APPLICATIONS_FILE):
        return applications
    try:
        with open(CITIZENSHIP_APPLICATIONS_FILE, 'r') as f:
            for line in f:
                if line.strip(): # Avoid empty lines
                    applications.append(json.loads(line.strip()))
    except IOError as e:
        print(f"Error loading applications file: {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from applications file: {e}")
    return applications

def save_applications(applications):
    """Saves citizenship applications to the JSONL file."""
    try:
        with open(CITIZENSHIP_APPLICATIONS_FILE, 'w') as f:
            for app_data in applications:
                f.write(json.dumps(app_data) + '\n')
    except IOError as e:
        print(f"Error saving applications file: {e}")

# --- Routes ---

@app.route('/')
def index():
    """Renders the main welcome page."""
    log_visitor_ip()
    return render_template('index.html') # Flash messages will appear here

@app.route('/history')
def history():
    """Renders the UCDS history page."""
    log_visitor_ip()
    return render_template('history.html')

@app.route('/about')
def about():
    """Renders the About UCDS page (principles and mission)."""
    log_visitor_ip()
    return render_template('about.html')

@app.route('/government')
def government():
    """Renders the UCDS Government page."""
    log_visitor_ip()
    return render_template('government.html')

@app.route('/citizenship', methods=['GET', 'POST'])
def citizenship():
    """Renders the UCDS Citizenship page and handles application submission."""
    log_visitor_ip()
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        discord_username = request.form.get('discord_username') # NEW: Added Discord username
        applicant_ip = request.headers.get('X-Forwarded-For', request.remote_addr) # NEW: Added applicant IP
        reason = request.form.get('reason')
        agree_terms = request.form.get('agree_terms')

        if not all([full_name, email, reason, agree_terms]):
            flash("Please fill out all required fields and agree to the terms.", 'error') # Flash error message
            return redirect(url_for('citizenship')) # Redirect back to citizenship page if error

        applications = load_applications()
        new_application = {
            'id': str(uuid.uuid4()), # Generate a unique ID
            'full_name': full_name,
            'email': email,
            'discord_username': discord_username, # NEW: Save Discord username
            'applicant_ip': applicant_ip, # NEW: Save applicant IP
            'reason': reason,
            'status': 'pending', # Initial status
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        applications.append(new_application)
        save_applications(applications)
        flash("Your application has been submitted successfully! We will review it shortly.", 'success') # Flash success message
        return redirect(url_for('index')) # Redirect to home page
    return render_template('citizenship.html')


@app.route('/symbols')
def symbols():
    """Renders the UCDS National Symbols page."""
    log_visitor_ip()
    return render_template('symbols.html')

@app.route('/contact')
def contact():
    """Renders the Contact Us page."""
    log_visitor_ip()
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    """Renders the Privacy Policy page."""
    log_visitor_ip()
    return render_template('privacy.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles admin login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid Credentials', 'error') # Use flash for login message
            return render_template('login.html') # Keep render_template here to show message on same page
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logs the admin user out."""
    session.pop('logged_in', None)
    flash("You have been logged out.", 'info') # Optional: Add logout message
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST']) # Added POST method for IP actions
def admin_panel():
    """Displays the admin panel with visitor IP logs and citizenship applications. Requires login."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    log_visitor_ip()

    # --- IP Flagging/Whitelisting Logic (Handles POST requests for IP actions) ---
    if request.method == 'POST':
        action = request.form.get('action')
        ip_address_to_process = request.form.get('ip_address')
        flagged_ips = load_flagged_ips()

        if action == 'flag' and ip_address_to_process:
            if ip_address_to_process not in flagged_ips:
                flagged_ips.add(ip_address_to_process)
                save_flagged_ips(flagged_ips)
                flash(f"IP {ip_address_to_process} flagged successfully.", 'success')
            else:
                flash(f"IP {ip_address_to_process} is already flagged.", 'info')
        elif action == 'whitelist' and ip_address_to_process:
            if ip_address_to_process in flagged_ips:
                flagged_ips.remove(ip_address_to_process)
                save_flagged_ips(flagged_ips)
                flash(f"IP {ip_address_to_process} whitelisted successfully.", 'success')
            else:
                flash(f"IP {ip_address_to_process} is not currently flagged.", 'info')
        else:
            flash("Invalid IP action.", 'error')

        # Redirect to prevent re-submission on refresh after POST action
        return redirect(url_for('admin_panel')) 

    # --- Display Logic for GET request (and after POST redirect) ---
    flagged_ips = load_flagged_ips()
    all_visitor_ips = []
    if os.path.exists(VISITOR_IPS_FILE):
        try:
            with open(VISITOR_IPS_FILE, 'r') as f:
                # Read lines in reverse to show newest first
                for line in reversed(f.readlines()): 
                    parts = line.strip().split(',', 1)
                    if len(parts) == 2:
                        timestamp, ip_address = parts[0], parts[1]
                        is_flagged = ip_address in flagged_ips
                        all_visitor_ips.append({'timestamp': timestamp, 'ip': ip_address, 'flagged': is_flagged})
                    else:
                        pass # Skip malformed lines
        except IOError as e:
            print(f"Error reading visitor IPs file: {e}")
            all_visitor_ips = []

    # Load citizenship applications for the admin panel
    applications = load_applications()
    # Sort applications by timestamp in descending order (newest first)
    applications.sort(key=lambda x: datetime.strptime(x['timestamp'], "%Y-%m-%d %H:%M:%S"), reverse=True)

    pending_applications = [app for app in applications if app['status'] == 'pending']
    approved_applications = [app for app in applications if app['status'] == 'approved']
    denied_applications = [app for app in applications if app['status'] == 'denied']


    return render_template('admin_panel.html',
                           visitor_ips=all_visitor_ips,
                           pending_applications=pending_applications,
                           approved_applications=approved_applications,
                           denied_applications=denied_applications)


# --- Route for Processing Applications (Approve/Deny) ---
@app.route('/process_application/<app_id>/<action>', methods=['POST'])
def process_application(app_id, action):
    if not session.get('logged_in'):
        flash("You need to be logged in to perform this action.", 'error')
        return redirect(url_for('login'))

    applications = load_applications()
    found = False
    for app_data in applications:
        if app_data['id'] == app_id:
            if action == 'approve':
                app_data['status'] = 'approved'
            elif action == 'deny':
                app_data['status'] = 'denied'
            found = True
            break

    if found:
        save_applications(applications)
        flash(f"Application {app_id} {action}d successfully.", 'success')
    else:
        flash(f"Application {app_id} not found.", 'error')

    return redirect(url_for('admin_panel'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)