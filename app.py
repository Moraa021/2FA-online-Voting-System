from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import random
import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, ValidationError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['OTP_EXPIRATION'] = 300  # 5 minutes in seconds

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    has_voted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

class Election(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False)  # 'upcoming', 'ongoing', 'completed'
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
@property
def progress(self):
    total_duration = (self.end_date - self.start_date).total_seconds()
    elapsed = (datetime.utcnow() - self.start_date).total_seconds()
    return min(100, max(0, (elapsed / total_duration) * 100))

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text)
    votes_count = db.Column(db.Integer, default=0)  # Renamed from 'votes' to avoid conflict
    image = db.Column(db.String(200))
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    
    election = db.relationship('Election', backref='candidates')
    # Changed backref name to avoid conflict
    vote_records = db.relationship('Vote', back_populates='candidate')

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='votes')
    candidate = db.relationship('Candidate', back_populates='vote_records')
    election = db.relationship('Election', backref='votes')

class PasswordValidator:
    def __init__(self):
        self.message = "Password must:"
        self.requirements = [
            ("be at least 6 characters long", lambda p: len(p) >= 6),
            ("contain at least 3 of: uppercase, lowercase, number, special character", 
             lambda p: sum([
                 bool(re.search(r'[A-Z]', p)),
                 bool(re.search(r'[a-z]', p)),
                 bool(re.search(r'[0-9]', p)),
                 bool(re.search(r'[^A-Za-z0-9]', p))
             ]) >= 3),
            ("not contain your username", 
             lambda p, u: u.lower() not in p.lower() if u else True),
            ("not contain your email prefix", 
             lambda p, e: e.split('@')[0].lower() not in p.lower() if e else True),
            ("not be a common password", 
             lambda p: p.lower() not in ['password', '123456', 'qwerty', 'letmein'])
        ]

    def __call__(self, form, field):
        password = field.data
        username = form.username.data if hasattr(form, 'username') else ""
        email = form.email.data if hasattr(form, 'email') else ""
        
        errors = []
        for message, check in self.requirements:
            if not check(password, username) if message.startswith('not contain') else not check(password):
                errors.append(message)
        
        if errors:
            error_message = "Password requirements not met:<br>" + "<br>• ".join([""] + errors)
            raise ValidationError(error_message)
        
class PhoneNumberValidator:
    def __init__(self):
        self.message = "Phone number must contain only numbers (digits 0-9)"

    def __call__(self, form, field):
        phone = field.data
        if not phone.isdigit():
            # Check what kind of invalid characters were entered
            invalid_chars = set(c for c in phone if not c.isdigit())
            if invalid_chars:
                self.message = f"Invalid characters in phone number: {', '.join(invalid_chars)}. Only numbers are allowed."
            raise ValidationError(self.message)
        
class EmailFormatValidator:
    def __init__(self):
        self.message = "Please enter a valid email address in lowercase (e.g., user@example.com)"

    def __call__(self, form, field):
        email = field.data
        # First check if email is lowercase
        if email != email.lower():
            self.message = "Email must be in lowercase letters only"
            raise ValidationError(self.message)
        
        # Then check the email format
        if not re.match(r'^[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$', email):
            if ' ' in email:
                self.message = "Email addresses cannot contain spaces"
            elif '@' not in email:
                self.message = "Missing @ symbol in email address"
            elif '.' not in email.split('@')[-1]:
                self.message = "Missing domain extension (e.g., .com, .org)"
            elif not email.split('@')[0]:
                self.message = "Missing username before @ symbol"
            raise ValidationError(self.message)


# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=2, max=50)
    ])
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        EmailFormatValidator(),  # Our enhanced validator
        Email(message="This doesn't look like a valid email")
    ])
    phone = StringField('Phone Number', validators=[
        DataRequired(),
        Length(min=10, max=15, message="Phone number must be 10-15 digits long"),
        PhoneNumberValidator()
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6),  # Changed from min=8 to min=6 to match requirements
        PasswordValidator()
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password')
    ])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        EmailFormatValidator(),
        Email(message="This doesn't look like a valid email")])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[
        DataRequired(),
        Length(min=6, max=6)
    ])
    submit = SubmitField('Verify')

class SettingsForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=2, max=50)
    ])
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        EmailFormatValidator(),
        Email(message="This doesn't look like a valid email")
    ])
    phone = StringField('Phone Number', validators=[
        DataRequired(),
        Length(min=10, max=15, message="Phone number must be 10-15 digits long"),
        PhoneNumberValidator() 
    ])
    current_password = PasswordField('Current Password', validators=[
        DataRequired()
    ])
    password = PasswordField('New Password', validators=[
        Optional(),
        Length(min=6),  # Changed from min=8 to min=6
        PasswordValidator()
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        EqualTo('password')
    ])
    submit = SubmitField('Update Settings')

# Helper Functions
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_via_sms(phone_number, otp_code):
    print(f"\n=== SIMULATED SMS ===\nTo: {phone_number}\nOTP: {otp_code}\n(Expires in 5 minutes)\n")
    return True

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize Database
def initialize_database():
    with app.app_context():
        try:
            # 1. Completely reset the database
            db.drop_all()
            db.create_all()
            
            # 2. Create admin user
            admin = User(
                username='admin',
                email='admin@voting.com',
                password=generate_password_hash('admin123'),
                phone='+254700000000',
                is_admin=True,
                created_at=datetime.utcnow()
            )
            db.session.add(admin)
            
            # 3. Create sample election with all required fields
            election = Election(
                name='Kenya Presidential Election 2025',
                description='Official presidential election for Kenya',
                status='ongoing',
                start_date=datetime.utcnow(),
                end_date=datetime.utcnow() + timedelta(days=30)
            )
            db.session.add(election)
            
            # 4. Create candidates with proper image paths
            candidates = [
                Candidate(
                    name='Raila Odinga',
                    party='Nasa',
                    bio='Experienced politician and former Prime Minister',
                    election_id=1,
                    votes_count=0,
                    image='candidates/raila.png'
                ),
                Candidate(
                    name='William Rutto',
                    party='UDA',
                    bio='Current Deputy President of Kenya',
                    election_id=1,
                    votes_count=0,
                    image='candidates/ruto.png'
                ),
                Candidate(
                    name='George Wajakoya',
                    party='Roots',
                    bio='Businessman and philanthropist',
                    election_id=1,
                    votes_count=0,
                    image='candidates/wajakoya.png'
                ),
                Candidate(
                    name='David Mwaure',
                    party='Agano',
                    bio='Lawyer and civil rights activist',
                    election_id=1,
                    votes_count=0,
                    image='candidates/mwaure.png'
                )
            ]
            db.session.bulk_save_objects(candidates)
            
            db.session.commit()
            print("Database initialized successfully with Kenyan candidates!")

            
            
        except Exception as e:
            db.session.rollback()
            print(f"Error initializing database: {e}")


# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/elections')
@login_required
def elections():
    # Get current election (you might want to modify this logic)
    current_election = Election.query.filter_by(status='ongoing').first()
    
    if not current_election:
        flash('No ongoing elections at this time', 'info')
        return redirect(url_for('dashboard'))
    
    candidates = Candidate.query.filter_by(election_id=current_election.id).all()
    
    # Check if user has already voted
    voted_candidate = None
    vote = Vote.query.filter_by(
        user_id=current_user.id,
        election_id=current_election.id
    ).first()
    
    if vote:
        voted_candidate = Candidate.query.get(vote.candidate_id).name
    
    return render_template('elections.html',
                         election=current_election,
                         candidates=candidates,
                         voted_candidate=voted_candidate)

@app.route('/vote', methods=['POST'])
@login_required
def handle_vote():
    data = request.get_json()
    candidate_name = data.get('candidate')
    
    if not candidate_name:
        return jsonify({'success': False, 'message': 'No candidate specified'}), 400
    
    # Get current election
    current_election = Election.query.filter_by(status='ongoing').first()
    if not current_election:
        return jsonify({'success': False, 'message': 'No active election'}), 400
    
    # Check if user has already voted
    if Vote.query.filter_by(user_id=current_user.id, election_id=current_election.id).first():
        return jsonify({'success': False, 'message': 'You have already voted'}), 400
    
    # Find the candidate
    candidate = Candidate.query.filter_by(
        name=candidate_name,
        election_id=current_election.id
    ).first()
    
    if not candidate:
        return jsonify({'success': False, 'message': 'Candidate not found'}), 404
    
    try:
        # Record the vote
        candidate.votes_count += 1
        current_user.has_voted = True
        
        vote = Vote(
            user_id=current_user.id,
            candidate_id=candidate.id,
            election_id=current_election.id
        )
        db.session.add(vote)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Vote recorded successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error recording vote'}), 500
    
class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        EmailFormatValidator(),
        Email(message="This doesn't look like a valid email")
    ])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=6),  # Changed from no length requirement
        PasswordValidator()
    ])
    submit = SubmitField('Reset Password')

    def has_voted_in(self, election_id):
        return Vote.query.filter_by(
        user_id=self.id,
        election_id=election_id
    ).first() is not None

@property
def last_login(self):
    # Implement last login tracking in your login route
    pass

@app.template_filter('time_remaining')
def time_remaining(delta):
    days = delta.days
    hours, remainder = divmod(delta.seconds, 3600)
    minutes = remainder // 60
    return f"{days}d {hours}h {minutes}m"

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Generate and send reset token (simplified for example)
            token = generate_otp()  # In production, use proper token generation
            session['reset_token'] = token
            session['reset_user_id'] = user.id
            session['reset_token_expires'] = (datetime.utcnow() + timedelta(hours=1)).timestamp()
            
            # Simulate sending email (replace with actual email service)
            print(f"Password reset token for {user.email}: {token}")
            flash('Check your email for instructions to reset your password', 'info')
            return redirect(url_for('login'))
        
        flash('If this email exists, you will receive a password reset link', 'info')
        return redirect(url_for('login'))
    
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if session.get('reset_token') != token:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('reset_password_request'))
    
    if datetime.utcnow().timestamp() > session.get('reset_token_expires', 0):
        flash('Token has expired', 'danger')
        return redirect(url_for('reset_password_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            user = User.query.get(session['reset_user_id'])
            if user:
                user.password = generate_password_hash(form.password.data)
                db.session.commit()
                session.pop('reset_token', None)
                session.pop('reset_user_id', None)
                session.pop('reset_token_expires', None)
                flash('Your password has been reset. Please login.', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while resetting your password', 'danger')
    
    return render_template('reset_password.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.password.data)
            user = User(
                username=form.username.data,
                email=form.email.data,
                phone=form.phone.data,
                password=hashed_password
            )
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():  # Fixed: validate_on_submit instead of validate_on_submit
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and check_password_hash(user.password, form.password.data):
            otp_code = generate_otp()
            expires_at = datetime.utcnow() + timedelta(seconds=app.config['OTP_EXPIRATION'])
            
            # Clear existing OTPs
            OTP.query.filter_by(user_id=user.id).delete()
            
            # Create new OTP
            otp = OTP(
                user_id=user.id,
                otp_code=otp_code,
                expires_at=expires_at
            )
            db.session.add(otp)
            db.session.commit()
            
            if send_otp_via_sms(user.phone, otp_code):
                session['temp_user_id'] = user.id
                flash('OTP sent to your registered phone number', 'info')
                return redirect(url_for('otp_verify'))  # Ensure proper redirect
            else:
                flash('Failed to send OTP', 'danger')
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/privacy')
def privacy():
    return render_template('privacy.html', 
                         title='Privacy Policy',
                         active_page='privacy')

# Terms of Service Route
@app.route('/terms')
def terms():
    return render_template('terms.html', 
                         title='Terms of Service',
                         active_page='terms')

@app.route('/otp_verify', methods=['GET', 'POST'])
def otp_verify():
    # Check if user has a valid temp session
    if 'temp_user_id' not in session:
        flash('Session expired. Please login again.', 'danger')
        return redirect(url_for('login'))
    
    # Fetch user from database
    user = User.query.get(session['temp_user_id'])
    if not user:
        flash('User not found', 'danger')
        session.pop('temp_user_id', None)  # Clean up invalid session
        return redirect(url_for('login'))
    
    form = OTPForm()
    
    if form.validate_on_submit():
        # Verify OTP exists and isn't expired
        otp = OTP.query.filter_by(
            user_id=user.id,
            otp_code=form.otp.data
        ).first()
        
        if otp and not otp.is_expired():
            # Successful verification
            session.pop('temp_user_id', None)  # Clear temp session
            login_user(user)  # Log in the user
            
            # Clean up used OTP
            db.session.delete(otp)
            db.session.commit()
            
            flash('Login successful!', 'success')
            
            # Redirect based on user role
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired OTP. Please try again.', 'danger')
    
    return render_template('otp_verify.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    current_election = Election.query.filter_by(status='ongoing').first()
    candidates = Candidate.query.filter_by(election_id=current_election.id).all() if current_election else []
    
    return render_template('dashboard.html', 
                         user=current_user,
                         current_election=current_election,
                         candidates=candidates)

@app.route('/vote/<int:candidate_id>', methods=['POST'])
@login_required
def vote(candidate_id):
    if current_user.has_voted:
        flash('You have already voted in this election', 'warning')
        return redirect(url_for('dashboard'))
    
    candidate = Candidate.query.get(candidate_id)
    if not candidate:
        flash('Candidate not found', 'danger')
        return redirect(url_for('dashboard'))
    
    current_election = Election.query.filter_by(status='ongoing').first()
    if not current_election:
        flash('No active election found', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Record the vote
        candidate.votes_count += 1  # Changed from votes to votes_count
        current_user.has_voted = True
        
        # Create vote record
        vote = Vote(
            user_id=current_user.id,
            candidate_id=candidate.id,
            election_id=current_election.id
        )
        db.session.add(vote)
        db.session.commit()
        
        flash('Your vote has been recorded successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while recording your vote', 'danger')
    
    return redirect(url_for('dashboard'))



@app.route('/profile')
@login_required
def profile():
    # Get user's voting history with election details
    voting_history = db.session.query(Vote, Election, Candidate)\
        .join(Election, Vote.election_id == Election.id)\
        .join(Candidate, Vote.candidate_id == Candidate.id)\
        .filter(Vote.user_id == current_user.id)\
        .order_by(Vote.timestamp.desc())\
        .all()

    # Count elections participated in
    elections_participated = len({vote.Election.id for vote in voting_history})

    return render_template('profile.html',
                         user=current_user,
                         voting_history=voting_history,
                         votes_count=len(voting_history),
                         elections_count=elections_participated)
@app.route('/results')
@login_required
def results():
    completed_elections = Election.query.filter_by(status='completed')\
                                      .order_by(Election.end_date.desc())\
                                      .all()
    
    election_results = []
    for election in completed_elections:
        candidates = Candidate.query.filter_by(election_id=election.id)\
                                 .order_by(Candidate.votes_count.desc())\
                                 .all()
        
        total_votes = sum(candidate.votes_count for candidate in candidates) or 1  # Changed from votes to votes_count
        
        election_results.append({
            'election': election,
            'candidates': candidates,
            'total_votes': total_votes,
            'user_voted': Vote.query.filter_by(
                user_id=current_user.id,
                election_id=election.id
            ).first() is not None
        })
    
    return render_template('results.html', 
                         election_results=election_results)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm(obj=current_user)
    
    if form.validate_on_submit():
        try:
            # Verify current password if changing password
            if form.new_password.data:
                if not check_password_hash(current_user.password, form.current_password.data):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('settings'))
                
                current_user.password = generate_password_hash(form.new_password.data)
            
            # Update user details
            current_user.username = form.username.data
            current_user.email = form.email.data
            current_user.phone = form.phone.data
            
            db.session.commit()
            flash('Your settings have been updated successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating your settings', 'danger')
    
    return render_template('settings.html', form=form)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    if not check_password_hash(current_user.password, request.form.get('password', '')):
        flash('Incorrect password', 'danger')
        return redirect(url_for('settings'))
    
    try:
        # Delete all user-related data
        Vote.query.filter_by(user_id=current_user.id).delete()
        OTP.query.filter_by(user_id=current_user.id).delete()
        
        # Delete the user
        db.session.delete(current_user)
        db.session.commit()
        
        logout_user()
        flash('Your account has been permanently deleted', 'info')
        return redirect(url_for('home'))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting your account', 'danger')
        return redirect(url_for('settings'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    elections = Election.query.all()
    candidates = Candidate.query.order_by(Candidate.votes_count.desc()).all()  # Changed from votes to votes_count
    
    return render_template('admin.html',
                         users=users,
                         elections=elections,
                         candidates=candidates)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('home'))

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)