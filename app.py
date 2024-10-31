from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SECRET_KEY'] = 'My_Secr3t1$Th15'
app.config['SESSION_COOKIE_SECURE'] = False  # Secure session cookie
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JS access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevent CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # Session lifetime

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# Models
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    roll = db.Column(db.String(20), unique=True, nullable=False)
    marks = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(100), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create the database and tables
with app.app_context():
    db.create_all()

# WTForms
class SignupForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords must match")])
    submit = SubmitField('Signup')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered!')

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class MarksEntryForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    roll = StringField('Roll No', validators=[DataRequired()])
    marks = StringField('Marks', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')

# Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        # hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and  bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('mainpage'))
        else:
            flash('Invalid credentials, please try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/marks')
def marks():
    if 'user_id' not in session:
        flash('Please log in to view marks.', 'danger')
        return redirect(url_for('login'))
    
    students = Student.query.all()
    return render_template('marks.html', students=students)

@app.route('/marks-entry', methods=['GET', 'POST'])
def marks_entry():
    form = MarksEntryForm()  # Create the form object
    students = Student.query.all()  # Retrieve all students
    edit_data = None

    # Check if we are editing a student (GET request with the 'roll' parameter)
    if request.args.get('roll'):
        edit_roll = request.args.get('roll')
        edit_data = Student.query.filter_by(roll=edit_roll).first()
        if edit_data:
            # Populate the form with the existing student's data for editing
            form.name.data = edit_data.name
            form.roll.data = edit_data.roll
            form.marks.data = edit_data.marks
            form.email.data = edit_data.email

    if form.validate_on_submit():  # If the form is submitted and valid
        # Collect data from form fields
        student_data = {
            'name': form.name.data,
            'roll': form.roll.data,
            'marks': form.marks.data,
            'email': form.email.data
        }

        if request.form['action'] == 'Save' and edit_data:
            # Update the existing student's data
            edit_data.name = student_data['name']
            edit_data.roll = student_data['roll']
            edit_data.marks = student_data['marks']
            edit_data.email = student_data['email']
            db.session.commit()
            flash('Student data updated successfully!', 'success')
            return redirect(url_for('marks_entry'))

        elif request.form['action'] == 'Add':
            # Add a new student if roll number does not exist
            if not Student.query.filter_by(roll=student_data['roll']).first():
                new_student = Student(**student_data)
                db.session.add(new_student)
                db.session.commit()
                flash('Student added successfully!', 'success')
                return redirect(url_for('marks_entry'))
            else:
                flash('Roll number already exists!', 'danger')

    return render_template('index.html', form=form, students=students, edit_data=edit_data)


@app.route('/', methods=['GET'])
def mainpage():
    return render_template('mainpage.html')

# Route to edit a student's details
@app.route('/edit/<roll>', methods=['GET', 'POST'])
def edit_student(roll):
    student = Student.query.filter_by(roll=roll).first()
    if not student:
        flash('Student not found', 'danger')
        return redirect(url_for('marks'))

    form = MarksEntryForm()

    if request.method == 'GET':
        # Pre-populate the form with existing data for GET request
        form.name.data = student.name
        form.roll.data = student.roll
        form.marks.data = student.marks
        form.email.data = student.email
    elif form.validate_on_submit():
        # Update the student's data for POST request (when the form is submitted)
        student.name = form.name.data
        student.roll = form.roll.data
        student.marks = form.marks.data
        student.email = form.email.data
        db.session.commit()
        flash('Student updated successfully!', 'success')
        return redirect(url_for('marks'))

    return render_template('edit_student.html', form=form, student=student)

# Route to delete a student
@app.route('/delete/<roll>', methods=['GET'])
def delete_student(roll):
    student = Student.query.filter_by(roll=roll).first()
    if student:
        db.session.delete(student)
        db.session.commit()
        flash('Student removed successfully!', 'success')
    else:
        flash('Student not found', 'danger')
    return redirect(url_for('marks'))

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=False, port=8080, host="0.0.0.0")
