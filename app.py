from flask import Flask, render_template, request, redirect, url_for, flash,session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,login_required,logout_user,current_user,LoginManager
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from functools import wraps
import os


app = Flask(__name__)
app.secret_key="ShillUp"
basedir=os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db=SQLAlchemy(app)
migrate = Migrate(app, db)  

bcrypt=Bcrypt(app) # to connect bcrypt with orm
login_manager=LoginManager() # to initialise login manager , flask_login module to authenticate user, session data,(e.g decorators = user mixing, login_required, these are if else conditions nothing else inbuilt functions)
login_manager.init_app(app) # 
login_manager.login_view="login" # if not authorised will redirect to login page




class User(UserMixin,db.Model): # for objects in tables usermixing = user authenticate, activate, anonymous(not logged in), get_id(returns unique id)
    __tablename__="user"  # Mapping to a Table: It helps SQLAlchemy map the model class to a specific table in the database.
    id=db.Column(db.Integer,primary_key=True) # id is primary key
    name=db.Column(db.String(150),nullable=False)
    email=db.Column(db.String(150),nullable=False,unique=True)
    password_hash=db.Column(db.String(256),nullable=False)
    mobile=db.Column(db.String(15),nullable=True)
    role=db.Column(db.String(50),nullable=False,default='user') # default user = user registered as default role when login
    occupation = db.Column(db.String(100))   
    interests = db.Column(db.PickleType, default=[])  # Stores a list of interests
    enrolled_courses = db.relationship('EnrolledCourse', backref='user', lazy=True)
    wishlist = db.Column(db.PickleType, default=[])
    purchase_history = db.relationship('Purchase', backref='user', lazy=True)
    enrolled_courses = db.relationship('EnrolledCourse', backref='user', lazy=True)
    purchase_history = db.relationship('Purchase', backref='user', lazy=True)
    

    def set_password(self,password):  # set password 
        self.password_hash=bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self,password): # to match credential input with password  in data base for that we need to hash password for we use check_password ,is handled by bcrypt
        return bcrypt.check_password_hash(self.password_hash,password) #check password checks stored hashed password with entered password
    
    def get_id(self):
        return str(self.id)
    
# Course Model
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    image_url = db.Column(db.String(500), nullable=True)

    def _repr_(self):
        return f'<Course {self.title}>'

class EnrolledCourse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    progress = db.Column(db.Integer, default=0)  # Progress in percentage (0-100)

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
  
with app.app_context(): # create table in database must to write in all applications
    db.create_all()

@login_manager.user_loader # to access data of user who has already login 


def load_user(user_id):
    return User.query.get(int(user_id)) # when we  use current user data we use current user module
login_manager.login_view = 'login'  # Redirects users to /login if not authenticated

def admin_required(func): 
    @wraps(func) 
    def wrapper(*args, **kwargs): 
        if current_user.role != 'admin': 
            flash("Access denied!", "danger") 
            return redirect(url_for('admindashboard')) 
        return func(*args, **kwargs) 
    return wrapper

# Route for Home Page
@app.route('/')
def home():
    return render_template('index.html', courses=courses)

@app.route("/signup",methods=["GET","POST"])
def signup():
    if request.method=="POST": # if not post method register.html will execute
        # id=request.form.get("id") # primary key 
        fullname=request.form.get("fullname")
        email=request.form.get("email")
        password=request.form.get("password").strip() # 
        confirm_password=request.form.get("confirm_password").strip() # for security reasons 
        mobile = request.form.get("mobile")   
        role=request.form.get("role","user") # as it is set to default 
        if password!=confirm_password: 
            flash("Passwords do not match","danger")
            return redirect(url_for("signup"))
        # check if email already exists

        if User.query.filter_by(email=email).first(): # if this email matches with object of email it wiil give that particular user data
            flash("Email already exists","danger")
            return redirect(url_for("signup"))
        
        # if both matches user can update further changes which will be further stored in form of objects in dbms
        try:
            new_user = User(
                name=fullname,  # Map form's 'fullname' to model's 'name'
                email=email,                
                mobile=mobile,
                role=role
                
                 # Will be set via set_password()
        )
            
            # new_user=User(name=fullname,email=email,role=role,mobile=mobile)
            # role_id = request.form.get('options')
            # role = Role.query.filter_by(id=role_id).first()

            new_user.set_password(password) # hashing
            db.session.add(new_user) # 
            db.session.commit()

            flash("Registered successfully","success")
            return redirect(url_for('login')) # if registered successfully it will redirect to login page 
    
        except Exception as e:
            db.session.rollback()
            flash("Registration failed. Please check all fields", "danger")
            return redirect(url_for("signup"))
    
    return render_template("signup.html")

# @app.route("/login",methods=["GET","POST"])
# def login():
#     if request.method=="POST": 
#         email=request.form.get("email")
#         password=request.form.get("password").strip()
        
#         user=User.query.filter_by(email=email).first() # if email matches get the details of that user
                
#         if not user:
#             flash("Invalid credentials!", "danger")
#             return redirect(url_for('login'))  
         
#         if user.check_password(password): # password will be in form of hash differnt from original password it will check_password
#                 login_user(user) #to store info
#                 flash("Login successful!", "success")
#                 return redirect(url_for("dashboard")) # private page only can be accessed once login 
#         else:
#                 flash("Invalid credentials!", "danger")
        
#     return render_template('login.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password").strip()
        
        user = User.query.filter_by(email=email).first()  # Get the user by email
                
        if not user:
            flash("Invalid credentials!", "danger")
            return redirect(url_for('login'))  
         
        if user.check_password(password):  # If password matches
            login_user(user)  # Log the user in
            flash("Login successful!", "success")
            
            # Redirect to the appropriate dashboard based on role
            if user.role=='admin':
                return redirect(url_for("admindashboard"))  # Admin dashboard
            else:
                return redirect(url_for("dashboard"))  # User dashboard
                
        else:
            flash("Invalid credentials!", "danger")
        
    return render_template('login.html')


# routes.py (or your main Flask file)
@app.route('/forgetPassword', methods=['GET', 'POST'])
def forgetPassword():
    if request.method == 'POST':
        email = request.form.get('email')
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')

        # Basic validation
        if not email or not new_password or not confirm_password:
            flash("All fields are required!", "danger")
            return redirect(url_for('forgetPassword'))

        if new_password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('forgetPassword'))

        # Find user by email
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with that email!", "danger")
            return redirect(url_for('forgetPassword'))


        # Update password
        user.set_password(new_password)
        db.session.commit()

        flash("Password updated successfully!", "success")
        return redirect(url_for('login'))

    return render_template('forgetPassword.html')


# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user=current_user)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role=='admin':  # Prevent admins from accessing user dashboard
        return redirect(url_for('admindashboard'))
    return render_template('dashboard.html', user=current_user)


@app.route('/admin') 
@login_required 
@admin_required 
def admin(): 
    if current_user.role != "admin":  # Restrict non-admin users
        flash("Access Denied! Admins only.", "danger")
        return redirect(url_for('admindashboard', user=current_user))  # Redirect to a safe page
    return render_template("index.html")

# @app.route('/admindashboard')
# @login_required
# @admin_required
# def admindashboard():
#     # Fetch all courses from the database
#     courses = Course.query.all()
#     if not current_user.is_admin:
#         return redirect(url_for('dashboard'))
#     return render_template('admindashboard.html', courses=courses)

@app.route('/admindashboard')
@login_required
def admindashboard():
    if not current_user.role=='admin':  # Ensure only admins can access
        flash("Access Denied! Admins only.", "danger")
        return redirect(url_for('dashboard'))  # Redirect normal users to their dashboard
    courses = Course.query.all()  # Fetch all courses
    return render_template('admindashboard.html', courses=courses)


@app.route('/createcourse', methods=['GET', 'POST'])
def createcourse():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        image_url = request.form['image_url']

        # Create a new course and add it to the database
        new_course = Course(title=title, description=description, image_url=image_url)
        db.session.add(new_course)
        db.session.commit()

        return redirect(url_for('admindashboard'))
    return render_template('createcourse.html')
    
@app.route('/deletecourse/<int:id>')
def deletecourse(id):
    course = Course.query.get_or_404(id)
    db.session.delete(course)
    db.session.commit()
    return redirect(url_for('admindashboard'))

@app.route('/editcourse/<int:id>', methods=['GET', 'POST'])
def editcourse(id):
    course = Course.query.get_or_404(id)
    if request.method == 'POST':
        course.title = request.form['title']
        course.description = request.form['description']
        course.image_url = request.form['image_url']
        db.session.commit()
        return redirect(url_for('admindashboard'))
    return render_template('editcourse.html', course=course)


# Route for Courses Page
@app.route('/courses')
def courses():
    return render_template('courses.html')

@app.route('/termscondition')
def termscondition():
    return render_template('termscondition.html')


# Route for Profile Page
@app.route('/profile')
@login_required
def profile():  
    if not current_user.is_authenticated:
        flash("Please log in to access your profile.", "warning")
        return redirect(url_for('login'))
    return render_template('profile.html', current_user=current_user)

@app.route('/coursedetail')
def coursedetail():
    return render_template('coursedetail.html')


@app.route('/checkout')
def checkout():
    return render_template('checkout.html')



@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    course_id = request.form.get('course_id')
    course_name = request.form.get('course_name')
    price = float(request.form.get('price'))  # Convert price to float

    if 'cart' not in session:
        session['cart'] = []

    

    # Prevent duplicate courses in cart
    existing_item = next((item for item in session['cart'] if item['id'] == course_id), None)
    if existing_item:
        flash("Course is already in the cart!", "info")
    else:
        session['cart'].append({'id': course_id, 'name': course_name, 'price': price})
        session.modified = True
        flash("Course added to cart!", "success")

    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    cart_items = session.get('cart', [])
    total_price = sum(item['price'] for item in cart_items)  # Calculate total price
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/remove_from_cart/<course_id>')
def remove_from_cart(course_id):
    if 'cart' in session:
        session['cart'] = [item for item in session['cart'] if item['id'] != course_id]
        session.modified = True
        flash("Course removed from cart!", "warning")

    return redirect(url_for('cart'))

@app.route('/clear_cart')
def clear_cart():
    session.pop('cart', None)  # Remove cart from session
    flash("Cart cleared!", "danger")
    return redirect(url_for('cart'))

# Route for Language Selection (Placeholder)
@app.route('/language/<lang>')
def set_language(lang):
    return f"Language changed to {lang}"  # Placeholder, actual implementation needed

@app.route("/logout")
@login_required
def logout():
    logout_user() # remove session data
    session.clear()
    flash("Logged out successfully","success") 
    return redirect(url_for('login'))



if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create the database tables
    app.run(debug=True)