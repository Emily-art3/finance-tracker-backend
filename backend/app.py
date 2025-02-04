from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
import locale
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
from datetime import timedelta
from functools import wraps
from supabase import create_client, Client
from sqlalchemy.engine import URL
from urllib.parse import quote_plus 





load_dotenv()


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Supabase URL and API key must be set in environment variables.")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://finance-tracker-frontend-dzbczyfyo-emily-art3s-projects.vercel.app", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}}, supports_credentials=True)

port = int(os.environ.get("PORT", 5000))


DB_CONFIG = {
    "dbname" : os.getenv("DB_NAME"),
    "user" : os.getenv("DB_USER"),
    "password": quote_plus(os.getenv("DB_PASSWORD")),
    "host" : os.getenv("DB_HOST"),
    "port" : os.getenv("DB_PORT")
}

database_url = URL.create(
    drivername="postgresql",
    username=DB_CONFIG['user'],
    password=DB_CONFIG['password'],
    host=DB_CONFIG['host'],
    port=DB_CONFIG['port'],
    database=DB_CONFIG['dbname']
)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY") 

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True,autoincrement= True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(400), nullable=False)
    role = db.Column(db.String(10), default="user")  
    locale = db.Column(db.String(10), default="en_US")  

    def __init__(self, username, email, password, role="user"):
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.role = role
      
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), index=True)
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.String(100), nullable=False)

class Goal(db.Model):
    __tablename__ = 'goal'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    goal_name = db.Column(db.String(100), nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    current_amount = db.Column(db.Float, default=0)
    deadline = db.Column(db.Date, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

    category = db.relationship('Category', backref=db.backref('goals', lazy=True))

@app.route('/healthz')
def health_check():
    return "OK", 200


@app.route('/')
def home():
    return jsonify({"message": "Welcome to Finance Tracker API"}), 200


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')   
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201

@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")
        username = data.get("username")
        role = data.get("role", "user")

        if not email or not password or not username:
            return jsonify({"error": "Email, username, and password are required"}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"error": "User already exists in local database"}), 400

        auth_response = supabase.auth.sign_up({"email": email, "password": password})

        if not auth_response or not hasattr(auth_response, "user") or not auth_response.user:
            print("Supabase Auth Error:", auth_response)
            return jsonify({"error": "Auth registration failed"}), 400

        user_id = auth_response.user.id 

        insert_response = supabase.table("users").insert({
            "id": user_id,
            "email": email,
            "username": username,
            "role": role
        }).execute()

        print("Supabase Insert Result:", insert_response)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role=role)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User created successfully"}), 201

    except Exception as e:
        print(f"Full Error: {str(e)}")
        return jsonify({"error": f"Signup failed: {str(e)}"}), 500



def role_required(required_role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_function(*args, **kwargs):
            user = get_jwt_identity()
            if user.get("role") != required_role:
                return jsonify({"error": "Unauthorized access"}), 403
            return fn(*args, **kwargs)
        return decorated_function
    return wrapper

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        print(f"Attempting login for email: {email}")

        user = User.query.filter_by(email=email).first()

        if user:
            if bcrypt.check_password_hash(user.password, password):
                print("User found in local database.")
            else:
                return jsonify({"error": "Invalid credentials"}), 401 
        else:
            print("User not found locally. Checking Supabase...")

            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})

            if hasattr(auth_response, "user") and auth_response.user:
                print("User found in Supabase. Syncing to local database...")

                existing_user = User.query.filter_by(email=email).first()

                if existing_user:
                    print("User already exists in local database. Skipping insert.")
                    user = existing_user  
                else:
                    print("User does not exist locally. Creating a new record...")

                    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

                    new_user = User(id=auth_response.user.id, email=email, username=email.split("@")[0], password=hashed_password, role="user")
                    db.session.add(new_user)
                    db.session.commit()

                    user = new_user 

        access_token = create_access_token(identity={
            "id": user.id,
            "email": user.email,
            "role": user.role
        }, expires_delta=timedelta(hours=1))

        return jsonify({
            "access_token": access_token,
            "user_id": user.id,
            "role": user.role
        }), 200

    except Exception as e:
        print(f"Error logging in via Supabase: {str(e)}")
        return jsonify({"error": "Login failed"}), 500



@app.route('/api/get_users', methods=['GET'])
def get_users():
    users = supabase.table('users').select('*').execute()
    return jsonify(users['data'])

@app.route("/api/sync_users", methods=["GET"])
def sync_users():
    try:
        print("Fetching users from Supabase...")
        supabase_users = supabase.table("users").select("*").execute()

        for user in supabase_users.data:
            email = user.get("email")
            role = user.get("role", "user")

            existing_user = User.query.filter_by(email=email).first()
            if not existing_user:
                print(f"Adding {email} to local database...")

                new_user = User(username=email.split("@")[0], email=email, password="from_supabase", role=role)
                db.session.add(new_user)

        db.session.commit()
        return jsonify({"message": "Users synced successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    user_identity = get_jwt_identity()
    print(f"User ID from token: {user_identity}")
   
    user_id = user_identity.get("id")

    if not user_id:
        print("Error: No user ID in token!")  
        return jsonify({"error": "Invalid token"}), 401
    
    user = User.query.get(user_id)
    user_locale = user.locale if user else 'en_US'  

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    transactions = Transaction.query.filter_by(user_id=user_id).paginate(page=page, per_page=per_page, error_out=False)

    result = [
        {
            "id": t.id,
            "description": t.description,
            "amount": format_currency(t.amount, user_locale),
            "date": t.date,
            "category": t.category_id,
        }
        for t in transactions.items
    ]
    return jsonify({
        "transactions": result,
        "total": transactions.total,
        "pages": transactions.pages,
        "current_page": transactions.page,
    })



@app.route('/api/transactions', methods=['POST'])
@jwt_required()
def add_transaction():
    user_id = get_jwt_identity()['id']
    data = request.json
    try:
        new_transaction = Transaction(
            user_id=user_id,
            description=data['description'],
            amount=data['amount'],
            date=data['date'],
            category_id=data['category_id'],
        )
        category = Category.query.get(data['category_id'])
        if category and category.goals:
            for goal in category.goals:
                if goal.user_id == user_id:
                    goal.current_amount += new_transaction.amount
                    db.session.commit()
              
        db.session.add(new_transaction)
        db.session.commit()
        print("Transaction added to local database")

        insert_response = supabase.table("transactions").insert({
            "user_id": user_id,
            "description": data['description'],
            "amount": data['amount'],
            "date": data['date'],
            "category_id": data.get('category_id'),
            "goal_id": data.get('goal_id')
        }).execute()

        if insert_response.status_code == 201:
           print("Transaction added to Supabase:", insert_response.data)
        else:
            print("Error inserting transaction into Supabase:", insert_response.data)

        return jsonify({"message": "Transaction added successfully!"}), 201
    except Exception as e:
        print(f"Error adding transaction: {str(e)}")  
        return jsonify({"error": str(e)}), 400
    

@app.route('/api/users/locale', methods=['PATCH'])
@jwt_required()
def update_locale():
    user_id = get_jwt_identity()['id']
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.json
    if not data.get('locale'):
        return jsonify({"error": "Locale is required!"}), 400

    try:
        user.locale = data['locale']
        db.session.commit()
        return jsonify({"message": "Locale updated successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def format_currency(amount, user_locale):
    try:
        locale.setlocale(locale.LC_ALL, user_locale)
        return locale.currency(amount, grouping=True)
    except locale.Error:
        locale.setlocale(locale.LC_ALL, 'en_US')
        return locale.currency(amount, grouping=True)

@app.route('/api/admin/transactions', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_all_transactions():
    user_role = get_jwt_identity()['role']
    if user_role != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    transactions = Transaction.query.all()
    result = [
        {
            "id": t.id,
            "description": t.description,
            "amount": t.amount,
            "date": t.date,
            "amount": format_currency(t.amount),
            "user_id": t.user_id,
        }
        for t in transactions
    ]
    return jsonify(result)

@app.route('/api/goals', methods=['GET'])
@jwt_required()
def get_goals():
    user_id = get_jwt_identity()['id']
    goals = Goal.query.filter_by(user_id=user_id).all()
    result = [
        {
            "id": goal.id,
            "goal_name": goal.goal_name,
            "target_amount": goal.target_amount,
            "current_amount": goal.current_amount,
            "deadline": goal.deadline.strftime('%Y-%m-%d'),
            "category_id": goal.category_id,
            "category_name": goal.category.name if goal.category else None  # Include category name if present
        }
        for goal in goals
    ]
    return jsonify(result)
@app.route('/api/goals', methods=['POST'])
@jwt_required()
def add_goal():
    user_id = get_jwt_identity()['id']
    
    data = request.json
    goal_name = data.get('goal_name')
    target_amount = data.get('target_amount')
    deadline = data.get('deadline')
    category_id = data.get('category_id')
    
    if not goal_name:
        return jsonify({"error": "Goal name is required!"}), 400
    if target_amount <= 0:
        return jsonify({"error": "Target amount must be greater than 0!"}), 400
    if not deadline:
        return jsonify({"error": "Deadline is required!"}), 400

    category = Category.query.get(category_id)
    if not category:
        return jsonify({"error": "Invalid category ID!"}), 400
    
    new_goal = Goal(
        user_id=user_id,
        goal_name=goal_name,
        target_amount=target_amount,
        current_amount=0,
        deadline=deadline,
        category_id=category_id
    )

    try:
        db.session.add(new_goal)
        db.session.commit()
       
        insert_response = supabase.table("goals").insert({
            "user_id": user_id,
            "goal_name": goal_name,
            "target_amount": target_amount,
            "current_amount": 0,
            "deadline": deadline,
            "category_id": category_id
        }).execute()

        return jsonify({"message": "Goal added successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/goals/<int:goal_id>', methods=['PATCH'])
@jwt_required()
def update_goal(goal_id):
    user_id = get_jwt_identity()['id']
    goal = Goal.query.filter_by(id=goal_id, user_id=user_id).first()
    if not goal:
        return jsonify({"error": "Goal not found"}), 404
    
    data = request.json
    try:
        if 'amount' in data:
            goal.current_amount = data['amount'] 
        db.session.commit()
        return jsonify({"message": "Goal progress updated!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/categories', methods=['GET'])
def get_categories():
    response = supabase.from_('categories').select('*').execute()

    print("Supabase response:", response)

    if hasattr(response, 'error') and response.error:
        return jsonify({"error": str(response.error)}), 500

    categories = getattr(response, 'data', None)

    if isinstance(categories, list):
        for cat in categories:
            existing_category = Category.query.filter_by(id=cat["id"]).first()
            if not existing_category:
                new_category = Category(id=cat["id"], name=cat["name"])
                db.session.add(new_category)
        db.session.commit()
        
        return jsonify(categories), 200  

    return jsonify({"error": "Unexpected response format"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)
    with app.app_context():
        print("Registered routes:")
        for rule in app.url_map.iter_rules():
            print(rule)

