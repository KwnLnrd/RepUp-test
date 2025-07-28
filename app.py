import os
import traceback
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, get_jwt

# --- CONFIGURATION INITIALE ---
load_dotenv()
app = Flask(__name__)

# --- LOGGING CONFIGURATION ---
app.logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# --- CORS CONFIGURATION ---
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://repup-avis.netlify.app")
CORS(app, 
     origins=[FRONTEND_URL, "http://127.0.0.1:5500", "http://127.0.0.1:5501"],
     supports_credentials=True,
     allow_headers=["Authorization", "Content-Type"]
)

# --- CONFIGURATION DE LA BASE DE DONNÉES ET JWT ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL is not set.")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "une-cle-vraiment-secrete-et-longue-pour-la-prod")

# --- FINAL FIX: EXPLICITLY SET TOKEN LOCATION ---
# This forces Flask-JWT-Extended to look for the JWT in the Authorization header,
# which is where we know it is. This resolves the conflict.
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_CSRF_PROTECTION"] = False # Explicitly disable CSRF for safety

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- LOGGING HOOK ---
@app.before_request
def log_request_info():
    """Log the headers of every incoming request to help debug the auth issue."""
    app.logger.info(f"--- Request to {request.path} ---")
    app.logger.info(f"Headers: {request.headers}")


# --- MODÈLES DE LA BASE DE DONNÉES (Architecture Multi-Tenant) ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    restaurant = db.relationship('Restaurant', back_populates='user', uselist=False)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    logo_url = db.Column(db.String(255), nullable=True)
    primary_color = db.Column(db.String(7), default='#BF5B3F')
    google_link = db.Column(db.String(512), nullable=True)
    tripadvisor_link = db.Column(db.String(512), nullable=True)
    enabled_languages = db.Column(db.JSON, default=['fr', 'en'])
    
    user = db.relationship('User', back_populates='restaurant', cascade="all, delete-orphan")
    servers = db.relationship('Server', back_populates='restaurant', cascade="all, delete-orphan")
    dishes = db.relationship('Dish', back_populates='restaurant', cascade="all, delete-orphan")

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    avatar_url = db.Column(db.String(255), nullable=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='servers')

class Dish(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='dishes')

with app.app_context():
    db.create_all()

# --- HELPER ---
def get_restaurant_id_from_token():
    """Helper to get restaurant_id from JWT claims."""
    return get_jwt()["restaurant_id"]

# --- AUTHENTIFICATION & INSCRIPTION ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email, password, restaurant_name = data.get('email'), data.get('password'), data.get('restaurant_name')
    if not all([email, password, restaurant_name]): return jsonify({"error": "Données manquantes"}), 400
    if User.query.filter_by(email=email).first(): return jsonify({"error": "Cet email est déjà utilisé"}), 409
    
    slug = restaurant_name.lower().replace(' ', '-') + '-' + str(db.session.query(Restaurant).count() + 1)
    new_restaurant = Restaurant(name=restaurant_name, slug=slug)
    db.session.add(new_restaurant)
    db.session.flush()
    
    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password_hash=hashed_password, restaurant_id=new_restaurant.id)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Compte créé avec succès"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(
            identity=user.id, 
            additional_claims={
                "restaurant_id": user.restaurant_id,
                "restaurant_slug": user.restaurant.slug 
            }
        )
        return jsonify(access_token=access_token)
    return jsonify({"error": "Identifiants invalides"}), 401

# --- API PUBLIQUE (Page de collecte d'avis) ---
@app.route('/api/public/restaurant/<string:slug>', methods=['GET'])
def get_restaurant_public_data(slug):
    restaurant = Restaurant.query.filter_by(slug=slug).first_or_404()
    servers = Server.query.filter_by(restaurant_id=restaurant.id).all()
    return jsonify({
        "name": restaurant.name,
        "logoUrl": restaurant.logo_url,
        "primaryColor": restaurant.primary_color,
        "links": {
            "google": restaurant.google_link,
            "tripadvisor": restaurant.tripadvisor_link
        },
        "servers": [{"id": s.id, "name": s.name, "avatar": s.avatar_url} for s in servers],
        "languages": restaurant.enabled_languages
    })

# --- API PRIVÉE (Panel d'administration) ---

# RESTAURANT SETTINGS
@app.route('/api/restaurant', methods=['GET', 'PUT'])
@jwt_required()
def manage_restaurant_settings():
    restaurant_id = get_restaurant_id_from_token()
    restaurant = db.session.get(Restaurant, restaurant_id)
    if not restaurant: return jsonify({"error": "Restaurant non trouvé"}), 404

    if request.method == 'GET':
        return jsonify({
            "name": restaurant.name,
            "slug": restaurant.slug,
            "logoUrl": restaurant.logo_url,
            "primaryColor": restaurant.primary_color,
            "googleLink": restaurant.google_link,
            "tripadvisorLink": restaurant.tripadvisor_link,
            "enabledLanguages": restaurant.enabled_languages
        })

    if request.method == 'PUT':
        data = request.get_json()
        restaurant.logo_url = data.get('logoUrl', restaurant.logo_url)
        restaurant.primary_color = data.get('primaryColor', restaurant.primary_color)
        restaurant.google_link = data.get('googleLink', restaurant.google_link)
        restaurant.tripadvisor_link = data.get('tripadvisorLink', restaurant.tripadvisor_link)
        restaurant.enabled_languages = data.get('enabledLanguages', restaurant.enabled_languages)
        db.session.commit()
        return jsonify({"message": "Paramètres mis à jour"})

# SERVERS
@app.route('/api/servers', methods=['GET', 'POST'])
@jwt_required()
def manage_servers():
    restaurant_id = get_restaurant_id_from_token()
    if request.method == 'GET':
        servers = Server.query.filter_by(restaurant_id=restaurant_id).order_by(Server.name).all()
        return jsonify([{"id": s.id, "name": s.name, "reviews": 0} for s in servers])
    if request.method == 'POST':
        data = request.get_json()
        new_server = Server(name=data['name'], restaurant_id=restaurant_id)
        db.session.add(new_server)
        db.session.commit()
        return jsonify({"id": new_server.id, "name": new_server.name}), 201

@app.route('/api/servers/<int:server_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def handle_server(server_id):
    restaurant_id = get_restaurant_id_from_token()
    server = Server.query.filter_by(id=server_id, restaurant_id=restaurant_id).first_or_404()
    if request.method == 'PUT':
        data = request.get_json()
        server.name = data.get('name', server.name)
        db.session.commit()
        return jsonify({"id": server.id, "name": server.name})
    if request.method == 'DELETE':
        db.session.delete(server)
        db.session.commit()
        return jsonify({"message": "Serveur supprimé"})

# MENU
@app.route('/api/menu', methods=['GET'])
@jwt_required()
def get_menu():
    restaurant_id = get_restaurant_id_from_token()
    dishes = Dish.query.filter_by(restaurant_id=restaurant_id).order_by(Dish.category, Dish.name).all()
    menu = {}
    for dish in dishes:
        if dish.category not in menu:
            menu[dish.category] = []
        menu[dish.category].append({"id": dish.id, "name": dish.name})
    return jsonify(menu)

@app.route('/api/dishes', methods=['POST'])
@jwt_required()
def add_dish():
    restaurant_id = get_restaurant_id_from_token()
    data = request.get_json()
    new_dish = Dish(name=data['name'], category=data['category'], restaurant_id=restaurant_id)
    db.session.add(new_dish)
    db.session.commit()
    return jsonify({"id": new_dish.id, "name": new_dish.name, "category": new_dish.category}), 201

@app.route('/api/dishes/<int:dish_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def handle_dish(dish_id):
    restaurant_id = get_restaurant_id_from_token()
    dish = Dish.query.filter_by(id=dish_id, restaurant_id=restaurant_id).first_or_404()
    if request.method == 'PUT':
        data = request.get_json()
        dish.name = data.get('name', dish.name)
        dish.category = data.get('category', dish.category)
        db.session.commit()
        return jsonify({"id": dish.id, "name": dish.name, "category": dish.category})
    if request.method == 'DELETE':
        db.session.delete(dish)
        db.session.commit()
        return jsonify({"message": "Plat supprimé"})

# --- ROOT ROUTE (Added for health checks and to avoid 404) ---
@app.route('/')
def index():
    return jsonify({"status": "API is running"}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)
