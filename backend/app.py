import os
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
import stripe

# --- CONFIGURATION INITIALE ---
load_dotenv()
app = Flask(__name__)
CORS(app, supports_credentials=True)

# --- CONFIGURATION DE LA BASE DE DONNÉES ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL is not set.")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "une-cle-vraiment-secrete-et-longue")

db = SQLAlchemy(app)
jwt = JWTManager(app)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# --- MODÈLES DE LA BASE DE DONNÉES (Architecture Multi-Tenant) ---

class User(db.Model):
    """ Modèle pour l'utilisateur (le propriétaire du restaurant) """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    restaurant = db.relationship('Restaurant', back_populates='user', uselist=False)

class Restaurant(db.Model):
    """ Modèle central pour chaque client restaurant (tenant) """
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
    reviews = db.relationship('Review', back_populates='restaurant', cascade="all, delete-orphan")
    internal_feedbacks = db.relationship('InternalFeedback', back_populates='restaurant', cascade="all, delete-orphan")

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

class Review(db.Model):
    """ Stocke chaque avis positif généré pour les statistiques """
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='reviews')

class InternalFeedback(db.Model):
    """ Stocke les retours négatifs privés """
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    feedback_text = db.Column(db.Text, nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='internal_feedbacks')

with app.app_context():
    db.create_all()

# --- ROUTES D'AUTHENTIFICATION ET D'INSCRIPTION ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    restaurant_name = data.get('restaurant_name')

    if not all([email, password, restaurant_name]):
        return jsonify({"error": "Données manquantes"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Cet email est déjà utilisé"}), 409

    # Création du restaurant
    slug = restaurant_name.lower().replace(' ', '-') + '-' + str(db.session.query(Restaurant).count() + 1)
    new_restaurant = Restaurant(name=restaurant_name, slug=slug)
    db.session.add(new_restaurant)
    db.session.flush() # Pour obtenir l'ID du restaurant

    # Création de l'utilisateur
    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password_hash=hashed_password, restaurant_id=new_restaurant.id)
    db.session.add(new_user)
    
    db.session.commit()

    return jsonify({"message": "Compte créé avec succès"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(
            identity=user.id,
            additional_claims={"restaurant_id": user.restaurant_id}
        )
        return jsonify(access_token=access_token)

    return jsonify({"error": "Identifiants invalides"}), 401

# --- API PUBLIQUE (pour la page de collecte d'avis) ---

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

@app.route('/api/public/submit-feedback', methods=['POST'])
def submit_feedback():
    data = request.get_json()
    restaurant_slug = data.get('restaurant_slug')
    server_id = data.get('server_id')
    rating = data.get('rating')
    feedback_text = data.get('feedback_text', None)

    restaurant = Restaurant.query.filter_by(slug=restaurant_slug).first_or_404()

    if rating >= 4: # Avis positif
        new_review = Review(rating=rating, server_id=server_id, restaurant_id=restaurant.id)
        db.session.add(new_review)
    else: # Avis négatif (feedback interne)
        if not feedback_text:
            return jsonify({"error": "Le texte du feedback est requis pour les notes faibles"}), 400
        new_internal_feedback = InternalFeedback(
            rating=rating,
            feedback_text=feedback_text,
            server_id=server_id,
            restaurant_id=restaurant.id
        )
        db.session.add(new_internal_feedback)

    db.session.commit()
    return jsonify({"message": "Feedback enregistré avec succès"}), 200


# --- API PRIVÉE (pour le panel d'administration) ---
# Toutes les routes ci-dessous nécessitent un token JWT valide

def get_current_restaurant_id():
    """Fonction helper pour récupérer l'ID du restaurant depuis le token JWT"""
    return get_jwt_identity() # L'identité est l'ID de l'utilisateur, mais on utilise la claim
    
@jwt_required()
def get_restaurant_id_from_token():
    return get_jwt()["restaurant_id"]


@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_data():
    restaurant_id = get_restaurant_id_from_token()
    
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    reviews_count = Review.query.filter(
        Review.restaurant_id == restaurant_id,
        Review.created_at >= thirty_days_ago
    ).count()
    
    avg_rating_query = db.session.query(func.avg(Review.rating)).filter(
        Review.restaurant_id == restaurant_id,
        Review.created_at >= thirty_days_ago
    ).scalar()
    avg_rating = round(avg_rating_query, 1) if avg_rating_query else 0
    
    internal_feedback_count = InternalFeedback.query.filter(
        InternalFeedback.restaurant_id == restaurant_id,
        InternalFeedback.created_at >= thirty_days_ago
    ).count()

    # Pour le serveur du mois, c'est une logique plus complexe, on simule pour l'instant
    top_server = "Clara" # Simulation

    return jsonify({
        "stats": {
            "reviews_30d": reviews_count,
            "avg_rating": avg_rating,
            "top_server_30d": top_server,
            "internal_feedbacks_30d": internal_feedback_count
        }
        # Vous pouvez ajouter les données de graphique ici
    })

@app.route('/api/servers', methods=['GET', 'POST'])
@jwt_required()
def manage_servers():
    restaurant_id = get_restaurant_id_from_token()
    if request.method == 'GET':
        servers = Server.query.filter_by(restaurant_id=restaurant_id).all()
        return jsonify([{"id": s.id, "name": s.name, "reviews": 0} for s in servers]) # reviews à calculer
    
    if request.method == 'POST':
        data = request.get_json()
        new_server = Server(name=data['name'], restaurant_id=restaurant_id)
        db.session.add(new_server)
        db.session.commit()
        return jsonify({"id": new_server.id, "name": new_server.name}), 201

# ... Ajoutez les autres routes de l'API privée ici (PUT/DELETE pour serveurs, CRUD pour plats, etc.)
# Chaque route devra utiliser `get_restaurant_id_from_token()` et filtrer les requêtes par cet ID.

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)
