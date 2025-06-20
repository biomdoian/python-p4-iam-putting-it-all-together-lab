#!/usr/bin/env python3

from flask import request, session, make_response, jsonify # Import make_response, jsonify, and session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError # For handling unique constraint errors
from flask_bcrypt import Bcrypt # Import Bcrypt for password hashing

# Import app, db, api from config.py as per your provided structure
from config import app, db, api 
from models import User, Recipe # Import your User and Recipe models

# Initialize Bcrypt with your app instance.
# Assuming 'app' is imported from config and is already a Flask app instance.
bcrypt = Bcrypt(app)

# --- Utility Route for Tests (Clear Session) ---
# This route is typically used by test suites to ensure a clean session state.
@app.route('/clear', methods=['DELETE'])
def clear_session_route():
    session.pop('user_id', None) # Clear the user_id from the session
    # Also clear any other session data that might interfere with tests
    session.pop('page_views', None) 
    return make_response(jsonify({"message": "Session cleared."}), 204) # 204 No Content

# --- Home Route (basic server check) ---
# This can be a simple function or a Resource. Sticking to simple function for root.
@app.route('/')
def index():
    return '<h1>Full Stack Auth & Auth Lab API</h1>'

# --- Signup Feature (POST /signup) ---
class Signup(Resource):
    def post(self):
        username = request.json.get('username')
        password = request.json.get('password') # Raw password from request
        image_url = request.json.get('image_url')
        bio = request.json.get('bio')

        if not username or not password:
            return make_response(jsonify({"errors": ["Username and password are required"]}), 422)

        try:
            # Create a new User instance. The password_hash setter will handle bcrypt hashing.
            user = User(
                username=username,
                image_url=image_url,
                bio=bio
            )
            user.password_hash = password # Calls the property setter in models.py

            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id # Log in the new user by saving their ID to the session

            # Return the new user's data (excluding password hash) with a 201 Created status
            return make_response(jsonify(user.to_dict()), 201)

        except ValueError as e: # Catch custom validation errors from models (e.g., username not present, instructions length)
            db.session.rollback()
            return make_response(jsonify({"errors": [str(e)]}), 422)
        except IntegrityError: # Catch database unique constraint errors (e.g., duplicate username)
            db.session.rollback()
            return make_response(jsonify({"errors": ["Username already exists"]},), 422)
        except Exception as e: # Catch other potential unexpected errors
            db.session.rollback()
            return make_response(jsonify({"errors": ["An unexpected error occurred: " + str(e)]}), 500)


# --- Check Session Feature (GET /check_session) ---
class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id') # Get user_id from session

        if user_id:
            user = User.query.filter_by(id=user_id).first()
            if user:
                # If user found and logged in, return their data
                return make_response(jsonify(user.to_dict()), 200)
        
        # If no user_id in session or user not found, return unauthorized
        return make_response(jsonify({"errors": ["Unauthorized"]}), 401)


# --- Login Feature (POST /login) ---
class Login(Resource):
    def post(self):
        username = request.json.get('username')
        password = request.json.get('password')

        user = User.query.filter_by(username=username).first()

        # Authenticate user using the method defined in the User model
        if user and user.authenticate(password):
            session['user_id'] = user.id # Log in the user
            return make_response(jsonify(user.to_dict()), 200)
        else:
            # If authentication fails, return unauthorized error
            return make_response(jsonify({"errors": ["Invalid username or password"]}), 401)


# --- Logout Feature (DELETE /logout) ---
class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if user_id:
            session.pop('user_id', None)  # Log out
            return make_response('', 204)
        else:
            return make_response(jsonify({"errors": ["Not logged in"]}), 401)
# --- Recipe Index Feature (GET /recipes, POST /recipes) ---
class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response(jsonify({"errors": ["Unauthorized: Please log in to view recipes."]}), 401)
        
        # If authorized, fetch all recipes
        recipes = Recipe.query.all()
        # Serialize each recipe; serialization rules in models.py will handle nested user object
        return make_response(jsonify([r.to_dict() for r in recipes]), 200)

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response(jsonify({"errors": ["Unauthorized: Please log in to create recipes."]}), 401)

        data = request.get_json()
        if not data:
            return make_response(jsonify({"errors": ["No data provided"]}), 422)

        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        # Get the logged-in user to associate the recipe
        current_user = User.query.filter_by(id=user_id).first()
        if not current_user: # Safety check, though user_id in session should imply user exists
            db.session.rollback()
            return make_response(jsonify({"errors": ["Logged-in user not found."]},), 401)

        try:
            # Create new Recipe instance, associating it with the current_user object
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user=current_user # Assign the user object directly
            )
            
            db.session.add(new_recipe)
            db.session.commit()
            
            # Return the newly created recipe's data (serialized) with a 201 Created status
            return make_response(jsonify(new_recipe.to_dict()), 201)

        except ValueError as e: # Catch custom validation errors from models (e.g., instructions length)
            db.session.rollback()
            return make_response(jsonify({"errors": [str(e)]}), 422)
        except Exception as e: # Catch other potential database errors
            db.session.rollback()
            return make_response(jsonify({"errors": ["An unexpected error occurred: " + str(e)]}), 500)


# --- Register Resources with API ---
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes') # Handles both GET and POST for /recipes

# --- Global Error Handlers (Consistent JSON responses) ---
# These handlers catch exceptions that bubble up from your routes
@app.errorhandler(401)
def unauthorized_error(error):
    return make_response(jsonify({'errors': ['Unauthorized', 'Authentication required.']}), 401)

@app.errorhandler(403)
def forbidden_error(error):
    return make_response(jsonify({'errors': ['Forbidden', 'You do not have permission to access this resource.']}), 403)

@app.errorhandler(404)
def not_found_error(error):
    return make_response(jsonify({'errors': ['Not Found', 'The requested URL was not found on the server.']}), 404)

@app.errorhandler(500)
def internal_server_error(error):
    db.session.rollback() # Ensure rollback for any uncaught errors that reach here
    return make_response(jsonify({'errors': ['Internal Server Error', 'Something went wrong on the server.']}), 500)

if __name__ == '__main__':
    # Flask app is run from config.py, but for local testing without that setup,
    # it's good to keep this block if config.py doesn't run the app directly.
    # In this specific lab, the provided `app.py` from the user already has this.
    app.run(port=5555, debug=True)

