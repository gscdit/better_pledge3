from app import app, db, bcrypt, api, admin
from flask import jsonify, request, make_response
from flask_admin.contrib.sqla import ModelView
from flask_restful import Resource
from app.models import User, Donor, Address, Beneficiary, Listings, Orders, Reviews
from functools import wraps
from flask import g
import jwt
import datetime

admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Donor, db.session))
admin.add_view(ModelView(Address, db.session))
admin.add_view(ModelView(Beneficiary, db.session))
admin.add_view(ModelView(Listings, db.session))
admin.add_view(ModelView(Orders, db.session))
admin.add_view(ModelView(Reviews, db.session))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if auth and auth.username == 'username' and auth.password == 'passwor':
            return f(*args, **kwargs)

        return make_response('Could not verify your login!', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    return decorated


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return {'message': 'Token is missing!'}, 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Beneficiary.query.filter_by(
                username=data['username']).first()
        except:
            return {'message': 'Token is invalid!'}, 403

        return f(*args, **kwargs)

    return decorated


@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Welcome to the api'})


@app.route('/createuser', methods=['POST'])
def create():
    user = request.json
    print(user)
    u = User(name=user.get('name'), info=user.get('info'))
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'user added to database'})


@app.route('/users', methods=['GET'])
# @token_required
def users():
    users = User.query.all()
    users_list = []
    for user in users:
        d = {'name': user.name, 'info': user.info, 'id': user.id}
        users_list.append(d)
    return jsonify({'users': users_list})


def username_in_database_donor(username):
    username = Donor.query.filter_by(username=username).first()
    return username


def username_in_database_beneficiary(username):
    username = Beneficiary.query.filter_by(username=username).first()
    return username


@app.route('/donor', methods=['POST'])
def createdonor():
    donor = request.json
    if not donor:
        return "not json"
    print(donor)
    password_hash = bcrypt.generate_password_hash(
        donor.get('password')).decode('utf-8')
    username = donor.get('email').split('@')[0]
    check_username = username_in_database_donor(username)
    if check_username:
        while check_username:
            username = username+'1'
            check_username = username_in_database_donor(username)
    print(username)
    u = Donor(name=donor.get('name'), email=donor.get('email'), phone_no=donor.get('phone_no'), username=username,
              password_hash=password_hash)
    if donor.get('address'):
        address = Address(donor=u, city=donor.get('city'), street=donor.get(
            'street'), country=donor.get('country'))
        db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'donor added to database'})


@app.route('/donors', methods=['GET'])
def donors():
    donors = Donor.query.all()
    donor_list = []
    for donor in donors:
        address = Address.query.filter_by(donor=donor).first()
        print(address)
        if address:
            d = {'name': donor.name, 'password_hash': donor.password_hash, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username, 'city': address.city, 'country': address.country,
                 'street': address.street}
        else:
            d = {'name': donor.name, 'password_hash': donor.password_hash, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username}
        donor_list.append(d)
    return jsonify({'donors': donor_list})


@app.route('/beneficiaries', methods=['GET'])
def beneficiaries():
    beneficiaries = Beneficiary.query.all()
    beneficiaries_list = []
    for beneficiary in beneficiaries:
        address = Address.query.filter_by(beneficiary=beneficiary).first()
        print(address)
        if address:
            d = {'name': beneficiary.name, 'password_hash': beneficiary.password_hash, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username, 'city': address.city, 'country': address.country,
                 'street': address.street}
        else:
            d = {'name': beneficiary.name, 'password_hash': beneficiary.password_hash, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username}
        beneficiaries_list.append(d)
    return jsonify({'beneficiaries': beneficiaries_list})


@app.route('/beneficiary', methods=['POST'])
def createbeneficiary():
    beneficiary = request.json
    if not beneficiary:
        return "not json"
    print(beneficiary)
    password_hash = bcrypt.generate_password_hash(
        beneficiary.get('password')).decode('utf-8')
    username = beneficiary.get('email').split('@')[0]
    check_username = username_in_database_beneficiary(username)
    if check_username:
        while check_username:
            username = username+'1'
            check_username = username_in_database_beneficiary(username)
    print(username)
    u = Beneficiary(name=beneficiary.get('name'), email=beneficiary.get('email'), phone_no=beneficiary.get('phone_no'), username=username,
                    password_hash=password_hash, type=1)
    if beneficiary.get('address'):
        address = Address(beneficiary=u, city=beneficiary.get(
            'city'), street=beneficiary.get('street'), country=beneficiary.get('country'))
        db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'beneficiary added to database'})


class Login(Resource):
    def get(self):
        return {"hi": "testing"}

    def post(self):
        user_data = request.json
        if not user_data:
            return {"not": "json"}
        if user_data.get('type') == 'beneficiary':
            user = Beneficiary.query.filter_by(
                email=user_data.get('email')).first()
            type = 'beneficiary'
        else:
            user = Donor.query.filter_by(email=user_data.get('email')).first()
            type = 'donor'
        if user and bcrypt.check_password_hash(user.password_hash, user_data.get('password')):
            token = jwt.encode(
                {'username': user.username, 'name': user.name, 'type': type, 'id': user.id,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
                app.config['SECRET_KEY'])
            return {'token': token.decode('UTF-8')}
        else:
            return None


class Listing(Resource):
    def get(self):
        listings = Listings.query.all()
        listing_list = []
        for listing in listings:
            l = {"listing_id": listing.id,
                 "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                 "type": listing.type, "image": listing.image, "donor_id": listing.donor_id}
            listing_list.append(l)
        print(listing_list)
        return {"listing": listing_list}
    #
    # quantity = db.Column(db.Integer)
    # expiry = db.Column(db.String(20))
    # description = db.Column(db.String(250))
    # type = db.Column(db.String(10))
    # image = db.Column(db.String(100))

    @token_required
    def post(self):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        listing = request.json
        if not listing:
            return {"not": "json"}
        print(token_data.get('name'))
        donor = Donor.query.filter_by(
            username=token_data.get('username')).first()
        print(listing)
        print(donor.name)
        print(donor.id)
        # print(donor.username, "xxx")
        l = Listings(quantity=listing.get('quantity'), expiry=listing.get('expiry'),
                     description=listing.get('description'), type=listing.get('type'),
                     image=listing.get('image'), donor_id=donor.id)
        db.session.add(l)
        db.session.commit()
        return {"listing": "added"}


class Order(Resource):
    def get(self):
        orders = Orders.query.all()
        print(orders)
        order_list = []
        for order in orders:
            l = {"donor": order.donor.name,
                 "beneficiary": order.beneficiary.name}
            print(l)
            order_list.append(l)
        print(order_list)
        return {"orders": order_list}
    #
    # quantity = db.Column(db.Integer)
    # expiry = db.Column(db.String(20))
    # description = db.Column(db.String(250))
    # type = db.Column(db.String(10))
    # image = db.Column(db.String(100))

    @token_required
    def post(self):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        order = request.json
        if not order:
            return {"not": "json"}
        donor = Donor.query.get(order.get('donor_id'))
        beneficiary = Beneficiary.query.filter_by(
            username=order.get('beneficiary_username')).first()
        listing = Listings.query.get(order.get('listing_id'))
        o = Orders(donor=donor, beneficiary=beneficiary, listing=listing)
        db.session.add(o)
        db.session.commit()
        return {"orders": "added"}


class DonorListings(Resource):
    #    def post(self):
    #        return {"testing": "donorlistings"}

    @token_required
    def get(self):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        donor = Donor.query.filter_by(username=username).first()
        listings = Listings.query.filter_by(donor_id=donor.id).all()
        parsed_listings = []
        d = dict()
        # first parsing individual listings. overcomes object 'Listings' cannot be jsonify.
        for listing in listings:
            l = {"listing_id": listing.id,
                 "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                 "type": listing.type, "image": listing.image, "donor_id": listing.donor_id}
            parsed_listings.append(l)

        count = 0
        all_listings = []
        print(listings)
        # giving structure
        for listings in parsed_listings:
            d[count] = listings
            print(listings)
            all_listings.append(d)
            d = {}
            count = count + 1
        print(all_listings)
        print(jsonify(all_listings))
        return {"listings": all_listings}


class SingleListing(Resource):
    def get(self):
        listing_id = request.args.get("listing_id")
        if not listing_id:
            return {"listing_id": listing_id}
        listing = Listings.query.get(listing_id)
        if not listing:
            return {"no listing available": "with that listing_id"}
        return {"listing_id": listing.id,
                "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                "type": listing.type, "image": listing.image, "donor_id": listing.donor_id}


class UpdateListing(Resource):
    def post(self):
        # don't know why headers is not working on deployed version. will probably look later.
        listing_id = request.args.get("listing_id")
        update_listing = request.json
        if not listing_id:
            return {"listing_id": "not received"}
        listing = Listings.query.get(listing_id)
        if not listing:
            return {"no listing available": "with that listing_id"}
        listing.quantity = update_listing.get("quantity")
        listing.description = update_listing.get("description")
        listing.expiry = update_listing.get("expiry")
        listing.type = update_listing.get("type")
        listing.image = update_listing.get("image")
        listing.description = update_listing.get("description")
        db.session.commit()
        return {"listing": "updated"}


class DeleteListing(Resource):
    # very prone to exploitation. anyone can delete anything.
    @token_required
    def post(self):
        listing_id = request.args.get("listing_id")
        if not listing_id:
            return {"listing_id": listing_id}
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        donor = Donor.query.filter_by(username=username).first()
        donor_listings = Listings.query.filter_by(donor_id=donor.id).all()
        # Listings.query.filter_by(id=listing_id).delete()
        listing = Listings.query.filter_by(id=listing_id).first()
        if not listing:
            return {"no listing available": "with that listing_id"}
        if listing not in donor_listings:
            return {"permission": "denied"}
        print(listing.description)
        db.session.delete(listing)
        db.session.commit()
        return {"listing": "deleted"}


class Profile(Resource):
    @token_required
    def get(self):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        type = token_data.get('type')
        username = token_data.get("username")
        if type == 'donor':
            user = Donor.query.filter_by(username=username).first()
        elif type == 'beneficiary':
            user = Beneficiary.query.filter_by(username=username).first()

        u = {'name': user.name, 'password_hash': user.password_hash, 'id': user.id, 'phone_no': user.phone_no,
             'email': user.email, 'username': user.username}

        return {'user': u}


# TODO: update address too
class UpdateUser(Resource):
    @token_required
    def post(self):
        updated_user = request.json
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        type = token_data.get('type')
        username = token_data.get("username")
        if type == 'donor':
            user = Donor.query.filter_by(username=username).first()
            check_username = Donor.query.filter_by(username=updated_user['username']).first()
            if check_username:
                if check_username.id != user.id:
                    return {'message': 'username already exist'}
        elif type == 'beneficiary':
            user = Beneficiary.query.filter_by(username=username).first()
            check_username = Beneficiary.query.filter_by(username=updated_user['username']).first()
            if check_username.id != user.id:
                return {'message': 'username already exist'}
 
        # u = {'name': user.name, 'password_hash': user.password_hash, 'id': user.id, 'phone_no': user.phone_no,
        #      'email': user.email, 'username': user.username}

        user.name = updated_user.get('name')
        user.phone_no = updated_user.get('phone_no')
        user.username = updated_user.get('username')
        db.session.commit()
        token = jwt.encode(
                {'username': user.username, 'name': user.name, 'type': type, 'id': user.id,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
                app.config['SECRET_KEY'])
        return {'token': token.decode('UTF-8')}



api.add_resource(Login, '/login')
api.add_resource(Listing, '/listing')
api.add_resource(Order, '/order')
api.add_resource(DonorListings, '/donorlistings')
api.add_resource(SingleListing, '/singlelisting')
api.add_resource(UpdateListing, '/updatelisting')
api.add_resource(DeleteListing, '/deletelisting')
api.add_resource(Profile, '/user')
api.add_resource(UpdateUser, '/user/update')
