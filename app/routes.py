from app import app, db, bcrypt, api, admin
from flask import jsonify, request, make_response
from flask_admin.contrib.sqla import ModelView
from flask_restful import Resource, reqparse
from app.models import User, Donor, Address, Beneficiary, Listings, Orders, Reviews
from functools import wraps
from flask import g
from werkzeug.utils import secure_filename
import os
import jwt
import datetime
import requests
from PIL import Image
from io import BytesIO
import base64


admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Donor, db.session))
admin.add_view(ModelView(Address, db.session))
admin.add_view(ModelView(Beneficiary, db.session))
admin.add_view(ModelView(Listings, db.session))
admin.add_view(ModelView(Orders, db.session))
admin.add_view(ModelView(Reviews, db.session))


ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    u = User(first_name=user.get('first_name'), info=user.get('info'))
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'user added to database'})


@app.route('/users', methods=['GET'])
# @token_required
def users():
    users = User.query.all()
    users_list = []
    for user in users:
        d = {'first_name': user.first_name, 'info': user.info, 'id': user.id}
        users_list.append(d)
    return jsonify({'users': users_list})


def username_in_database_donor(username):
    username = Donor.query.filter_by(username=username).first()
    return username


def username_in_database_beneficiary(username):
    username = Beneficiary.query.filter_by(username=username).first()
    return username


# TODO: also add address support on all routes.
@app.route('/donor', methods=['POST'])
def createdonor():
    """
    @api {post} /donor add a new donor
    @apiVersion 1.0.0
    @apiName createdonor
    @apiGroup Donor
    @apiParam {String}      first_name      The first name of the Donor.
    @apiParam {String}      last_name       the last name of the Donor.
    @apiParam {String}      email           email of Donor.
    @apiParam {String}      phone_no        phone number of Donor
    @apiParam {String}      password        password of Donor
    @apiSuccess {String}    message         donor added to database
    """
    donor = request.json
    if not donor:
        return "not json"
    print(donor)
    check_donor = Donor.query.filter_by(email=donor.get('email')).first()
    if check_donor:
        return jsonify({'message': 'Donor with that email already exists!'})
    password_hash = bcrypt.generate_password_hash(
        donor.get('password')).decode('utf-8')
    username = donor.get('email').split('@')[0]
    check_username = username_in_database_donor(username)
    if check_username:
        while check_username:
            username = username+'1'
            check_username = username_in_database_donor(username)
    print(username)
    u = Donor(first_name=donor.get('first_name'), last_name=donor.get('last_name'), email=donor.get('email'), phone_no=donor.get('phone_no'), username=username,
              password_hash=password_hash, organisation=donor.get('organisation'))
    # if donor.get('address'):
    print(donor.get('hello'))
    address = Address(donor=u, city=donor.get('city'), street=donor.get(
        'street'), country=donor.get('country'), landmark=donor.get('landmark'))
    print(address.city)
    db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'Donor added to database'})


@app.route('/donors', methods=['GET'])
def donors():
    """
    @api {get} /donors Display all donors
    @apiVersion 1.0.0
    @apiName donors
    @apiGroup Donor
    @apiDescription Display all donors
    @apiSuccess {Number}    id              The donors's id.
    @apiSuccess {String}    username        The donors's username.
    @apiSuccess {String}    first_name      The first name of the donor.
    @apiSuccess {String}    last_name       The last name of the donor.
    @apiSuccess {String}    password_hash   password_hash of the user
    @apiSuccess {Number}    email           email of donor
    @apiSuccess {Number}    phone_no        phone_no of donor
    """
    donors = Donor.query.all()
    donor_list = []
    for donor in donors:
        address = Address.query.filter_by(donor=donor).first()
        print(address)
        if address:
            d = {'first_name': donor.first_name, 'last_name': donor.last_name, 'password_hash': donor.password_hash, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username, 'city': address.city, 'country': address.country,
                 'street': address.street, 'landmark': address.landmark, 'organisation': donor.organisation}
        else:
            d = {'first_name': donor.first_name, 'last_name': donor.last_name, 'password_hash': donor.password_hash, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username}
        donor_list.append(d)
    return jsonify({'donors': donor_list})


@app.route('/beneficiaries', methods=['GET'])
def beneficiaries():
    """
    @api {get} /beneficiaries Display all beneficiaries
    @apiVersion 1.0.0
    @apiName get_beneficiary
    @apiGroup Beneficiary
    @apiDescription Display all beneficiaries
    @apiSuccess {Number}    id              The beneficiary's id.
    @apiSuccess {String}    username        The beneficiary's username.
    @apiSuccess {String}    first_name      The first name of the beneficiary.
    @apiSuccess {String}    last_name       The last name of the beneficiary.
    @apiSuccess {String}    password_hash   password_hash of the beneficiary
    @apiSuccess {Number}    email           email of beneficiary
    @apiSuccess {Number}    phone_no        phone_no of beneficiary
    """
    beneficiaries = Beneficiary.query.all()
    beneficiaries_list = []
    for beneficiary in beneficiaries:
        address = Address.query.filter_by(beneficiary=beneficiary).first()
        print(address)
        if address:
            d = {'first_name': beneficiary.first_name, 'last_name': beneficiary.last_name, 'password_hash': beneficiary.password_hash, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username, 'city': address.city, 'country': address.country,
                 'street': address.street, 'landmark': address.landmark}
        else:
            d = {'first_name': beneficiary.first_name, 'last_name': beneficiary.last_name, 'password_hash': beneficiary.password_hash, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username}
        beneficiaries_list.append(d)
    return jsonify({'beneficiaries': beneficiaries_list})


@app.route('/beneficiary', methods=['POST'])
def createbeneficiary():
    """
    @api {post} /beneficiary Add a new beneficiary
    @apiVersion 1.0.0
    @apiName createbeneficiary
    @apiGroup Beneficiary
    @apiParam {String}      first_name      The first name of the Beneficiary.
    @apiParam {String}      last_name       the last name of the Beneficiary.
    @apiParam {String}      email           email of Beneficiary.
    @apiParam {String}      phone_no        phone number of Beneficiary
    @apiParam {String}      password        password of Beneficiary
    """
    beneficiary = request.json
    if not beneficiary:
        return "not json"
    print(beneficiary)
    check_beneficiary = Beneficiary.query.filter_by(
        email=beneficiary.get('email')).first()
    print(check_beneficiary)
    if check_beneficiary:
        return jsonify({'message': 'beneficiary with that email already exists'})
    password_hash = bcrypt.generate_password_hash(
        beneficiary.get('password')).decode('utf-8')
    username = beneficiary.get('email').split('@')[0]
    check_username = username_in_database_beneficiary(username)
    if check_username:
        while check_username:
            username = username+'1'
            check_username = username_in_database_beneficiary(username)
    print(username)
    u = Beneficiary(first_name=beneficiary.get('first_name'), last_name=beneficiary.get('last_name'), email=beneficiary.get('email'), phone_no=beneficiary.get('phone_no'), username=username,
                    password_hash=password_hash, type=1)
    # if beneficiary.get('address'):
    address = Address(beneficiary=u, city=beneficiary.get(
        'city'), street=beneficiary.get('street'), country=beneficiary.get('country'), landmark=beneficiary.get('landmark'))
    db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'beneficiary added to database'})


class Login(Resource):
    def get(self):
        return {"hi": "testing"}

    def post(self):
        """
        @api {post} /login get jwt token 
        @apiVersion 1.0.0
        @apiName Login
        @apiGroup Login
        @apiParam {String}      type            if user is 'donor' or 'beneficiary'
        @apiParam {Object}      email           email of user
        @apiParam {Object}      password        password of user   
        @apiSuccess {Number}    token           jwt token
        """

        user_data = request.json
        if not user_data:
            return {"not": "json"}
        if user_data.get('type') == 'beneficiary':
            user = Beneficiary.query.filter_by(
                email=user_data.get('email')).first()
            organisation = ""
            type = 'beneficiary'
        else:
            user = Donor.query.filter_by(email=user_data.get('email')).first()
            organisation = user.organisation
            type = 'donor'
        if user and bcrypt.check_password_hash(user.password_hash, user_data.get('password')):
            token = jwt.encode(
                {'username': user.username, 'first_name': user.first_name, 'organisation': organisation, 'last_name': user.last_name, 'type': type, 'id': user.id,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
                app.config['SECRET_KEY'])
            return {'token': token.decode('UTF-8')}
        else:
            return None


class Listing(Resource):
    def get(self):
        send_all = request.args.get("send_all")
        if send_all == "0":
            listings = Listings.query.all()
            listing_list = []
            # listing_dict = {}
            for listing in listings:
                donor = Donor.query.get(listing.donor_id)
                address = Address.query.filter_by(
                    donor_id=listing.donor_id).first()
                if listing.quantity == None:
                    continue
                if listing.quantity < 1:
                    continue
                l = {"listing_id": listing.id,
                     "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                     "type": listing.type, "image": listing.image, "donor_id": listing.donor_id, "street": address.street,
                     "landmark": address.landmark, "city": address.city, "country": address.country, 'organisation': donor.organisation}
                listing_list.append(l)
            return {"listing": listing_list}

        elif send_all == "1":
            listings = Listings.query.all()
            # listing_list = []
            listing_dict = {}
            for listing in listings:
                donor = Donor.query.get(listing.donor_id)
                address = Address.query.filter_by(
                    donor_id=listing.donor_id).first()
                # if listing.quantity < 1:
                #     continue
                listing_dict[listing.id] = {"listing_id": listing.id,
                                            "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                                            "type": listing.type, "image": listing.image, "donor_id": listing.donor_id, "street": address.street,
                                            "landmark": address.landmark, "city": address.city, "country": address.country, 'organisation': donor.organisation}
                # listing_list.append(l)
        # print(listing_list)
        # return {"listing": listing_list}
            return listing_dict
        else:
            return {"message": "send_all not given"}, 403
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
        print(token_data.get('first_name'))
        donor = Donor.query.filter_by(
            username=token_data.get('username')).first()
        print(listing)
        print(donor.first_name)
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
            l = {"donor_id": order.donor_id,
                 "beneficiary_id": order.beneficiary_id,
                 "listing_id": order.lising_id,
                 "quantity": order.quantity,
                 "time_stamp": order.time_stamp}
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

# {	"time_stamp": "1324",
#     "orders":[
#     	 {
#         "product":{
#           "donor_id": 1,
#           "listing_id": 3
#         },
#         "quantity": 3
#       },

#     	 {
#         "product":{
#           "donor_id": 1,
#           "listing_id": 3
#         },
#         "quantity": 3
#       }
#     ]
# }


# {	"time_stamp": "1324",
#     "orders":[
#     	"",
#     	{
#         "product":{
#           "donor_id": 1,
#           "listing_id": 1
#         },
#         "quantity": 1
#       },
#       {
#         "product":{
#           "donor_id": 1,
#           "listing_id": 2
#         },
#         "quantity": 1
#       }
# 	]
# }

    @token_required
    def post(self):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        json_data = request.json
        print(json_data)
        if not json_data:
            return {"not": "json"}
        orders = json_data.get('orders')
        print(orders)
        for i in range(0, len(orders)):
            if orders[i] is None:
                continue
            order = orders[i].get('product')
            print(order)
            donor = Donor.query.get(order.get('donor_id'))
            beneficiary_username = token_data.get("username")
            beneficiary = Beneficiary.query.filter_by(
                username=beneficiary_username).first()
            if not beneficiary:
                return {'message': 'beneficiary not found', 'username': beneficiary_username}

            listing = Listings.query.get(order.get('listing_id'))
            quantity = orders[i].get('quantity')
            if quantity < 0:
                return {'message': 'listing quantity less than 0'}
            print(quantity)
            listing.quantity -= int(quantity)
            if listing.quantity < 0:
                return {'message': 'quantity more than stock'}
            o = Orders(donor=donor, beneficiary_id=beneficiary.id,
                       listing=listing, quantity=quantity, time_stamp=json_data.get('time_stamp'))
            db.session.add(o)
            db.session.commit()

        # donor = Donor.query.get(order.get('donor_id'))
        # beneficiary_username = token_data.get("username")
        # beneficiary = Beneficiary.query.filter_by(
        #     username=beneficiary_username).first()
        # listing = Listings.query.get(order.get('listing_id'))
        # listing.quantity -= quantity
        # o = Orders(donor=donor, beneficiary=beneficiary,
        #            listing=listing, quantity=quantity, time_stamp=order.get('time_stamp'))
        # db.session.add(o)
        # db.session.commit()
        return {"message": "Your order has been placed."}


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
        # db.session.delete(listing)
        listing.quantity = 0
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
            address = Address.query.filter_by(donor_id=user.id).first()
            u = {'first_name': user.first_name, 'last_name': user.last_name, 'password_hash': user.password_hash, 'id': user.id, 'phone_no': user.phone_no,
                 'email': user.email, 'username': user.username, 'organisation': user.organisation, 'street': address.street, 'landmark': address.landmark,
                 'city': address.city, 'country': address.country}
        elif type == 'beneficiary':
            user = Beneficiary.query.filter_by(username=username).first()
            address = Address.query.filter_by(beneficiary_id=user.id).first()
            u = {'first_name': user.first_name, 'last_name': user.last_name, 'password_hash': user.password_hash, 'id': user.id, 'phone_no': user.phone_no,
                 'email': user.email, 'username': user.username, 'street': address.street, 'landmark': address.landmark,
                 'city': address.city, 'country': address.country}

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
            user.organisation = updated_user.get('organisation')
            address = Address.query.filter_by(donor_id=user.id).first()
            check_username = Donor.query.filter_by(
                username=updated_user['username']).first()
            if check_username:
                if check_username.id != user.id:
                    return {'token': token, 'message': 0}
        elif type == 'beneficiary':
            user = Beneficiary.query.filter_by(username=username).first()
            address = Address.query.filter_by(beneficiary_id=user.id).first()
            check_username = Beneficiary.query.filter_by(
                username=updated_user['username']).first()
            if check_username.id != user.id:
                return {'token': token, 'message': 0}

        # u = {'name': user.name, 'password_hash': user.password_hash, 'id': user.id, 'phone_no': user.phone_no,
        #      'email': user.email, 'username': user.username}
        address.street = updated_user.get('street')
        address.city = updated_user.get('city')
        address.landmark = updated_user.get('landmark')
        address.country = updated_user.get('country')
        user.first_name = updated_user.get('first_name')
        user.last_name = updated_user.get('last_name')
        user.phone_no = updated_user.get('phone_no')
        user.username = updated_user.get('username')
        db.session.commit()
        token = jwt.encode(
            {'username': user.username, 'first_name': user.first_name, 'type': type, 'id': user.id,
             'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
            app.config['SECRET_KEY'])
        return {'token': token.decode('UTF-8'), 'message': 1}


# class Order
class BeneficiaryOrders(Resource):
    @token_required
    def get(self):
        """
        @api {get} /beneficiary/orders Display all orders of beneficiary
        @apiVersion 1.0.0
        @apiName beneficiaryorders
        @apiGroup Beneficiary

        @apiSuccess {Integer} donor_id           donor id
        @apiSuccess {Integer} beneficiary_id     beneficiary id
        @apiSuccess {Integer} listing_id         listing id
        @apiSuccess {String} quantity            quantity of listing.
        @apiSuccess {String} time_stamp          time stamp.
        @apiSuccess {String} street              street(address)
        @apiSuccess {String} landmark            landmark(address)
        @apiSuccess {String} city                city(address)
        @apiSuccess {String} country             country(address)
        @apiSuccess {String} image               image url
        @apiSuccess {String} description         description of listing

        @apiSuccessExample Success-Response:
            HTTP/1.1 200 OK
            {
                "firstname": "John",
                "lastname": "Doe"
            }

        @apiError UserNotFound The id of the User was not found.

        @apiErrorExample Error-Response:
            HTTP/1.1 404 Not Found
            {
                "error": "UserNotFound"
            }
        """
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        beneficiary = Beneficiary.query.filter_by(username=username).first()
        orders = Orders.query.filter_by(beneficiary_id=beneficiary.id)
        order_list = []
        #address, url, description, organisation
        for order in orders:
            address = Address.query.filter_by(donor_id=order.donor_id).first()
            listing = Listings.query.get(order.listing_id)
            l = {
                "donor_id": order.donor_id,
                "beneficiary_id": order.beneficiary_id,
                "listing_id": order.listing_id,
                "quantity": order.quantity,
                "time_stamp": order.time_stamp,
                "street": address.street,
                "landmark": address.landmark,
                "city": address.city,
                "country": address.country,
                "image": listing.image,
                "description": listing.description
            }
            print(l)
            order_list.append(l)
        # print(order_list)
        order_list.reverse()
        return {"orders": order_list}


class DonorOrders(Resource):
    @token_required
    def get(self):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        donor = Donor.query.filter_by(username=username).first()
        orders = Orders.query.filter_by(donor_id=donor.id).all()
        order_list = []
        for order in orders:
            address = Address.query.filter_by(donor_id=order.donor_id).first()
            listing = Listings.query.get(order.listing_id)
            l = {"donor_id": order.donor_id,
                 "beneficiary_id": order.beneficiary_id,
                 "listing_id": order.listing_id,
                 "quantity": order.quantity,
                 "time_stamp": order.time_stamp,
                 "street": address.street,
                 "landmark": address.landmark,
                 "city": address.city,
                 "country": address.country,
                 "image": listing.image,
                 "description": listing.description,
                 "organisation": donor.organisation}
            print(l)
            order_list.append(l)
        print(order_list)
        return {"orders": order_list}


# randomize the image filename
class UploadImage(Resource):
    def post(self):
        # check if the post request has the file part
        if 'file' not in request.files:
            return {"message": "No file sent"}
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return {'massage': 'No selected file'}
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(app.root_path, filename)
            file.save(path)
            url = upload_to_imgur(path)
            return {"url": url}
        # file.save(path)
        # returnoutput = BytesIO()
# im = Image.open('image.jpg')
# im.save(output, format='JPEG')
# im_data = output.getvalue()
# e64 = base64.b64encode(im_data)
# #print(e64)
# url = 'https://api.imgur.com/3/image'
# payload = {'image': e64}
# files = {}
# headers = {
#     'Authorization': 'Client-ID b24245cb0505c2c'
# }
# response = requests.request(
#     'POST', url, headers=headers, data=payload, files=files, allow_redirects=False)
# # print(response.json())

# content = response.json()
# url = content.get('data').get('link')
# print(url)

# {'message': 'hello'}
        # content = request.headers.get('image')
        # # content = request.json
        # print(content)
        # # return {"content": content}


def upload_to_imgur(path):
    output = BytesIO()
    im = Image.open(path)
    im.save(output, format='JPEG')
    im_data = output.getvalue()
    base_64 = base64.b64encode(im_data)
    os.remove(path)
    url = 'https://api.imgur.com/3/image'
    payload = {'image': base_64}
    files = {}
    headers = {
    'Authorization': 'Client-ID b24245cb0505c2c'
    }
    response = requests.request('POST', url, headers=headers, data=payload, files=files, allow_redirects=False)
    print(response.text)
    content = response.json()
    url = content.get('data').get('link')
    print(url)
    return url

# output = BytesIO()
# im = Image.open('image.jpg')
# im.save(output, format='JPEG')
# im_data = output.getvalue()
# e64 = base64.b64encode(im_data)
# #print(e64)
# url = 'https://api.imgur.com/3/image'
# payload = {'image': e64}
# files = {}
# headers = {
#     'Authorization': 'Client-ID b24245cb0505c2c'
# }
# response = requests.request(
#     'POST', url, headers=headers, data=payload, files=files, allow_redirects=False)
# # print(response.json())

# content = response.json()
# url = content.get('data').get('link')
# print(url)


api.add_resource(Login, '/login')
api.add_resource(Listing, '/listing')
api.add_resource(Order, '/order')
api.add_resource(DonorListings, '/donorlistings')
api.add_resource(SingleListing, '/singlelisting')
api.add_resource(UpdateListing, '/updatelisting')
api.add_resource(DeleteListing, '/deletelisting')
api.add_resource(Profile, '/user')
api.add_resource(UpdateUser, '/user/update')
api.add_resource(BeneficiaryOrders, '/beneficiary/orders')
api.add_resource(DonorOrders, '/donor/orders')
api.add_resource(UploadImage, '/uploadimage')


# /order -> orders of beneficiary. also add datestamp to the database.[done]
# /check_out route -> delete the quantity. also remove the products which has zero quantity.[done]
# remove those listings which have 0 quantity
# add address support. also send it to products and my products.
# add image api. image from front-end and return url.
# notification to donor {later}
