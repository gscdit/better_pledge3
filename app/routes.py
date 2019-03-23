from app import app, db, bcrypt, api, admin
from flask import jsonify, request
from flask_admin.contrib.sqla import ModelView
from flask_restful import Resource
from app.models import Donor, Address, Beneficiary, Listings, Orders, Reviews
from functools import wraps
from werkzeug.utils import secure_filename
import sendgrid
import os
import jwt
import datetime
import requests
from PIL import Image
from io import BytesIO
import base64


sg = sendgrid.SendGridAPIClient(apikey=app.config['SENDGRID_API_KEY'])


def send_mail(to_email, donor, beneficiary, listing):
    text = f"Hi {donor.first_name}, An order has been placed for your product of {listing.description} by "\
           f"{beneficiary.first_name} {beneficiary.last_name}."
    data = {
                "personalizations": [
                    {
                        "to": [
                            {
                                "email": to_email
                            }
                        ],
                        "subject": "Order placed for your product"
                    }
                ],
                "from": {
                    "email": app.config['SENDGRID_DEFAULT_FROM'],
                    "name": "BetterPledge"
                },
                "content": [
                    {
                        "type": "text/plain",
                        "value": text
                    }
                            ]
            }
    response = sg.client.mail.send.post(request_body=data)
    print(response.status_code)
    # print(response.body)
    # print(response.headers)


admin.add_view(ModelView(Donor, db.session))
admin.add_view(ModelView(Address, db.session))
admin.add_view(ModelView(Beneficiary, db.session))
admin.add_view(ModelView(Listings, db.session))
admin.add_view(ModelView(Orders, db.session))
admin.add_view(ModelView(Reviews, db.session))


ALLOWED_EXTENSIONS = set(['jpg', 'jpeg'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# TODO: add type to models and verify


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return {'message': 'Token is missing'}, 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            type = data['type']
            if type == 'donor':
                donor = Donor.query.filter_by(
                    username=data['username']).first()
                print(donor.first_name)
            elif type == 'beneficiary':
                beneficiary = Beneficiary.query.filter_by(
                    username=data['username']).first()
                print(beneficiary.first_name)
        except Exception:
            return {'message': 'Token is invalid'}, 403

        return f(*args, **kwargs)

    return decorated


@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Welcome to the api'})


def username_in_database_donor(username):
    username = Donor.query.filter_by(username=username).first()
    return username


def username_in_database_beneficiary(username):
    username = Beneficiary.query.filter_by(username=username).first()
    return username


@app.route('/donor', methods=['POST'])
def createdonor():
    """
    @api {post} /donor Add a new donor
    @apiVersion 1.0.0
    @apiName createdonor
    @apiGroup Donor

    @apiParam {String}      first_name      The first name of the Donor.
    @apiParam {String}      last_name       the last name of the Donor.
    @apiParam {String}      email           email of Donor.
    @apiParam {String}      phone_no        phone number of Donor.
    @apiParam {String}      password        password of Donor.
    @apiParam {String}      organisation    organisation of Donor.
    @apiParam {String}      city            city name(part of address)
    @apiParam {String}      street          street number(part of address)
    @apiParam {String}      landmark        landmark description(part of address)
    @apiParam {String}      country         country name(part of address)

    @apiSuccess {String}    message         donor added to database

    @apiError               message         Donor with that email already exists!
    @apiError               message[2]         address street not provided
    @apiError               message[3]         not json
    """
    donor = request.json
    if not donor:
        return jsonify({"message": "not json"}), 400
    if not donor.get("street"):
        return jsonify({"message": "address street not provided"}), 400
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
            username = username + '1'
            check_username = username_in_database_donor(username)
    u = Donor(first_name=donor.get('first_name'), last_name=donor.get('last_name'), email=donor.get('email'), phone_no=donor.get('phone_no'), username=username,
              password_hash=password_hash, organisation=donor.get('organisation'))
    address = Address(donor=u, city=donor.get('city'), street=donor.get(
        'street'), country=donor.get('country'), landmark=donor.get('landmark'))
    db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'Donor added to database'}), 200


@app.route('/donors', methods=['GET'])
def donors():
    """
    @api {get} /donors get all donors
    @apiVersion 1.0.0
    @apiName donors
    @apiGroup Donor

    @apiSuccess {Object[]}  donors                 Array of donor objects.
    @apiSuccess {Number}    donors.id              The donors's id.
    @apiSuccess {String}    donors.username        The donors's username.
    @apiSuccess {String}    donors.first_name      The first name of the donor.
    @apiSuccess {String}    donors.last_name       The last name of the donor.
    @apiSuccess {Number}    donors.email           email of donor.
    @apiSuccess {Number}    donors.phone_no        phone_no of donor.
    @apiSuccess {Number}    donors.city            city name.
    @apiSuccess {Number}    donors.street          street number/name.
    @apiSuccess {Number}    donors.landmark        landmark description.
    @apiSuccess {Number}    donors.country         country name.
    @apiSuccess {Number}    donors.organisation    organisation name.

    """
    donors = Donor.query.all()
    donor_list = []
    for donor in donors:
        address = Address.query.filter_by(donor=donor).first()
        if address:
            d = {'first_name': donor.first_name, 'last_name': donor.last_name, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username, 'city': address.city, 'country': address.country,
                 'street': address.street, 'landmark': address.landmark, 'organisation': donor.organisation}
        else:
            d = {'first_name': donor.first_name, 'last_name': donor.last_name, 'password_hash': donor.password_hash, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username}
        donor_list.append(d)
    return jsonify({'donors': donor_list}), 200


@app.route('/beneficiaries', methods=['GET'])
def beneficiaries():
    """
    @api {get} /beneficiaries get all beneficiaries
    @apiVersion 1.0.0
    @apiName beneficiaries
    @apiGroup Beneficiary

    @apiSuccess {Object[]}  beneficiaries                 Array of beneficiary objects.
    @apiSuccess {Number}    beneficiaries.id              The beneficiary's id.
    @apiSuccess {String}    beneficiaries.username        The beneficiary's username.
    @apiSuccess {String}    beneficiaries.first_name      The first name of the beneficiary.
    @apiSuccess {String}    beneficiaries.last_name       The last name of the beneficiary.
    @apiSuccess {Number}    beneficiaries.email           email of beneficiary
    @apiSuccess {Number}    beneficiaries.phone_no        phone_no of beneficiary
    @apiSuccess {Number}    beneficiaries.city            city name.
    @apiSuccess {Number}    beneficiaries.street          street number/name.
    @apiSuccess {Number}    beneficiaries.landmark        landmark description.
    @apiSuccess {Number}    beneficiaries.country         country name.
    """

    beneficiaries = Beneficiary.query.all()
    beneficiaries_list = []
    for beneficiary in beneficiaries:
        address = Address.query.filter_by(beneficiary=beneficiary).first()
        if address:
            d = {'first_name': beneficiary.first_name, 'last_name': beneficiary.last_name, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username, 'status': beneficiary.status, 'city': address.city, 'country': address.country,
                 'street': address.street, 'landmark': address.landmark}
        else:
            d = {'first_name': beneficiary.first_name, 'last_name': beneficiary.last_name, 'password_hash': beneficiary.password_hash, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username, 'status': beneficiary.status}
        beneficiaries_list.append(d)
    return jsonify({'beneficiaries': beneficiaries_list}), 200


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
    @apiParam {String}      city            city name(part of address)
    @apiParam {String}      street          street number(part of address)
    @apiParam {String}      landmark        landmark description(part of address)
    @apiParam {String}      country         country name(part of address)

    @apiSuccess {String}    message         beneficiary added to database

    @apiError               message         beneficiary with that email already exists
    @apiError               message[2]         address street not provided
    @apiError               message[3]         not json
    """
    beneficiary = request.json
    if not beneficiary:
        return jsonify({"message": "not json"}), 400
    check_beneficiary = Beneficiary.query.filter_by(
        email=beneficiary.get('email')).first()
    if check_beneficiary:
        return jsonify({'message': 'beneficiary with that email already exists'})
    password_hash = bcrypt.generate_password_hash(
        beneficiary.get('password')).decode('utf-8')
    username = beneficiary.get('email').split('@')[0]
    check_username = username_in_database_beneficiary(username)
    if check_username:
        while check_username:
            username = username + '1'
            check_username = username_in_database_beneficiary(username)
    u = Beneficiary(first_name=beneficiary.get('first_name'), last_name=beneficiary.get('last_name'), email=beneficiary.get('email'), phone_no=beneficiary.get('phone_no'), username=username,
                    password_hash=password_hash, type=1, status=0)
    address = Address(beneficiary=u, city=beneficiary.get(
        'city'), street=beneficiary.get('street'), country=beneficiary.get('country'), landmark=beneficiary.get('landmark'))
    db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'beneficiary added to database'}), 200


class Login(Resource):
    def post(self):
        """
        @api {post} /login get jwt token
        @apiVersion 1.0.0
        @apiName Login
        @apiGroup Login

        @apiParam {String}      type            'donor' or 'beneficiary'
        @apiParam {Object}      email           email of user
        @apiParam {Object}      password        password of user

        @apiSuccess {Number}    token           jwt token

        @apiError               message         not json
        """

        user_data = request.json
        if not user_data:
            return {"message": "not json"}, 400
        if user_data.get('type') == 'beneficiary':
            user = Beneficiary.query.filter_by(
                email=user_data.get('email')).first()
            organisation = ""
            type = 'beneficiary'
            status = user.status
        else:
            user = Donor.query.filter_by(email=user_data.get('email')).first()
            organisation = user.organisation
            type = 'donor'
            status = 1
        if user and bcrypt.check_password_hash(user.password_hash, user_data.get('password')):
            token = jwt.encode(
                {'username': user.username, 'first_name': user.first_name, 'status': status, 'organisation': organisation, 'last_name': user.last_name, 'type': type, 'id': user.id,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
                app.config['SECRET_KEY'])
            return {'token': token.decode('UTF-8')}, 200
        else:
            return None


class Listing(Resource):
    def get(self):
        """
        @api {get} /listing get all listing
        @apiVersion 1.0.0
        @apiName listing_get
        @apiGroup Listing

        @apiSuccess {Number}    listing_id      id of the listing.
        @apiSuccess {String}    quantity        listing quantity
        @apiSuccess {String}    description     listing description.
        @apiSuccess {String}    type            'veg' or 'non-veg'
        @apiSuccess {String}    image           image url
        @apiSuccess {String}    donor_id        id of donor
        @apiSuccess {String}    street          street number/name of donor
        @apiSuccess {String}    landmark        landmark description of donor address
        @apiSuccess {String}    city            city name of donor
        @apiSuccess {String}    country         country name of donor.
        @apiSuccess {String}    organisation    organisation name of donor

        @apiError               message         send_all not given
        """
        send_all = request.args.get("send_all")
        if send_all == "0":
            listings = Listings.query.all()
            listing_list = []
            for listing in listings:
                donor = Donor.query.get(listing.donor_id)
                address = Address.query.filter_by(
                    donor_id=listing.donor_id).first()
                if listing.quantity is None:
                    continue
                if listing.quantity < 1:
                    continue
                _list = {"listing_id": listing.id,
                         "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                         "type": listing.type, "phone_no": donor.phone_no, "image": listing.image, "donor_id": listing.donor_id, "street": address.street,
                         "landmark": address.landmark, "city": address.city, "country": address.country, 'organisation': donor.organisation}
                listing_list.append(_list)
            return {"listing": listing_list}, 200

        elif send_all == "1":
            listings = Listings.query.all()
            listing_dict = {}
            for listing in listings:
                donor = Donor.query.get(listing.donor_id)
                address = Address.query.filter_by(
                    donor_id=listing.donor_id).first()
                # if listing.quantity < 1:
                #     continue
                listing_dict[listing.id] = {"listing_id": listing.id,
                                            "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                                            "type": listing.type, "phone_no": donor.phone_no, "image": listing.image, "donor_id": listing.donor_id, "street": address.street,
                                            "landmark": address.landmark, "city": address.city, "country": address.country, 'organisation': donor.organisation}
            return listing_dict
        else:
            return {"message": "send_all not given"}, 400

    @token_required
    def post(self):
        """
        @api {post} /listing Add a new listing
        @apiVersion 1.0.0
        @apiName listing_post
        @apiGroup Listing

        @apiParam {String}      quantity        quantity of the listing
        @apiParam {String}      description     description of the listing.
        @apiParam {String}      image           image url
        @apiParam {String}      type            'veg' or 'non veg'

        @apiSuccess {String}    message         listing added

        @apiError               message         not json
        @apiError               message[2]         token is missing
        @apiError               message[3]         token is invalid
        """
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        listing = request.json
        if not listing:
            return {"message": "not json"}, 400
        donor = Donor.query.filter_by(
            username=token_data.get('username')).first()
        # print(donor.username, "xxx")
        _list = Listings(quantity=listing.get('quantity'), expiry=listing.get('expiry'),
                         description=listing.get('description'), type=listing.get('type'),
                         image=listing.get('image'), donor_id=donor.id)
        db.session.add(_list)
        db.session.commit()
        return {"message": "listing added"}, 200


class Order(Resource):
    def get(self):
        """
        @api {get} /order get all orders
        @apiVersion 1.0.0
        @apiName order_get
        @apiGroup Order

        @apiSuccess {Number}    donor_id        id of donor.
        @apiSuccess {Number}    beneficiary_id  id of beneficiary.
        @apiSuccess {Number}    listing_id      id of listing.
        @apiSuccess {Number}    quantity        quantity of order.
        @apiSuccess {Number}    time_stamp      time stamp of order palcement.
        """
        orders = Orders.query.all()
        order_list = []
        for order in orders:
            _list = {"donor_id": order.donor_id,
                     "beneficiary_id": order.beneficiary_id,
                     "listing_id": order.listing_id,
                     "quantity": order.quantity,
                     "time_stamp": order.time_stamp}
            order_list.append(_list)
        print(order_list)
        return {"orders": order_list}, 200

    @token_required
    def post(self):
        """
        @api {post} /order Add a new order
        @apiVersion 1.0.0
        @apiName order_post
        @apiGroup Order

        @apiParam {String}      timestamp           time stamp of order placement
        @apiParam {Object[]}    orders              List of orders placed(Array of Objects)
        @apiParam {Number}      orders.product      order id
        @apiParam {Number}      orders.donor_id     donor id
        @apiParam {Number}      orders.listing_id   listing id
        @apiParam {Number}      orders.quantity     quantity of order.

        @apiSuccess {String}    message         Your order has been placed.

        @apiError               message         not json
        @apiError               message[2]         beneficiary not found
        @apiError               message[3]         listing quantity less than 0
        @apiError               message[4]         quantity more than stock
        @apiError               message[5]         token is missing
        @apiError               message[6]         token is invalid
        """
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        json_data = request.json
        if not json_data:
            return {"message": "not json"}, 400
        orders = json_data.get('orders')
        for i in range(0, len(orders)):
            if orders[i] is None:
                continue
            order = orders[i].get('product')
            donor = Donor.query.get(order.get('donor_id'))
            beneficiary_username = token_data.get("username")
            beneficiary = Beneficiary.query.filter_by(
                username=beneficiary_username).first()
            if not beneficiary:
                return {'message': 'beneficiary not found', 'username': beneficiary_username, "error": 1}, 400

            listing = Listings.query.get(order.get('listing_id'))
            quantity = orders[i].get('quantity')
            if quantity < 0:
                return {'message': 'listing quantity less than 0', "error": 1}, 400
            listing.quantity -= int(quantity)
            if listing.quantity < 0:
                return {'message': 'quantity more than stock', "error": 1}, 400
            o = Orders(donor=donor, beneficiary_id=beneficiary.id,
                       listing=listing, quantity=quantity, time_stamp=json_data.get('time_stamp'))
            db.session.add(o)
            db.session.commit()
            send_mail(to_email=donor.email, donor=donor,
                      beneficiary=beneficiary, listing=listing)
        return {"message": "Your order has been placed.", "error": 0}, 200


class DonorListings(Resource):
    @token_required
    def get(self):
        """
        @api {get} /donorlistings get all listings of donor
        @apiVersion 1.0.0
        @apiName donorlisting
        @apiGroup Listing

        @apiSuccess {Object[]}  listings                 All listing of donor(Array of Objects)
        @apiSuccess {Number}    listings.listing_id      id of listing
        @apiSuccess {Number}    listings.quantity        quantity of listing
        @apiSuccess {Number}    listings.donor_id        id of donor
        @apiSuccess {String}    listings.description     description of listing
        @apiSuccess {String}    listings.type            'veg' or 'non-veg'
        @apiSuccess {String}    listings.image           image url

        @apiError               message         token is missing
        @apiError               message[2]         token is invalid
        """
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        donor = Donor.query.filter_by(username=username).first()
        listings = Listings.query.filter_by(donor_id=donor.id).all()
        parsed_listings = []
        d = dict()
        # first parsing individual listings. overcomes object 'Listings' cannot be jsonify.
        for listing in listings:
            _list = {"listing_id": listing.id,
                     "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                     "type": listing.type, "image": listing.image, "donor_id": listing.donor_id}
            parsed_listings.append(_list)

        count = 0
        all_listings = []
        # giving structure
        for listings in parsed_listings:
            d[count] = listings
            print(listings)
            all_listings.append(d)
            d = {}
            count = count + 1
        return {"listings": all_listings}, 200


class SingleListing(Resource):
    def get(self):
        """
        @api {get} /singlelisting get single listing
        @apiVersion 1.0.0
        @apiName singlelisting
        @apiGroup Listing

        @apiParam {Number}      listing_id      id of listing(in args)

        @apiSuccess {Number}    listing_id      id of listing
        @apiSuccess {Number}    quantity        quantity of listing
        @apiSuccess {Number}    donor_id        id of donor
        @apiSuccess {String}    description     description of listing
        @apiSuccess {String}    type            'veg' or 'non-veg'
        @apiSuccess {String}    image           image url
        @apiSuccess {String}    street          street number/name of donor.
        @apiSuccess {String}    landmark        landmark description of donor.
        @apiSuccess {String}    city            city of donor.
        @apiSuccess {String}    country         country of donor.
        @apiSuccess {String}    organisation    organisation of donor.

        @apiError               message         no listing with that listing id
        @apiError               message[2]         no listing available with that listing_id
        """
        listing_id = request.args.get("listing_id")
        if not listing_id:
            return {"listing_id": listing_id}, 400
        listing = Listings.query.get(listing_id)
        if not listing:
            return {"message": "No listing available with that listing_id"}, 400
        donor = Donor.query.get(listing.donor_id)
        address = Address.query.filter_by(donor_id=listing.donor_id).first()
        return {"listing_id": listing.id, "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                "type": listing.type, "image": listing.image, "phone_no": donor.phone_no, "donor_id": listing.donor_id, "street": address.street,
                "landmark": address.landmark, "city": address.city, "country": address.country, 'organisation': donor.organisation}


class UpdateListing(Resource):
    @token_required
    def post(self):
        """
        @api {post} /updatelisting update listing info
        @apiVersion 1.0.0
        @apiName updatelisting
        @apiGroup Listing

        @apiParam {Number}      quantity        quantity of listing.
        @apiParam {String}      description     description of listing.
        @apiParam {String}      type            'veg' or 'non-veg'
        @apiParam {String}      image           image url

        @apiSuccess {String}    message         listing updated

        @apiError               message         listing_id not provided
        @apiError               message[2]         no listing available with that listing_id
        """
        listing_id = request.args.get("listing_id")
        update_listing = request.json
        if not listing_id:
            return {"message": "listing_id not provided"}, 400
        listing = Listings.query.get(listing_id)
        if not listing:
            return {"message": "no listing available with that listing_id"}, 400
        listing.quantity = update_listing.get("quantity")
        listing.description = update_listing.get("description")
        listing.expiry = update_listing.get("expiry")
        listing.type = update_listing.get("type")
        listing.image = update_listing.get("image")
        db.session.commit()
        return {"message": "listing updated"}, 200


class DeleteListing(Resource):
    @token_required
    def post(self):
        """
        @api {post} /deletelisting delete listing
        @apiVersion 1.0.0
        @apiName deletelisting
        @apiGroup Listing

        @apiParam {Number}      listing_id      listing id (in args)

        @apiSuccess {String}    message         listing deleted

        @apiError               message         no listing_id sent in args
        @apiError               message[2]         no listing available with that listing_id
        @apiError               message[3]         permission denied
        @apiError               message[4]         token is missing
        @apiError               message[5]         token is invalid

        """
        listing_id = request.args.get("listing_id")
        if not listing_id:
            return {"message": "no listing_id sent in args"}, 400
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        donor = Donor.query.filter_by(username=username).first()
        donor_listings = Listings.query.filter_by(donor_id=donor.id).all()
        # Listings.query.filter_by(id=listing_id).delete()
        listing = Listings.query.filter_by(id=listing_id).first()
        if not listing:
            return {"message": "no listing available with that listing_id"}, 400
        if listing not in donor_listings:
            return {"message": "permission denied"}, 400
        listing.quantity = 0
        db.session.commit()
        return {"message": "listing deleted"}, 200


class Profile(Resource):
    @token_required
    def get(self):
        """ 
        @api {get} /user get details of user
        @apiVersion 1.0.0
        @apiName profile
        @apiGroup User

        @apiParam   {String}    type            'donor' or 'beneficiary'

        @apiSuccess {Object}    user                 Object with user info.
        @apiSuccess {String}    user.first_name      first name of user
        @apiSuccess {String}    user.last_name       last name of user
        @apiSuccess {String}    user.email           email of user
        @apiSuccess {String}    user.username        username of user
        @apiSuccess {String}    user.organisation    organisation of user(only for donor)
        @apiSuccess {String}    user.street          street number/name of user.
        @apiSuccess {String}    user.landmark        landmark description of user.
        @apiSuccess {String}    user.city            city of user.
        @apiSuccess {String}    user.country         country of user.

        @apiError               message         token is missing
        @apiError               message[2]         token is invalid

        """
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        type = token_data.get('type')
        username = token_data.get("username")
        if type == 'donor':
            user = Donor.query.filter_by(username=username).first()
            address = Address.query.filter_by(donor_id=user.id).first()
            u = {'first_name': user.first_name, 'last_name': user.last_name, 'id': user.id, 'phone_no': user.phone_no,
                 'email': user.email, 'username': user.username, 'organisation': user.organisation, 'street': address.street, 'landmark': address.landmark,
                 'city': address.city, 'country': address.country}
        elif type == 'beneficiary':
            user = Beneficiary.query.filter_by(username=username).first()
            address = Address.query.filter_by(beneficiary_id=user.id).first()
            u = {'first_name': user.first_name, 'last_name': user.last_name, 'id': user.id, 'phone_no': user.phone_no,
                 'email': user.email, 'username': user.username, 'street': address.street, 'landmark': address.landmark,
                 'city': address.city, 'country': address.country}

        return {'user': u}, 200


class UpdateUser(Resource):
    @token_required
    def post(self):
        """
        @api {post} /user/update update user
        @apiVersion 1.0.0
        @apiName updateuser
        @apiGroup User


        @apiParam {String}      type            'donor' or 'beneficiary'
        @apiParam {String}      first_name      The first name of the user.
        @apiParam {String}      last_name       the last name of the user.
        @apiParam {String}      username        username of user.
        @apiParam {String}      phone_no        phone number of user.
        @apiParam {String}      organisation    organisation of Donor(for donor only)
        @apiParam {String}      city            city name(part of address)
        @apiParam {String}      street          street number(part of address)
        @apiParam {String}      landmark        landmark description(part of address)
        @apiParam {String}      country         country name(part of address)

        @apiSuccess {String}    token           updated token

        @apiError               message         token is missing
        @apiError               message[2]         token is invalid

        """
        updated_user = request.json
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        type = token_data.get('type')
        username = token_data.get("username")
        if type == 'donor':
            user = Donor.query.filter_by(username=username).first()
            user.organisation = updated_user.get('organisation')
            address = Address.query.filter_by(donor_id=user.id).first()
            status = 1
            check_username = Donor.query.filter_by(
                username=updated_user['username']).first()
            if check_username:
                if check_username.id != user.id:
                    return {'token': token, 'message': 0}, 400
        elif type == 'beneficiary':
            user = Beneficiary.query.filter_by(username=username).first()
            address = Address.query.filter_by(beneficiary_id=user.id).first()
            status = user.status
            check_username = Beneficiary.query.filter_by(
                username=updated_user['username']).first()
            if check_username.id != user.id:
                return {'token': token, 'message': 0}, 400

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
            {'username': user.username, 'first_name': user.first_name, 'last_name': user.last_name, 'status': status, 'type': type, 'id': user.id,
             'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
            app.config['SECRET_KEY'])
        return {'token': token.decode('UTF-8'), 'message': 1}, 200


class BeneficiaryOrders(Resource):
    @token_required
    def get(self):
        """
        @api {get} /beneficiary/orders get all orders of beneficiary
        @apiVersion 1.0.0
        @apiName beneficiaryorders
        @apiGroup Beneficiary

        @apiSuccess {Object[]}  orders                 array of beneficiary orders
        @apiSuccess {Number}    orders.donor_id        id of donor
        @apiSuccess {Number}    orders.listing_id      id of listing
        @apiSuccess {Number}    orders.beneficiary_id  id of beneficiary
        @apiSuccess {String}    orders.street          street number/name of donor.
        @apiSuccess {String}    orders.landmark        landmark description of donor.
        @apiSuccess {String}    orders.city            city of donor.
        @apiSuccess {String}    orders.country         country of donor.
        @apiSuccess {String}    orders.image           image of listing
        @apiSuccess {String}    orders.description     description of listing
        @apiSuccess {String}    orders.organisation    organisation of donor
        @apiSuccess {Number}    orders.time_stamp      time stamp of order placement

        @apiError               message         token is missing
        @apiError               message[2]         token is invalid

        """
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        beneficiary = Beneficiary.query.filter_by(username=username).first()
        orders = Orders.query.filter_by(beneficiary_id=beneficiary.id)
        order_list = []
        for order in orders:
            address = Address.query.filter_by(donor_id=order.donor_id).first()
            donor = Donor.query.filter_by(id=order.donor_id).first()
            listing = Listings.query.get(order.listing_id)
            _list = {
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
                "description": listing.description,
                "organisation": donor.organisation
            }
            order_list.append(_list)
        order_list.reverse()
        return {"orders": order_list}


class DonorOrders(Resource):
    @token_required
    def get(self):
        """
        @api {get} /donor/orders get all orders of donor
        @apiVersion 1.0.0
        @apiName donororders
        @apiGroup Donor


        @apiSuccess {Object[]}  orders                 array of donor orders
        @apiSuccess {Number}    orders.donor_id        id of donor
        @apiSuccess {Number}    orders.listing_id      id of listing
        @apiSuccess {Number}    orders.beneficiary_id  id of beneficiary
        @apiSuccess {String}    orders.first_name      first name of beneficiary
        @apiSuccess {String}    orders.last_name       last name of beneficiary
        @apiSuccess {String}    orders.email           email of beneficiary
        @apiSuccess {String}    orders.username        username of beneficiary
        @apiSuccess {String}    orders.phone_no        phone number of beneficiary
        @apiSuccess {String}    orders.street          street number/name of donor.
        @apiSuccess {String}    orders.landmark        landmark description of donor.
        @apiSuccess {String}    orders.city            city of donor.
        @apiSuccess {String}    orders.country         country of donor.
        @apiSuccess {String}    orders.image           image of listing
        @apiSuccess {String}    orders.description     description of listing
        @apiSuccess {String}    orders.organisation    organisation of donor
        @apiSuccess {Number}    orders.time_stamp      time stamp of order placement

        @apiError               message         token is missing
        @apiError               message[2]         token is invalid

        """
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        donor = Donor.query.filter_by(username=username).first()
        orders = Orders.query.filter_by(donor_id=donor.id).all()
        order_list = []
        for order in orders:
            address = Address.query.filter_by(donor_id=order.donor_id).first()
            listing = Listings.query.get(order.listing_id)
            beneficiary = Beneficiary.query.get(order.beneficiary_id)
            _list = {"donor_id": order.donor_id,
                     "beneficiary_id": order.beneficiary_id,
                     "first_name": beneficiary.first_name,
                     "last_name": beneficiary.last_name,
                     "email": beneficiary.email,
                     "phone_no": beneficiary.phone_no,
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
            order_list.append(_list)
        order_list.reverse()
        return {"orders": order_list}


# randomize the image filename
class UploadImage(Resource):
    def post(self):
        """
        @api {post} /uploadimage upload image to imgur
        @apiVersion 1.0.0
        @apiName uploadimage
        @apiGroup Listing

        @apiParam {Bytes}       file            file object.

        @apiSuccess {String}    url             image url

        @apiError               message         No file sent
        @apiError               message[2]         No selected file
        """
        # check if the post request has the file part
        if 'file' not in request.files:
            return {"message": "No file sent"}, 400
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return {'massage': 'No selected file'}, 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(app.root_path, filename)
            file.save(path)
            url = upload_to_imgur(path)
            return {"url": url}, 200


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
    response = requests.request(
        'POST', url, headers=headers, data=payload, files=files, allow_redirects=False)
    content = response.json()
    url = content.get('data').get('link')
    return url


# only for beneficiary
class AddVerificationDetails(Resource):
    def post(self):
        """
        @api {post} /uploadimage upload image to imgur
        @apiVersion 1.0.0
        @apiName uploadimage
        @apiGroup Listing

        @apiParam {Bytes}       file            file object.

        @apiSuccess {String}    url             image url

        @apiError               message         No file sent
        @apiError               message[2]         No selected file
        """
        json_data = request.json
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        beneficiary = Beneficiary.query.filter_by(username=username).first()
        beneficiary.ngo_unique_id = json_data.get("ngo_unique_id")
        beneficiary.registration_no = json_data.get("registration_no")
        beneficiary.status = 2
        db.session.commit()
        token = jwt.encode(
            {'username': beneficiary.username, 'first_name': beneficiary.first_name, 'last_name': beneficiary.last_name, 'status': 2, 'type': 'beneficiary', 'id': beneficiary.id,
             'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
            app.config['SECRET_KEY'])
        return {'token': token.decode('UTF-8')}, 200


# only for beneficiary (on hold for now)
# class UploadCertificate(Resource):
#     def post(self):
#         """
#         @api {post} /uploadimage upload image to imgur
#         @apiVersion 1.0.0
#         @apiName uploadimage
#         @apiGroup Listing

#         @apiParam {Bytes}       file            file object.

#         @apiSuccess {String}    url             image url

#         @apiError               message         No file sent
#         @apiError               message[2]         No selected file
#         """
#         # check if the post request has the file part
#         if 'file' not in request.files:
#             return {"message": "No file sent"}, 400
#         file = request.files['file']
#         # if user does not select file, browser also
#         # submit an empty part without filename
#         if file.filename == '':
#             return {'massage': 'No selected file'}, 400
#         if file and allowed_file(file.filename):
#             filename = secure_filename(file.filename)
#             path = os.path.join(app.root_path, "certificates", filename)
#             file.save(path)
#             # url = upload_to_imgur(path)
#             token = request.headers.get("x-access-token")
#             token_data = jwt.decode(token, app.config['SECRET_KEY'])
#             username = token_data.get("username")
#             beneficiary = Beneficiary.query.filter_by(username=username).first()
#             beneficiary.status = 2
#             db.commit()
#             token = jwt.encode(
#                 {'username': beneficiary.username, 'first_name': beneficiary.first_name, 'type': type, 'id': beneficiary.id,
#                 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
#                 app.config['SECRET_KEY'])
#             return {'token': token.decode('UTF-8'), 'message': 1}, 200

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
# api.add_resource(UploadCertificate, '/uploadcertificate')
api.add_resource(AddVerificationDetails, '/addverificationdetails')


# notification to donor {later}
