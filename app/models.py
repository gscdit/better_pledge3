from app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    info = db.Column(db.String(80))


class Donor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    # location = db.Column(db.String(50))
    # address = db.Column(db.String(200))
    email = db.Column(db.String(80))
    username = db.Column(db.String(40), unique=True)
    phone_no = db.Column(db.String(13))
    password_hash = db.Column(db.String(60))
    # rating = db.Column(db.String(5))
    address = db.relationship('Address', backref='donor', lazy=True)
    reviews = db.relationship('Reviews', backref='donor', lazy=True)
    listings = db.relationship('Listings', backref='donor', lazy=True)
    orders = db.relationship('Orders', backref='donor', lazy=True)


class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30))
    # location = db.Column(db.String(50))
    # address = db.Column(db.String(200))
    email = db.Column(db.String(80))
    username = db.Column(db.String(40), unique=True)
    phone_no = db.Column(db.String(13))
    password_hash = db.Column(db.String(60))
    type = db.Column(db.Integer)
    address = db.relationship('Address', backref='beneficiary', lazy=True)
    review = db.relationship('Reviews', backref='beneficiary', lazy=True)
    orders = db.relationship('Orders', backref='beneficiary', lazy=True)


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'),
                         nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'),
                               nullable=False)
    city = db.Column(db.String(20))
    street = db.Column(db.String(20))
    country = db.Column(db.String(20))


class Reviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'),
                         nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'),
                               nullable=False)
    stars = db.Column(db.String(1))
    review = db.Column(db.Text())


class Orders(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'),
                         nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'),
                               nullable=False)
    listing_id = db.Column(db.Integer, db.ForeignKey(
        'listings.id'), nullable=False)


class Listings(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    quantity = db.Column(db.Integer)
    expiry = db.Column(db.String(20))
    description = db.Column(db.String(250))
    type = db.Column(db.String(10))
    image = db.Column(db.String(100))
    orders = db.relationship('Orders', backref='listing', lazy=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'))
