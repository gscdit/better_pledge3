from app import db


class Donor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(200))
    last_name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    username = db.Column(db.String(200), unique=True)
    phone_no = db.Column(db.String(200))
    organisation = db.Column(db.String(200))
    password_hash = db.Column(db.String(60))
    address = db.relationship('Address', backref='donor', lazy=True)
    reviews = db.relationship('Reviews', backref='donor', lazy=True)
    listings = db.relationship('Listings', backref='donor', lazy=True)
    orders = db.relationship('Orders', backref='donor', lazy=True)


class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(200))
    status = db.Column(db.Integer)
    registration_no = db.Column(db.String(200))
    ngo_unique_id = db.Column(db.String(220))
    last_name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    username = db.Column(db.String(200), unique=True)
    phone_no = db.Column(db.String(200))
    password_hash = db.Column(db.String(60))
    type = db.Column(db.Integer)
    address = db.relationship('Address', backref='beneficiary', lazy=True)
    review = db.relationship('Reviews', backref='beneficiary', lazy=True)
    orders = db.relationship('Orders', backref='beneficiary', lazy=True)


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'))
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'))
    city = db.Column(db.String(200))
    street = db.Column(db.String(200))
    country = db.Column(db.String(200))
    landmark = db.Column(db.String(200))


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
    quantity = db.Column(db.String(200))
    time_stamp = db.Column(db.String(200))
    # pickup_time = db.Column(db.String(20))


class Listings(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    quantity = db.Column(db.Integer)
    expiry = db.Column(db.String(200))
    time_stamp = db.Column(db.DateTime)
    description = db.Column(db.String(250))
    type = db.Column(db.String(200))
    image = db.Column(db.String(200))
    orders = db.relationship('Orders', backref='listing', lazy=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'))
