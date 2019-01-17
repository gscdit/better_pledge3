from app.models import db


def reset_database():
    db.session.commit()
    db.drop_all()
    db.create_all()
    print('done')


if __name__ == '__main__':
    reset_database()
