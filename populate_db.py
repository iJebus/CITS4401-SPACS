__author__ = 'Liam'
from application import db, PoolOwner, PoolShopAdmin, \
    SPACSAdmin, Pool, Shop, Report

db.create_all()

owner = PoolOwner('PoolOwner1', 'a', 'Steve McQueen',
                  '73 Evergreen Terrace, Springfield',
                  's.mcqueen@fakemail.com')
owner1 = PoolOwner('PoolOwner2', 'b', 'Joe Bloggs',
                   '52 Sunset Drive, Springfield', 'j.bloggs@fakemail.com')
shop_admin = PoolShopAdmin('PoolShopAdmin1', 'c', 'Ren Smith',
                           '44 Hobb Cover, Springfield',
                           'r.smith@fakemail.com')
spacs_admin = SPACSAdmin('SPACSAdmin1', 'd', 'Sally Fernando',
                         '3 Ord St, West City', 's.fernando@fakemail.com')
shop = Shop('3', 'Ren\'s Pool Shack', '2a Floor Rd, San Hilderson',
            'rens.shack@fakemail.com', '+61 400 555 111')
shop1 = Shop('3', 'Smithy and Son Pool Supplies', '99 Surf Boulevard, Maxtown',
             'smith.son@fakemail.com', '+61 400 555 112')
pool = Pool('6.2', '4.3', '3', 'Cement', 'In-ground', '1', '1')
pool1 = Pool('3', '2', '1.5', 'Plastic', 'Above-ground', '2', '1')

report = Report('This is an example report. Latest measurements are x,y,z. '
                'Acid has been rising over the past month. Chlorine has been'
                ' dropping. Measurements are all still within nominal levels. '
                'No recommendations available.', '2015-4-29')
report1 = Report('This is an earlier example report. Latest measurements are '
                 'x,y,z. Acid is stable. Chlorine is stable. Measurements '
                 'within nominal levels. No recommendations available.',
                 '2015-4-22')
report.pool_id = '1'
report1.pool_id = '1'

db.session.add(owner)
db.session.add(owner1)

db.session.add(shop_admin)

db.session.add(spacs_admin)

db.session.add(shop)
db.session.add(shop1)

db.session.add(pool)
db.session.add(pool1)

db.session.add(report)
db.session.add(report1)

db.session.commit()