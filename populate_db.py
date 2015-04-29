__author__ = 'Liam'
from application import db, PoolOwner, PoolShopAdmin, \
    SPACSAdmin, Pool, Shop, Report

db.create_all()

owner = PoolOwner('PoolOwner1', 'a')
shop_admin = PoolShopAdmin('PoolShopAdmin1', 'a')
spacs_admin = SPACSAdmin('SPACSAdmin1', 'a')
shop = Shop('2')
pool = Pool('6.2', '4.3', '3', 'Cement', 'In-ground', '1', '2')
report = Report('This is an example report. Latest measurements are x,y,z. '
                'Acid has been rising over the past month. Chlorine has been'
                'dropping. Measurements are all still within nominal levels.'
                'No recommendations available.', '2015-4-29')

db.session.add(owner)
db.session.add(shop_admin)
db.session.add(spacs_admin)
db.session.add(shop)
db.session.add(pool)
db.session.add(report)

db.session.commit()