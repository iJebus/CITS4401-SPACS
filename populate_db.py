__author__ = 'Liam'
from application import db, PoolOwner, PoolShopAdmin, SPACSAdmin

db.create_all()

owner = PoolOwner('PoolOwner1', 'sandwich')
shop_admin = PoolShopAdmin('PoolShopAdministrator1', 'sandwich')
spacs_admin = SPACSAdmin('SPACSAdministrator1', 'sandwich')
liam = SPACSAdmin('Liam', 'toast')

db.session.add(owner)
db.session.add(shop_admin)
db.session.add(spacs_admin)
db.session.add(liam)

db.session.commit()