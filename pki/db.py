#
import enum

from sqlalchemy import create_engine
from sqlalchemy import MetaData, Table, Column
from sqlalchemy import Enum, Integer, String, Text

SQLITE = 'sqlite'

CERTS_TBL_NAME = 'certs'
KEYS_TBL_NAME  = 'keys'

class CertRole(enum.Enum):
    ROOT = 1
    INTERMEDIATE = 2
    HOST = 3

metadata = MetaData()
certs_tbl = Table(CERTS_TBL_NAME, metadata,
                  Column('id', Integer, primary_key=True),
                  Column('key_id', Integer),
                  Column('ski', String), # Subject Key Identifier
                  Column('aki', String), # Authority Key Identifier
                  Column('name', String),
                  Column('role', Enum(CertRole)),
                  Column('pem', Text),
)

keys_tbl = Table(KEYS_TBL_NAME, metadata,
                 Column('id', Integer, primary_key=True),
                 Column('cert_id', Integer),
                 Column('pem', Text)
)


class PKIDB:
    # http://docs.sqlalchemy.org/en/latest/core/engines.html
    DB_ENGINE = {
        SQLITE: 'sqlite:///{DB}'
    }

    db_engine = None

    def __init__(self, dbtype, dbname=''):
        dbtype = dbtype.lower()
        if dbtype in self.DB_ENGINE.keys():
            engine_url = self.DB_ENGINE[dbtype].format(DB=dbname)
            self.db_engine = create_engine(engine_url)
            # print(self.db_engine)
        else:
            print("DBType({}) is not supported".format(dbtype))

    def create_tables(self):
        try:
            metadata.create_all(self.db_engine)
        except Exception as e:
            print("ERROR: table creation failed")
            print(e)
