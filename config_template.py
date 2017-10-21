"""
fill in appropriate values and rename me to config.py
"""
# Redis Host
REDIS_HOST = 'localhost'

# database info
DB_NAME = ''
DB_PASSWORD = ''
DB_SERVER = 'localhost'
DB_USER = ''

SQLALCHEMY_DATABASE_URI = 'postgresql://{}:{}@{}/{}'.format(DB_USER,
                                                            DB_PASSWORD,
                                                            DB_SERVER,
                                                            DB_NAME)

PATH_TO_MOUNT = ''
INDEX_FOLDER = ["Folder1", "Folder2"]

CATEGORY_REGEXES = {
  "Category1": [
    "regex",
  ]
}
