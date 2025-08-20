candidates = ["Bob", "John", "Alice", "Jack", "Eric", "Hillary"]
# in real life - extract real ids of eligible people to vote
NUM_OF_VOTERS = 10
ids = [str(n) for n in range(1, NUM_OF_VOTERS + 1)]
INTERVAL_SIZE = 30  # 30 seconds

# TODO: put it in .env ?
HASH_ID_SERVER_KEY = b'\xc5\xfd\n\xef7f\x0f1\xc0v\xed,\x86,~\xa2D\xd9e}\x9f\xe0qv\xed\xe2\xebv\xdb\x85\x94\x03'
HASH_TOKEN_SERVER_KEY = b'\xb7\xc5\xa9\xdc\xfb~a\x99\xbetkN\xa4v#J}\xa0\x96\x84\x80{\x16\xe5O\x80e\x1a\xbdOl\xc8'
CANDIDATES_CIPHER_KEY = b'\xddm\xee\x87\xe2\xd8|\xc4c\xe6\xac\xa4\n\x07\xa1K'
IDS_CIPHER_KEY = b'\xf8\x810\x9c\xb8\x89D0\x1fZ\xa3\xd8\xb0\x08|\xb6'
