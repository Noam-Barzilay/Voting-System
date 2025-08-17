candidates = ["Bob", "John", "Alice", "Jack", "Eric", "Hillary"]
# in real life - extract real ids of eligible people to vote
NUM_OF_VOTERS = 10
ids = [str(n) for n in range(1, NUM_OF_VOTERS + 1)]
INTERVAL_SIZE = 30  # 30 seconds
# TODO: put it in .env ?
HASH_ID_SERVER_KEY = b'\xbdZ!\xab\xde\x994|\x83\xdf\xd3\xcd{\xa0\xbdM\xa509q\x1eFn{S\xaa\x07\xcc\xe6O\xad$'
