from slowapi import Limiter
from slowapi.util import get_remote_address

# We create a single instance of the Limiter here.
# get_remote_address is a helper that finds the user's IP address.
limiter = Limiter(key_func=get_remote_address)
