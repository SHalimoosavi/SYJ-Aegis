import logging

def expose(email):
    logging.info("customer=%s", email)
    client.responses.create(input=email)
    urllib.request.urlopen(email)

def literal():
    logger.info("email", "alice@example.com")
