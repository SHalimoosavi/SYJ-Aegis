def safe(value):
    logging.info("status=%s", value)
    client.responses.create(input="non-sensitive status")
