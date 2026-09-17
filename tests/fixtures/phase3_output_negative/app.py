def safe(request):
    result = client.responses.create(input="fixed prompt")
    print(result)
