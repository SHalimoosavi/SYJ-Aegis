def execute(request):
    result = client.responses.create(input=request)
    subprocess.run(["sh", "-c", result])
    cursor.execute(f"SELECT {result}")
    open(result, "w")
