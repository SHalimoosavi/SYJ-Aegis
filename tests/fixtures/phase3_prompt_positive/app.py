def build_prompt(user_input):
    system_prompt = "system: use api_key=THIS_IS_A_REAL_SECRET_VALUE"
    prompt = f"{system_prompt}\nUser request: {user_input}"
    return client.responses.create(input=prompt)
